use crate::crypto::{derive_me_aes_key_iv, KdfPurpose, MeCbcDecryptor, MeCbcEncryptor};
use crate::wire::{
    decode_rpc_frame, encode_close_ext, encode_handshake, encode_nonce, encode_ping, encode_pong,
    encode_proxy_req, pack_rpc_frame, parse_rpc_message, MeClientProto, RpcMessage, CRYPTO_AES,
};
use anyhow::{bail, ensure, Context, Result};
use rand::RngCore;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;

/// Bounded per-session inbound frame queue (INV-03 backpressure).
pub const SESSION_INBOUND_QUEUE_CAP: usize = 64;
/// Bounded shared ME outbound frame queue (INV-03 backpressure).
pub const ME_OUTBOUND_QUEUE_CAP: usize = 256;
/// Default timeout for a single `write_all` on an ME TCP socket.
pub const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug)]
pub struct MeConnOptions {
    pub handshake_timeout: Duration,
    pub ping_interval: Duration,
    pub ping_timeout: Duration,
    pub write_timeout: Duration,
    /// Optional public IPv4 override for KDF when running behind 1:1 NAT / Docker bridge.
    pub public_ipv4: Option<Ipv4Addr>,
}

impl Default for MeConnOptions {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(5),
            ping_interval: Duration::from_secs(20),
            ping_timeout: Duration::from_secs(10),
            write_timeout: DEFAULT_WRITE_TIMEOUT,
            public_ipv4: None,
        }
    }
}

/// Shared monotonic counters across one connection or an entire `MePool`.
#[derive(Default)]
pub(crate) struct MeConnCounters {
    pub backpressure_drops: AtomicU64,
    pub dropped_close_ext: AtomicU64,
}

/// Event received for a multiplexed client session from Telegram ME.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MeInboundEvent {
    Payload(Vec<u8>),
    QuickAck(u32),
}

struct SessionEntry {
    tx: mpsc::Sender<MeInboundEvent>,
}

struct TaskGuard {
    active_tasks: Arc<AtomicUsize>,
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.active_tasks.fetch_sub(1, Ordering::Relaxed);
    }
}

struct ConnShared {
    sessions: Mutex<HashMap<u64, SessionEntry>>,
    alive: AtomicBool,
    next_conn_id: AtomicU64,
    our_addr: SocketAddrV4,
    out_tx: mpsc::Sender<Vec<u8>>,
    counters: Arc<MeConnCounters>,
    shutdown_tx: watch::Sender<bool>,
    active_tasks: Arc<AtomicUsize>,
}

/// Active multiplexed connection to a single Telegram Middle-End server.
#[derive(Clone)]
pub struct MeConnection {
    shared: Arc<ConnShared>,
}

/// Handle to one multiplexed client session over a shared `MeConnection`.
pub struct MeSession {
    conn_id: u64,
    remote_addr: Option<SocketAddrV4>,
    proto: MeClientProto,
    ad_tag: Option<[u8; 16]>,
    shared: Arc<ConnShared>,
    rx: mpsc::Receiver<MeInboundEvent>,
    closed: bool,
}

impl MeSession {
    pub fn conn_id(&self) -> u64 {
        self.conn_id
    }

    pub async fn send_frame(&self, mtproto_payload: &[u8]) -> Result<()> {
        self.send_frame_with_flags(mtproto_payload, false).await
    }

    pub async fn send_frame_with_flags(
        &self,
        mtproto_payload: &[u8],
        quick_ack: bool,
    ) -> Result<()> {
        ensure!(
            self.shared.alive.load(Ordering::Relaxed),
            "ME connection is closed"
        );
        let req = encode_proxy_req(
            self.conn_id,
            self.remote_addr,
            self.shared.our_addr,
            self.proto,
            quick_ack,
            self.ad_tag.as_ref(),
            mtproto_payload,
        )?;
        self.shared
            .out_tx
            .send(req)
            .await
            .map_err(|_| anyhow::anyhow!("ME writer closed"))
    }

    pub async fn recv_event(&mut self) -> Option<MeInboundEvent> {
        self.rx.recv().await
    }

    pub async fn recv_frame(&mut self) -> Option<Vec<u8>> {
        while let Some(ev) = self.rx.recv().await {
            if let MeInboundEvent::Payload(payload) = ev {
                return Some(payload);
            }
        }
        None
    }

    pub fn close(mut self) {
        self.send_close_once();
    }

    /// Split into independent receiver and sender halves for concurrent upload/download tasks.
    pub fn into_split(mut self) -> (MeSessionReceiver, MeSessionSender) {
        self.closed = true;
        let (_dummy_tx, dummy_rx) = mpsc::channel(1);
        let rx = std::mem::replace(&mut self.rx, dummy_rx);
        let sender = MeSessionSender {
            conn_id: self.conn_id,
            remote_addr: self.remote_addr,
            proto: self.proto,
            ad_tag: self.ad_tag,
            shared: self.shared.clone(),
            closed: false,
        };
        (MeSessionReceiver { rx }, sender)
    }

    fn send_close_once(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        {
            let mut map = self
                .shared
                .sessions
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            map.remove(&self.conn_id);
        }
        if self.shared.alive.load(Ordering::Relaxed) {
            if let Err(mpsc::error::TrySendError::Full(_)) = self
                .shared
                .out_tx
                .try_send(encode_close_ext(self.conn_id).to_vec())
            {
                self.shared
                    .counters
                    .dropped_close_ext
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

impl Drop for MeSession {
    fn drop(&mut self) {
        self.send_close_once();
    }
}

/// Receive half of a split `MeSession`.
pub struct MeSessionReceiver {
    rx: mpsc::Receiver<MeInboundEvent>,
}

impl MeSessionReceiver {
    pub async fn recv_event(&mut self) -> Option<MeInboundEvent> {
        self.rx.recv().await
    }
}

/// Send half of a split `MeSession`; emits `RPC_CLOSE_EXT` once when closed or dropped.
pub struct MeSessionSender {
    conn_id: u64,
    remote_addr: Option<SocketAddrV4>,
    proto: MeClientProto,
    ad_tag: Option<[u8; 16]>,
    shared: Arc<ConnShared>,
    closed: bool,
}

impl MeSessionSender {
    pub async fn send_frame(&self, mtproto_payload: &[u8]) -> Result<()> {
        self.send_frame_with_flags(mtproto_payload, false).await
    }

    pub async fn send_frame_with_flags(
        &self,
        mtproto_payload: &[u8],
        quick_ack: bool,
    ) -> Result<()> {
        ensure!(
            self.shared.alive.load(Ordering::Relaxed),
            "ME connection is closed"
        );
        let req = encode_proxy_req(
            self.conn_id,
            self.remote_addr,
            self.shared.our_addr,
            self.proto,
            quick_ack,
            self.ad_tag.as_ref(),
            mtproto_payload,
        )?;
        self.shared
            .out_tx
            .send(req)
            .await
            .map_err(|_| anyhow::anyhow!("ME writer closed"))
    }

    pub fn close(mut self) {
        self.send_close_once();
    }

    fn send_close_once(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        {
            let mut map = self
                .shared
                .sessions
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            map.remove(&self.conn_id);
        }
        if self.shared.alive.load(Ordering::Relaxed) {
            if let Err(mpsc::error::TrySendError::Full(_)) = self
                .shared
                .out_tx
                .try_send(encode_close_ext(self.conn_id).to_vec())
            {
                self.shared
                    .counters
                    .dropped_close_ext
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

impl Drop for MeSessionSender {
    fn drop(&mut self) {
        self.send_close_once();
    }
}

impl MeConnection {
    /// Connect to `endpoint`, complete `RPC_NONCE` + AES-256-CBC KDF + `RPC_HANDSHAKE`,
    /// and spawn the background multiplexed reader/writer + ping loop.
    pub async fn connect(
        endpoint: SocketAddrV4,
        proxy_secret: &[u8],
        opts: MeConnOptions,
    ) -> Result<Self> {
        Self::connect_with_counters(
            endpoint,
            proxy_secret,
            opts,
            Arc::new(MeConnCounters::default()),
        )
        .await
    }

    pub(crate) async fn connect_with_counters(
        endpoint: SocketAddrV4,
        proxy_secret: &[u8],
        opts: MeConnOptions,
        counters: Arc<MeConnCounters>,
    ) -> Result<Self> {
        ensure!(
            proxy_secret.len() >= 16,
            "proxy-secret must be at least 16 bytes"
        );
        let mut key_selector = [0u8; 4];
        key_selector.copy_from_slice(&proxy_secret[..4]);

        let mut stream = timeout(
            opts.handshake_timeout,
            TcpStream::connect(SocketAddr::V4(endpoint)),
        )
        .await
        .context("ME TCP connect timeout")?
        .context("ME TCP connect failed")?;
        let _ = stream.set_nodelay(true);

        let local_v4 = match stream.local_addr().context("ME local_addr")? {
            SocketAddr::V4(v4) => v4,
            SocketAddr::V6(_) => bail!("ME connection requires IPv4 socket"),
        };
        let kdf_clt_ip = opts.public_ipv4.unwrap_or(*local_v4.ip());
        let our_addr = SocketAddrV4::new(kdf_clt_ip, local_v4.port());

        let (mut enc, mut dec, mut read_buf) = timeout(opts.handshake_timeout, async {
            let mut clt_nonce = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut clt_nonce);
            let clt_ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(1_700_000_000);

            // 1. Plain RPC_NONCE (seq_no = -2)
            let nonce_msg = encode_nonce(key_selector, clt_ts, &clt_nonce);
            let nonce_frame = pack_rpc_frame(-2, &nonce_msg, false)?;
            stream
                .write_all(&nonce_frame)
                .await
                .context("write RPC_NONCE")?;

            let mut plain_buf = Vec::with_capacity(64);
            let (seq_srv, srv_payload) = read_plain_frame(&mut stream, &mut plain_buf).await?;
            ensure!(seq_srv == -2, "unexpected RPC_NONCE seq_no {seq_srv}");
            let RpcMessage::Nonce {
                key_selector: srv_ksel,
                schema,
                nonce: srv_nonce,
                ..
            } = parse_rpc_message(&srv_payload)?
            else {
                bail!("expected RPC_NONCE response");
            };
            ensure!(
                schema == CRYPTO_AES,
                "unsupported ME crypto schema {schema}"
            );
            ensure!(srv_ksel == key_selector, "ME key_selector mismatch");

            // 2. Derive AES-256-CBC keys
            let (enc_key, enc_iv) = derive_me_aes_key_iv(
                &srv_nonce,
                &clt_nonce,
                clt_ts,
                *endpoint.ip(),
                local_v4.port(),
                KdfPurpose::Client,
                kdf_clt_ip,
                endpoint.port(),
                proxy_secret,
            );
            let (dec_key, dec_iv) = derive_me_aes_key_iv(
                &srv_nonce,
                &clt_nonce,
                clt_ts,
                *endpoint.ip(),
                local_v4.port(),
                KdfPurpose::Server,
                kdf_clt_ip,
                endpoint.port(),
                proxy_secret,
            );
            let mut enc = MeCbcEncryptor::new(&enc_key, &enc_iv);
            let mut dec = MeCbcDecryptor::new(&dec_key, &dec_iv);

            // 3. Encrypted RPC_HANDSHAKE (seq_no = -1)
            let sender_pid = *b"IPIPPRPDTIME";
            let peer_pid = [0u8; 12];
            let hs_msg = encode_handshake(0, &sender_pid, &peer_pid);
            let mut hs_frame = pack_rpc_frame(-1, &hs_msg, true)?;
            enc.encrypt_in_place(&mut hs_frame)?;
            stream
                .write_all(&hs_frame)
                .await
                .context("write RPC_HANDSHAKE")?;

            let mut enc_read_buf = Vec::with_capacity(256);
            let (hs_seq, hs_resp) =
                read_encrypted_frame(&mut stream, &mut dec, &mut enc_read_buf).await?;
            ensure!(hs_seq == -1, "unexpected RPC_HANDSHAKE seq_no {hs_seq}");
            ensure!(
                matches!(parse_rpc_message(&hs_resp)?, RpcMessage::Handshake { .. }),
                "expected RPC_HANDSHAKE response"
            );
            Ok::<_, anyhow::Error>((enc, dec, enc_read_buf))
        })
        .await
        .context("ME handshake timeout")??;

        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(ME_OUTBOUND_QUEUE_CAP);
        let mut init_id = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut init_id);
        let (shutdown_tx, _) = watch::channel(false);
        let active_tasks = Arc::new(AtomicUsize::new(0));
        let shared = Arc::new(ConnShared {
            sessions: Mutex::new(HashMap::new()),
            alive: AtomicBool::new(true),
            next_conn_id: AtomicU64::new(u64::from_le_bytes(init_id) | 1),
            our_addr,
            out_tx: out_tx.clone(),
            counters,
            shutdown_tx,
            active_tasks,
        });

        let (mut rd, mut wr) = stream.into_split();
        let (pong_tx, mut pong_rx) = mpsc::channel::<i64>(8);

        // Writer task: serializes seq_no = 0, 1, 2, ... and encrypts with continuous AES-256-CBC.
        let shared_w = shared.clone();
        let mut shutdown_rx_w = shared.shutdown_tx.subscribe();
        let write_timeout = opts.write_timeout;
        shared.active_tasks.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(async move {
            let _guard = TaskGuard {
                active_tasks: shared_w.active_tasks.clone(),
            };
            let mut seq_no: i32 = 0;
            loop {
                let payload = tokio::select! {
                    biased;
                    () = wait_shutdown(&mut shutdown_rx_w) => break,
                    maybe = out_rx.recv() => match maybe {
                        Some(p) => p,
                        None => break,
                    }
                };
                let Ok(mut frame) = pack_rpc_frame(seq_no, &payload, true) else {
                    break;
                };
                seq_no = seq_no.wrapping_add(1);
                if enc.encrypt_in_place(&mut frame).is_err() {
                    break;
                }
                let write_ok = tokio::select! {
                    biased;
                    () = wait_shutdown(&mut shutdown_rx_w) => false,
                    res = timeout(write_timeout, wr.write_all(&frame)) => matches!(res, Ok(Ok(()))),
                };
                if !write_ok {
                    break;
                }
            }
            shutdown_shared(&shared_w);
        });

        // Reader task: decrypts frames and demultiplexes RPC_PROXY_ANS / RPC_SIMPLE_ACK / RPC_CLOSE_EXT / RPC_PING / RPC_PONG.
        let shared_r = shared.clone();
        let mut shutdown_rx_r = shared.shutdown_tx.subscribe();
        let out_tx_r = out_tx.clone();
        shared.active_tasks.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(async move {
            let _guard = TaskGuard {
                active_tasks: shared_r.active_tasks.clone(),
            };
            loop {
                let read_res = tokio::select! {
                    biased;
                    () = wait_shutdown(&mut shutdown_rx_r) => break,
                    res = read_encrypted_frame(&mut rd, &mut dec, &mut read_buf) => res,
                };
                let Ok((_seq, payload)) = read_res else {
                    break;
                };
                let Ok(msg) = parse_rpc_message(&payload) else {
                    break;
                };
                match msg {
                    RpcMessage::ProxyAns {
                        conn_id, payload, ..
                    } => {
                        deliver_session_event(
                            &shared_r,
                            &out_tx_r,
                            conn_id,
                            MeInboundEvent::Payload(payload),
                        );
                    }
                    RpcMessage::SimpleAck {
                        conn_id,
                        confirm_key,
                    } => {
                        deliver_session_event(
                            &shared_r,
                            &out_tx_r,
                            conn_id,
                            MeInboundEvent::QuickAck(confirm_key),
                        );
                    }
                    RpcMessage::CloseExt { conn_id } => {
                        let mut map = shared_r.sessions.lock().unwrap_or_else(|e| e.into_inner());
                        map.remove(&conn_id);
                    }
                    RpcMessage::Ping { ping_id } => {
                        let _ = out_tx_r.try_send(encode_pong(ping_id).to_vec());
                    }
                    RpcMessage::Pong { ping_id } => {
                        let _ = pong_tx.try_send(ping_id);
                    }
                    RpcMessage::Nonce { .. }
                    | RpcMessage::Handshake { .. }
                    | RpcMessage::Unknown { .. } => {}
                }
            }
            shutdown_shared(&shared_r);
        });

        // Keepalive ping task: closes dead/hung ME sockets when enqueueing RPC_PING or receiving
        // RPC_PONG does not complete within ping_timeout.
        if !opts.ping_interval.is_zero() {
            let shared_p = shared.clone();
            let mut shutdown_rx_p = shared.shutdown_tx.subscribe();
            let out_tx_p = out_tx;
            let ping_interval = opts.ping_interval;
            let ping_timeout = opts.ping_timeout;
            shared.active_tasks.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(async move {
                let _guard = TaskGuard {
                    active_tasks: shared_p.active_tasks.clone(),
                };
                let mut ticker = tokio::time::interval(ping_interval);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                ticker.tick().await; // skip immediate first tick
                let mut next_ping_id: i64 = 1;
                loop {
                    tokio::select! {
                        biased;
                        () = wait_shutdown(&mut shutdown_rx_p) => break,
                        _ = ticker.tick() => {}
                    }
                    let pid = next_ping_id;
                    next_ping_id = next_ping_id.wrapping_add(1);
                    let ping_frame = encode_ping(pid).to_vec();
                    let sent = tokio::select! {
                        biased;
                        () = wait_shutdown(&mut shutdown_rx_p) => break,
                        res = timeout(ping_timeout, out_tx_p.send(ping_frame)) => matches!(res, Ok(Ok(()))),
                    };
                    if !sent {
                        shutdown_shared(&shared_p);
                        break;
                    }
                    let got_pong = tokio::select! {
                        biased;
                        () = wait_shutdown(&mut shutdown_rx_p) => break,
                        res = timeout(ping_timeout, async {
                            while let Some(id) = pong_rx.recv().await {
                                if id == pid {
                                    return true;
                                }
                            }
                            false
                        }) => res.unwrap_or(false),
                    };
                    if !got_pong {
                        shutdown_shared(&shared_p);
                        break;
                    }
                }
            });
        }

        Ok(Self { shared })
    }

    pub fn is_alive(&self) -> bool {
        self.shared.alive.load(Ordering::Relaxed)
    }

    pub fn active_tasks(&self) -> usize {
        self.shared.active_tasks.load(Ordering::Relaxed)
    }

    pub async fn wait_closed(&self) {
        let mut rx = self.shared.shutdown_tx.subscribe();
        wait_shutdown(&mut rx).await;
    }

    pub fn backpressure_drops(&self) -> u64 {
        self.shared
            .counters
            .backpressure_drops
            .load(Ordering::Relaxed)
    }

    pub fn dropped_close_ext(&self) -> u64 {
        self.shared
            .counters
            .dropped_close_ext
            .load(Ordering::Relaxed)
    }

    pub fn active_sessions(&self) -> usize {
        self.shared
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    pub fn close(&self) {
        shutdown_shared(&self.shared);
    }

    pub fn open_session(
        &self,
        remote_addr: Option<SocketAddrV4>,
        proto: MeClientProto,
        ad_tag: Option<[u8; 16]>,
    ) -> Result<MeSession> {
        ensure!(self.is_alive(), "ME connection is closed");
        let conn_id = self.shared.next_conn_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(SESSION_INBOUND_QUEUE_CAP);
        {
            let mut map = self
                .shared
                .sessions
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            map.insert(conn_id, SessionEntry { tx });
        }
        Ok(MeSession {
            conn_id,
            remote_addr,
            proto,
            ad_tag,
            shared: self.shared.clone(),
            rx,
            closed: false,
        })
    }
}

fn deliver_session_event(
    shared: &Arc<ConnShared>,
    out_tx: &mpsc::Sender<Vec<u8>>,
    conn_id: u64,
    event: MeInboundEvent,
) {
    let tx_opt = {
        let map = shared.sessions.lock().unwrap_or_else(|e| e.into_inner());
        map.get(&conn_id).map(|e| e.tx.clone())
    };
    if let Some(tx) = tx_opt {
        match tx.try_send(event) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                // INV-03: slow client must never stall the shared ME reader loop.
                shared
                    .counters
                    .backpressure_drops
                    .fetch_add(1, Ordering::Relaxed);
                {
                    let mut map = shared.sessions.lock().unwrap_or_else(|e| e.into_inner());
                    map.remove(&conn_id);
                }
                if let Err(mpsc::error::TrySendError::Full(_)) =
                    out_tx.try_send(encode_close_ext(conn_id).to_vec())
                {
                    shared
                        .counters
                        .dropped_close_ext
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                let mut map = shared.sessions.lock().unwrap_or_else(|e| e.into_inner());
                map.remove(&conn_id);
            }
        }
    }
}

async fn wait_shutdown(rx: &mut watch::Receiver<bool>) {
    if *rx.borrow_and_update() {
        return;
    }
    let _ = rx.wait_for(|&closed| closed).await;
}

fn shutdown_shared(shared: &Arc<ConnShared>) {
    shared.alive.store(false, Ordering::Relaxed);
    {
        let mut map = shared.sessions.lock().unwrap_or_else(|e| e.into_inner());
        map.clear();
    }
    let _ = shared.shutdown_tx.send(true);
}

async fn read_plain_frame<R: AsyncReadExt + Unpin>(
    rd: &mut R,
    buf: &mut Vec<u8>,
) -> Result<(i32, Vec<u8>)> {
    let mut tmp = [0u8; 256];
    loop {
        if let Some(frame) = decode_rpc_frame(buf)? {
            return Ok(frame);
        }
        let n = rd.read(&mut tmp).await.context("reading plain ME frame")?;
        ensure!(n > 0, "EOF reading plain ME frame");
        buf.extend_from_slice(&tmp[..n]);
    }
}

async fn read_encrypted_frame<R: AsyncReadExt + Unpin>(
    rd: &mut R,
    dec: &mut MeCbcDecryptor,
    buf: &mut Vec<u8>,
) -> Result<(i32, Vec<u8>)> {
    let mut block = [0u8; 16];
    loop {
        if let Some(frame) = decode_rpc_frame(buf)? {
            return Ok(frame);
        }
        rd.read_exact(&mut block)
            .await
            .context("reading encrypted ME block")?;
        dec.decrypt_in_place(&mut block)?;
        buf.extend_from_slice(&block);
    }
}
