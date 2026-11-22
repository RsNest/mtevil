use crate::crypto::{derive_me_aes_key_iv, KdfPurpose, MeCbcDecryptor, MeCbcEncryptor};
use crate::wire::{
    decode_rpc_frame, encode_close_ext, encode_handshake, encode_nonce, encode_ping, encode_pong,
    encode_proxy_req, pack_rpc_frame, parse_rpc_message, RpcMessage, CRYPTO_AES,
};
use anyhow::{bail, ensure, Context, Result};
use rand::RngCore;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;

/// Bounded per-session inbound frame queue (INV-03 backpressure).
pub const SESSION_INBOUND_QUEUE_CAP: usize = 64;
/// Bounded shared ME outbound frame queue (INV-03 backpressure).
pub const ME_OUTBOUND_QUEUE_CAP: usize = 256;

#[derive(Clone, Debug)]
pub struct MeConnOptions {
    pub handshake_timeout: Duration,
    pub ping_interval: Duration,
    pub ping_timeout: Duration,
    /// Optional public IPv4 override for KDF when running behind 1:1 NAT / Docker bridge.
    pub public_ipv4: Option<Ipv4Addr>,
}

impl Default for MeConnOptions {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(5),
            ping_interval: Duration::from_secs(20),
            ping_timeout: Duration::from_secs(10),
            public_ipv4: None,
        }
    }
}

struct SessionEntry {
    tx: mpsc::Sender<Vec<u8>>,
}

struct ConnShared {
    sessions: Mutex<HashMap<u64, SessionEntry>>,
    alive: AtomicBool,
    next_conn_id: AtomicU64,
    our_addr: SocketAddrV4,
    out_tx: mpsc::Sender<Vec<u8>>,
    /// Counter of sessions dropped due to slow-client inbound queue overflow (INV-03).
    backpressure_drops: AtomicU64,
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
    ad_tag: Option<[u8; 16]>,
    shared: Arc<ConnShared>,
    rx: mpsc::Receiver<Vec<u8>>,
    closed: bool,
}

impl MeSession {
    pub fn conn_id(&self) -> u64 {
        self.conn_id
    }

    pub async fn send_frame(&self, mtproto_payload: &[u8]) -> Result<()> {
        ensure!(
            self.shared.alive.load(Ordering::Relaxed),
            "ME connection is closed"
        );
        let req = encode_proxy_req(
            self.conn_id,
            self.remote_addr,
            self.shared.our_addr,
            self.ad_tag.as_ref(),
            mtproto_payload,
        )?;
        self.shared
            .out_tx
            .send(req)
            .await
            .map_err(|_| anyhow::anyhow!("ME writer closed"))
    }

    pub async fn recv_frame(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await
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
            let _ = self
                .shared
                .out_tx
                .try_send(encode_close_ext(self.conn_id).to_vec());
        }
    }
}

impl Drop for MeSession {
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
        let shared = Arc::new(ConnShared {
            sessions: Mutex::new(HashMap::new()),
            alive: AtomicBool::new(true),
            next_conn_id: AtomicU64::new(u64::from_le_bytes(init_id) | 1),
            our_addr,
            out_tx: out_tx.clone(),
            backpressure_drops: AtomicU64::new(0),
        });

        let (mut rd, mut wr) = stream.into_split();
        let (pong_tx, mut pong_rx) = mpsc::channel::<i64>(8);

        // Writer task: serializes seq_no = 0, 1, 2, ... and encrypts with continuous AES-256-CBC.
        let shared_w = shared.clone();
        tokio::spawn(async move {
            let mut seq_no: i32 = 0;
            while let Some(payload) = out_rx.recv().await {
                let Ok(mut frame) = pack_rpc_frame(seq_no, &payload, true) else {
                    break;
                };
                seq_no = seq_no.wrapping_add(1);
                if enc.encrypt_in_place(&mut frame).is_err() {
                    break;
                }
                if wr.write_all(&frame).await.is_err() {
                    break;
                }
            }
            shutdown_shared(&shared_w);
        });

        // Reader task: decrypts frames and demultiplexes RPC_PROXY_ANS / RPC_CLOSE_EXT / RPC_PING / RPC_PONG.
        let shared_r = shared.clone();
        let out_tx_r = out_tx.clone();
        tokio::spawn(async move {
            loop {
                let Ok((_seq, payload)) =
                    read_encrypted_frame(&mut rd, &mut dec, &mut read_buf).await
                else {
                    break;
                };
                let Ok(msg) = parse_rpc_message(&payload) else {
                    break;
                };
                match msg {
                    RpcMessage::ProxyAns {
                        conn_id, payload, ..
                    } => {
                        let tx_opt = {
                            let map = shared_r.sessions.lock().unwrap_or_else(|e| e.into_inner());
                            map.get(&conn_id).map(|e| e.tx.clone())
                        };
                        if let Some(tx) = tx_opt {
                            match tx.try_send(payload) {
                                Ok(()) => {}
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    // INV-03: slow client must never stall the shared ME reader loop.
                                    shared_r.backpressure_drops.fetch_add(1, Ordering::Relaxed);
                                    {
                                        let mut map = shared_r
                                            .sessions
                                            .lock()
                                            .unwrap_or_else(|e| e.into_inner());
                                        map.remove(&conn_id);
                                    }
                                    let _ = out_tx_r.try_send(encode_close_ext(conn_id).to_vec());
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    let mut map =
                                        shared_r.sessions.lock().unwrap_or_else(|e| e.into_inner());
                                    map.remove(&conn_id);
                                }
                            }
                        }
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
                    RpcMessage::SimpleAck { .. }
                    | RpcMessage::Nonce { .. }
                    | RpcMessage::Handshake { .. }
                    | RpcMessage::Unknown { .. } => {}
                }
            }
            shutdown_shared(&shared_r);
        });

        // Keepalive ping task: closes dead/hung ME sockets when pong does not arrive within ping_timeout.
        if !opts.ping_interval.is_zero() {
            let shared_p = shared.clone();
            let out_tx_p = out_tx;
            let ping_interval = opts.ping_interval;
            let ping_timeout = opts.ping_timeout;
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(ping_interval);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                ticker.tick().await; // skip immediate first tick
                let mut next_ping_id: i64 = 1;
                loop {
                    ticker.tick().await;
                    if !shared_p.alive.load(Ordering::Relaxed) {
                        break;
                    }
                    let pid = next_ping_id;
                    next_ping_id = next_ping_id.wrapping_add(1);
                    if out_tx_p.send(encode_ping(pid).to_vec()).await.is_err() {
                        break;
                    }
                    let got_pong = timeout(ping_timeout, async {
                        while let Some(id) = pong_rx.recv().await {
                            if id == pid {
                                return true;
                            }
                        }
                        false
                    })
                    .await
                    .unwrap_or(false);
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

    pub fn backpressure_drops(&self) -> u64 {
        self.shared.backpressure_drops.load(Ordering::Relaxed)
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
            ad_tag,
            shared: self.shared.clone(),
            rx,
            closed: false,
        })
    }
}

fn shutdown_shared(shared: &Arc<ConnShared>) {
    shared.alive.store(false, Ordering::Relaxed);
    let mut map = shared.sessions.lock().unwrap_or_else(|e| e.into_inner());
    map.clear();
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
