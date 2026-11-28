use super::*;
use aes::cipher::KeyIvInit;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::{
    sync::{mpsc, Barrier},
    task::JoinHandle,
};

const COVER_REPLY: &[u8] = b"COVER RESPONSE";
const CLIENT_PAYLOAD: &[u8] = b"client marker through Direct";
const DC_REPLY: &[u8] = b"dc reply through Direct";

fn fixture(name: &str) -> Result<Vec<u8>> {
    let text = match name {
        "hello" => include_str!("../../../tests/vectors/prototype/synthetic-ch.hex"),
        "init" => include_str!("../../../tests/vectors/prototype/client-init.hex"),
        "payload" => include_str!("../../../tests/vectors/prototype/client-payload.hex"),
        "reply" => include_str!("../../../tests/vectors/prototype/client-reply.hex"),
        _ => bail!("unknown fixture"),
    };
    Ok(hex::decode(text.trim())?)
}

fn secret() -> [u8; 16] {
    let mut key = [0; 16];
    for (i, b) in key.iter_mut().enumerate() {
        *b = i as u8;
    }
    key
}

fn hello() -> Result<Vec<u8>> {
    let mut bytes = fixture("hello")?;
    let old = 1700000000u32.to_le_bytes();
    let now = (SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32).to_le_bytes();
    for i in 0..4 {
        bytes[39 + i] ^= old[i] ^ now[i];
    }
    Ok(bytes)
}

fn fragmented(raw: &[u8], records: usize) -> Vec<u8> {
    let body = &raw[5..];
    let mut out = Vec::new();
    for i in 0..records {
        let part = &body[body.len() * i / records..body.len() * (i + 1) / records];
        out.extend_from_slice(&[0x16, 3, 1]);
        out.extend_from_slice(&(part.len() as u16).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

pub(crate) fn state(cover: SocketAddr, dc: SocketAddr) -> Arc<State> {
    Arc::new(State {
        secrets: std::sync::RwLock::new(Arc::new(vec![NamedSecret {
            name: "default".into(),
            key: Zeroizing::new(secret()),
        }])),
        sni: "example.com".into(),
        allowed_snis: std::sync::RwLock::new(Arc::new("example.com".into())),
        cover_resolver: Arc::new(CoverResolver::new(
            cover.to_string(),
            Duration::from_secs(config::default_cover_dns_ttl_secs()),
        )),
        enable_dd: false,
        proxy_protocol: false,
        proxy_protocol_allow_from: Vec::new(),
        cover_permits: Semaphore::new(8),
        dcs: HashMap::from([(2, dc)]),
        dc_media_overrides: default_media_override_map(),
        egress_upstreams: Vec::new(),
        ws_pool: None,
        egress_strategy: EgressStrategy::RoundRobin,
        egress_token: [0u8; 16],
        egress_rr: std::sync::atomic::AtomicUsize::new(0),
        egress_health: std::sync::Mutex::new(EgressHealth::new(0)),
        mtv4_cooldown: std::sync::Mutex::new(Vec::new()),
        egress_probe_notify: Arc::new(tokio::sync::Notify::new()),
        egress_cooldown: Duration::from_millis(config::default_egress_cooldown_base_ms()),
        egress_cooldown_max: Duration::from_millis(config::default_egress_cooldown_max_ms()),
        egress_probe_interval: Duration::from_secs(config::default_egress_probe_interval_secs()),
        egress_probe_degraded_interval: Duration::from_secs(
            config::default_egress_probe_degraded_interval_secs(),
        ),
        egress_hedge_ms: config::default_egress_hedge_ms(),
        egress_use_mtv3: false,
        client_hello: Duration::from_millis(150),
        handshake: Duration::from_millis(150),
        idle: Duration::from_millis(300),
        drain: Duration::from_millis(20),
        flight: wire::ServerFlightProfile::default(),
        flight_cert_bytes: Arc::new(std::sync::atomic::AtomicUsize::new(
            wire::DEFAULT_CERT_BYTES,
        )),
        flight_shaping: false,
        client_mss_bulk: None,
        replay: Mutex::new(ReplayCache::new(65536, Duration::from_secs(300))),
        counters: Arc::new(telemetry::Counters::default()),
        alert_webhook_url: None,
        alerts_file: None,
        diagnostics: false,
        me: None,
        edge_me: None,
    })
}

async fn proxy(state: Arc<State>) -> Result<(TcpStream, JoinHandle<Result<()>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        let (socket, _) = listener.accept().await?;
        connection(socket, state).await
    });
    let client = TcpStream::connect(address).await?;
    client.set_nodelay(true)?;
    Ok((client, handle))
}

struct Cover {
    addr: SocketAddr,
    received: mpsc::Receiver<Vec<u8>>,
    task: JoinHandle<()>,
}
impl Drop for Cover {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn cover_mock() -> Result<Cover> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (tx, received) = mpsc::channel(32);
    let task = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut bytes = Vec::new();
                if timeout(Duration::from_secs(2), socket.read_to_end(&mut bytes))
                    .await
                    .is_ok()
                {
                    let _ = socket.write_all(COVER_REPLY).await;
                    let _ = socket.shutdown().await;
                    let _ = tx.send(bytes).await;
                }
            });
        }
    });
    Ok(Cover {
        addr,
        received,
        task,
    })
}

async fn closed_port() -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    Ok(listener.local_addr()?)
}

async fn read_record(client: &mut (impl AsyncRead + Unpin)) -> Result<(u8, Vec<u8>)> {
    let mut h = [0u8; 5];
    timeout(Duration::from_secs(2), client.read_exact(&mut h)).await??;
    let n = usize::from(u16::from_be_bytes([h[3], h[4]]));
    ensure!(n <= wire::MAX_RECORD, "test record bound");
    let mut body = vec![0; n];
    timeout(Duration::from_secs(2), client.read_exact(&mut body)).await??;
    Ok((h[0], body))
}

async fn flight(client: &mut TcpStream, sent_hello: &[u8]) -> Result<()> {
    let mut all = Vec::new();
    for expected in [0x16, 0x14, 0x17] {
        let (kind, body) = read_record(client).await?;
        assert_eq!(kind, expected);
        all.extend_from_slice(&wire::record(kind, &body)?);
    }
    let received = all[11..43].to_vec();
    all[11..43].fill(0);
    let mut hmac = Hmac::<Sha256>::new_from_slice(&secret())?;
    hmac.update(&sent_hello[11..43]);
    hmac.update(&all);
    ensure!(hmac.verify_slice(&received).is_ok(), "SH HMAC mismatch");
    assert_eq!(&all[44..76], &sent_hello[44..76]);
    Ok(())
}

async fn roundtrip(state: Arc<State>, bytes: &[u8]) -> Result<Vec<u8>> {
    let (mut client, task) = proxy(state).await?;
    client.write_all(bytes).await?;
    client.shutdown().await?;
    let mut result = Vec::new();
    timeout(Duration::from_secs(2), client.read_to_end(&mut result)).await??;
    // Authenticated probes ending before their inner header legitimately return EOF errors.
    let _ = timeout(Duration::from_secs(2), task).await??;
    Ok(result)
}

#[tokio::test]
async fn inv01_invalid_auth_garbage_and_truncated_hello_reach_cover_unchanged() -> Result<()> {
    let mut cover = cover_mock().await?;
    let state = state(cover.addr, closed_port().await?);
    let mut bad_mac = hello()?;
    bad_mac[11] ^= 1;
    let mut skew = hello()?;
    let old = 1700000000u32.to_le_bytes();
    let now = (SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32).to_le_bytes();
    for i in 0..4 {
        skew[39 + i] ^= old[i] ^ now[i];
    }
    let cases = [
        b"GET / HTTP/1.1\r\n\r\n".to_vec(),
        bad_mac,
        skew,
        vec![0x16, 3],
    ];
    for input in cases {
        assert_eq!(roundtrip(state.clone(), &input).await?, COVER_REPLY);
        assert_eq!(
            timeout(Duration::from_secs(1), cover.received.recv())
                .await?
                .context("cover capture")?,
            input
        );
    }
    Ok(())
}

#[tokio::test]
async fn inv08_split_hello_1_through_16_records_authenticates_and_17_relays_exactly() -> Result<()>
{
    let mut cover = cover_mock().await?;
    for records in 1..=16 {
        let state = state(cover.addr, closed_port().await?);
        let raw = hello()?;
        let (mut client, task) = proxy(state).await?;
        // TCP fragmentation independent of TLS record fragmentation.
        for byte in fragmented(&raw, records) {
            client.write_all(&[byte]).await?;
        }
        flight(&mut client, &raw).await?;
        client.shutdown().await?;
        assert!(timeout(Duration::from_secs(1), task).await??.is_err());
    }
    let raw = fragmented(&hello()?, 17);
    assert_eq!(
        roundtrip(state(cover.addr, closed_port().await?), &raw).await?,
        COVER_REPLY
    );
    assert_eq!(cover.received.recv().await.context("cover capture")?, raw);
    Ok(())
}

#[tokio::test]
async fn single_record_can_authenticate_with_its_original_tls_header() -> Result<()> {
    let cover = cover_mock().await?;
    let (mut client, task) = proxy(state(cover.addr, closed_port().await?)).await?;
    let mut raw = hello()?;
    raw[2] = 3;
    raw[11..43].fill(0);
    let mut hmac = Hmac::<Sha256>::new_from_slice(&secret())?;
    hmac.update(&raw);
    raw[11..43].copy_from_slice(&hmac.finalize().into_bytes());
    let now = (SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32).to_le_bytes();
    for (byte, time) in raw[39..43].iter_mut().zip(now) {
        *byte ^= time;
    }
    client.write_all(&raw).await?;
    flight(&mut client, &raw).await?;
    client.shutdown().await?;
    assert!(timeout(Duration::from_secs(1), task).await??.is_err());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inv02_concurrent_identical_hellos_accept_exactly_one() -> Result<()> {
    let cover = cover_mock().await?;
    let mut state = state(cover.addr, closed_port().await?);
    let config = Arc::get_mut(&mut state).context("unique state")?;
    config.handshake = Duration::from_secs(2);
    config.idle = Duration::from_secs(2);
    let raw = hello()?;
    let barrier = Arc::new(Barrier::new(8));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let (state, raw, barrier) = (state.clone(), raw.clone(), barrier.clone());
        tasks.spawn(async move {
            barrier.wait().await;
            roundtrip(state, &raw).await
        });
    }
    let (mut accepted, mut covered) = (0, 0);
    while let Some(result) = tasks.join_next().await {
        let result = result??;
        if result.starts_with(&[0x16, 3, 3]) {
            accepted += 1;
        } else {
            assert_eq!(result, COVER_REPLY);
            covered += 1;
        }
    }
    assert_eq!((accepted, covered), (1, 7));
    Ok(())
}

#[tokio::test]
async fn inv01_errors_after_server_hello_never_fall_back_to_cover() -> Result<()> {
    let mut cover = cover_mock().await?;
    let mut unconfigured = fixture("init")?;
    unconfigured[60] ^= 2 ^ 3; // Authenticated obfuscated header targeting unconfigured DC3.
    for inner in [
        wire::record(0x17, &[0; 64])?,
        wire::record(0x17, &unconfigured)?,
        wire::record(0x17, &fixture("init")?)?,
    ] {
        let (mut client, task) = proxy(state(cover.addr, closed_port().await?)).await?;
        let raw = hello()?;
        client.write_all(&raw).await?;
        flight(&mut client, &raw).await?;
        client.write_all(&inner).await?;
        client.shutdown().await?;
        let mut result = Vec::new();
        timeout(Duration::from_secs(1), client.read_to_end(&mut result)).await??;
        assert!(result.is_empty());
        assert!(timeout(Duration::from_secs(1), task).await??.is_err());
    }
    assert!(cover.received.try_recv().is_err());
    Ok(())
}

#[tokio::test]
async fn inv03_handshake_deadline_bounds_slow_client_and_keeps_prefix_for_cover() -> Result<()> {
    let mut cover = cover_mock().await?;
    let (mut client, task) = proxy(state(cover.addr, closed_port().await?)).await?;
    client.write_all(&[0x16, 3]).await?;
    // Wait until the handshake deadline passes while the peer keeps the socket open.
    tokio::time::sleep(Duration::from_millis(200)).await;
    client.shutdown().await?;
    let mut response = Vec::new();
    timeout(Duration::from_secs(1), client.read_to_end(&mut response)).await??;
    assert_eq!(response, COVER_REPLY);
    assert_eq!(
        cover.received.recv().await.context("cover prefix")?,
        [0x16, 3]
    );
    timeout(Duration::from_secs(1), task).await???;
    Ok(())
}

#[tokio::test]
async fn inv03_admission_permit_is_released_when_authenticated_client_disconnects() -> Result<()> {
    let cover = cover_mock().await?;
    let state = state(cover.addr, closed_port().await?);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(serve(listener, state, 1, async {
        let _ = stopped.await;
    }));
    let raw = hello()?;
    let mut first = TcpStream::connect(address).await?;
    first.write_all(&raw).await?;
    flight(&mut first, &raw).await?;
    let mut second = TcpStream::connect(address).await?;
    // Change CH timestamp bytes without changing its canonical replay key would be a replay.
    // Instead send only a non-TLS byte: cover may run only after admission is released.
    second.write_all(b"G").await?;
    second.shutdown().await?;
    assert!(timeout(Duration::from_millis(20), second.read_u8())
        .await
        .is_err());
    drop(first);
    let mut response = Vec::new();
    timeout(Duration::from_secs(1), second.read_to_end(&mut response)).await??;
    assert_eq!(response, COVER_REPLY);
    let _ = stop.send(());
    timeout(Duration::from_secs(1), server).await???;
    Ok(())
}

#[tokio::test]
async fn inv03_shutdown_closes_listener_even_when_all_admission_permits_are_used() -> Result<()> {
    let cover = cover_mock().await?;
    let mut state = state(cover.addr, closed_port().await?);
    Arc::get_mut(&mut state)
        .context("unique test state")?
        .handshake = Duration::from_secs(5);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(serve(listener, state, 1, async {
        let _ = stopped.await;
    }));
    let mut client = TcpStream::connect(address).await?;
    let raw = hello()?;
    client.write_all(&raw).await?;
    flight(&mut client, &raw).await?;
    let _ = stop.send(());
    // Completion must not wait for the 5-second handshake/admission permit.
    timeout(Duration::from_secs(1), server).await???;
    assert!(TcpStream::connect(address).await.is_err());
    Ok(())
}

#[tokio::test]
async fn inv05_direct_relay_keeps_crypto_offsets_when_init_and_payload_share_record() -> Result<()>
{
    direct_relay_roundtrip(true).await
}

#[tokio::test]
async fn dd_direct_relay_keeps_crypto_offsets_without_tls_records() -> Result<()> {
    direct_relay_roundtrip(false).await
}

async fn direct_relay_roundtrip(framed: bool) -> Result<()> {
    let cover = cover_mock().await?;
    let dc = TcpListener::bind("127.0.0.1:0").await?;
    let mut state = state(cover.addr, dc.local_addr()?);
    Arc::get_mut(&mut state).context("unique state")?.enable_dd = true;
    let dc_task = tokio::spawn(async move {
        let (mut peer, _) = dc.accept().await?;
        let mut header = [0; 64];
        peer.read_exact(&mut header).await?;
        let mut decode = AesCtr::new_from_slices(&header[8..40], &header[40..56])?;
        let mut plain = header;
        wire::crypt(&mut decode, &mut plain);
        ensure!(plain[56..60] == [0xdd; 4], "DC transport tag");
        let mut payload = vec![0; CLIENT_PAYLOAD.len()];
        peer.read_exact(&mut payload).await?;
        wire::crypt(&mut decode, &mut payload);
        assert_eq!(payload, CLIENT_PAYLOAD);
        let mut trailing = [0; 1];
        assert_eq!(peer.read(&mut trailing).await?, 0);
        let reversed: Vec<_> = header[8..56].iter().rev().copied().collect();
        let mut encode = AesCtr::new_from_slices(&reversed[..32], &reversed[32..])?;
        let mut reply = DC_REPLY.to_vec();
        wire::crypt(&mut encode, &mut reply);
        for part in reply.chunks(3) {
            peer.write_all(part).await?;
        }
        peer.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    });
    let (mut client, task) = proxy(state.clone()).await?;
    let mut bytes = fixture("init")?;
    bytes.extend_from_slice(&fixture("payload")?);
    if framed {
        let raw = hello()?;
        client.write_all(&raw).await?;
        flight(&mut client, &raw).await?;
        client.write_all(&wire::record(0x17, &bytes)?).await?;
    } else {
        client.write_all(&bytes).await?;
    }
    client.shutdown().await?;
    let mut reply = Vec::new();
    if framed {
        while reply.len() < DC_REPLY.len() {
            let (kind, bytes) = read_record(&mut client).await?;
            assert_eq!(kind, 0x17);
            reply.extend_from_slice(&bytes);
        }
    } else {
        reply.resize(DC_REPLY.len(), 0);
        timeout(Duration::from_secs(1), client.read_exact(&mut reply)).await??;
    }
    assert_eq!(reply, fixture("reply")?);
    timeout(Duration::from_secs(1), task).await???;
    timeout(Duration::from_secs(1), dc_task).await???;
    if !framed {
        // The initial eight bytes are not part of the key or the IV.
        bytes[0] ^= 1;
        assert!(roundtrip(state, &bytes[..64]).await?.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn ios_application_record_can_span_two_relay_reads() -> Result<()> {
    let mut stream = vec![0x17, 3, 3];
    stream.extend_from_slice(&16_408u16.to_be_bytes());
    stream.extend(std::iter::repeat_n(0x42, 16_384));
    stream.extend_from_slice(&[0x24; 24]);
    stream.extend_from_slice(&wire::record(0x17, b"next record")?);
    let mut recv = stream.as_slice();
    let mut tls = TlsReader::default();
    let mut buf = [0; wire::MAX_RECORD];
    assert_eq!(tls.read_into(&mut recv, &mut buf).await?, buf.len());
    assert_eq!(buf, [0x42; wire::MAX_RECORD]);
    assert_eq!(tls.read_into(&mut recv, &mut buf).await?, 24);
    assert_eq!(&buf[..24], &[0x24; 24]);
    assert_eq!(tls.read_into(&mut recv, &mut buf).await?, 11);
    assert_eq!(&buf[..11], b"next record");
    assert_eq!(tls.read_into(&mut recv, &mut buf).await?, 0);
    Ok(())
}

#[tokio::test]
async fn tls_reader_counts_partial_bytes_at_the_handshake_deadline() -> Result<()> {
    let (mut send, mut recv) = tokio::io::duplex(64);
    let incomplete = [0x17, 3, 3, 0, 64, 1, 2, 3];
    send.write_all(&incomplete).await?;
    let mut tls = TlsReader::default();
    let mut out = [0; 64];
    assert!(timeout(
        Duration::from_millis(40),
        tls.read_into(&mut recv, &mut out)
    )
    .await
    .is_err());
    assert_eq!(tls.consumed, incomplete.len() as u64);

    let mut header = &[0x17, 3, 3][..];
    let mut tls = TlsReader::default();
    let error = tls
        .read_into(&mut header, &mut out)
        .await
        .err()
        .context("incomplete TLS header unexpectedly succeeded")?;
    assert_eq!(io_kind(&error), "unexpected_eof");
    assert_eq!(tls.consumed, 3);
    Ok(())
}

#[tokio::test]
async fn inv08_reject_oversize_tls_before_allocation() -> Result<()> {
    let (mut send, mut recv) = tokio::io::duplex(100);
    let length = 16_409u16.to_be_bytes();
    send.write_all(&[0x17, 3, 3, length[0], length[1]]).await?;
    let mut tls = TlsReader::default();
    assert!(tls.read_into(&mut recv, &mut [0; 64]).await.is_err());
    assert!(tls.pending.is_empty());
    Ok(())
}

#[tokio::test]
async fn inv03_blackholed_dc_has_finite_idle_deadline_without_cover_fallback() -> Result<()> {
    let mut cover = cover_mock().await?;
    let dc = TcpListener::bind("127.0.0.1:0").await?;
    let state = state(cover.addr, dc.local_addr()?);
    let dc_task = tokio::spawn(async move {
        let (mut peer, _) = dc.accept().await?;
        let mut sent = Vec::new();
        // Consume everything, never reply: deterministic local upstream blackhole.
        timeout(Duration::from_secs(5), peer.read_to_end(&mut sent))
            .await
            .context("DC mock did not see the relay close")??;
        ensure!(
            sent.len() == 64 + CLIENT_PAYLOAD.len(),
            "forwarded bytes missing"
        );
        Ok::<_, anyhow::Error>(())
    });
    let (mut client, task) = proxy(state).await?;
    let raw = hello()?;
    client.write_all(&raw).await?;
    flight(&mut client, &raw).await?;
    let mut bytes = fixture("init")?;
    bytes.extend_from_slice(&fixture("payload")?);
    client.write_all(&wire::record(0x17, &bytes)?).await?;
    let mut byte = [0];
    assert_eq!(
        timeout(Duration::from_secs(3), client.read(&mut byte))
            .await
            .context("client did not see the idle session close")??,
        0
    );
    let error = timeout(Duration::from_secs(3), task)
        .await??
        .err()
        .context("idle relay returned success")?;
    assert!(format!("{error:#}").contains("session idle timeout"));
    timeout(Duration::from_secs(3), dc_task).await???;
    assert!(cover.received.try_recv().is_err());
    Ok(())
}

#[tokio::test]
async fn inv03_stalled_writer_releases_upload_at_deadline() -> Result<()> {
    let (mut input, reader) = tokio::io::duplex(100);
    let (writer, _stalled_peer) = tokio::io::duplex(1);
    let decoder = AesCtr::new_from_slices(&[0; 32], &[0; 16])?;
    let encoder = AesCtr::new_from_slices(&[0; 32], &[0; 16])?;
    input
        .write_all(&wire::record(0x17, b"blocked bytes")?)
        .await?;
    let result = timeout(
        Duration::from_secs(1),
        upload(
            reader,
            writer,
            Some(TlsReader::default()),
            decoder,
            encoder,
            Duration::from_millis(30),
            &RelayStats::default(),
        ),
    )
    .await?;
    assert!(result.is_err());
    Ok(())
}

#[tokio::test]
async fn listener_health_connect_close_does_not_dial_cover() -> Result<()> {
    let address = closed_port().await?;
    let (client, task) = proxy(state(address, address)).await?;
    drop(client);
    // Cover is deliberately unreachable: an unnecessary outbound dial would fail.
    timeout(Duration::from_secs(1), task).await???;
    Ok(())
}

#[tokio::test]
async fn idle_preconnection_releases_slot_without_cover() -> Result<()> {
    let mut cover = cover_mock().await?;
    let (mut client, task) = proxy(state(cover.addr, closed_port().await?)).await?;
    let mut byte = [0];
    assert_eq!(
        timeout(Duration::from_secs(1), client.read(&mut byte)).await??,
        0
    );
    timeout(Duration::from_secs(1), task).await???;
    assert!(cover.received.try_recv().is_err());
    Ok(())
}

#[tokio::test]
async fn partial_tls_record_timeout_closes_without_dialing_cover() -> Result<()> {
    let cover = TcpListener::bind("127.0.0.1:0").await?;
    let (mut client, task) = proxy(state(cover.local_addr()?, closed_port().await?)).await?;
    client.write_all(&[0x16, 3, 1, 0x08, 0x00, 1]).await?;
    assert_eq!(
        timeout(Duration::from_secs(1), client.read(&mut [0])).await??,
        0
    );
    client.shutdown().await?;
    timeout(Duration::from_secs(1), task).await???;
    assert!(timeout(Duration::from_millis(30), cover.accept())
        .await
        .is_err());
    Ok(())
}

#[tokio::test]
async fn saturated_cover_leaves_capacity_for_direct_connections() -> Result<()> {
    let cover = TcpListener::bind("127.0.0.1:0").await?;
    let dc = TcpListener::bind("127.0.0.1:0").await?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let mut config = state(cover.local_addr()?, dc.local_addr()?);
    let settings = Arc::get_mut(&mut config).context("unique state")?;
    settings.cover_permits = Semaphore::new(1);
    settings.handshake = Duration::from_secs(2);
    settings.idle = Duration::from_secs(10);
    let (stop, shutdown) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(serve(listener, config, 4, async {
        let _ = shutdown.await;
    }));

    let mut prefix = hello()?;
    prefix[11] ^= 1;
    let mut stalled = TcpStream::connect(address).await?;
    stalled.write_all(&prefix).await?;
    let (mut cover_peer, _) = timeout(Duration::from_secs(4), cover.accept()).await??;
    let mut received = vec![0; prefix.len()];
    timeout(Duration::from_secs(1), cover_peer.read_exact(&mut received)).await??;
    assert_eq!(received, prefix);

    let mut rejected = TcpStream::connect(address).await?;
    rejected.write_all(&prefix).await?;
    rejected.shutdown().await?;
    assert_eq!(
        timeout(Duration::from_secs(1), rejected.read(&mut [0; 1])).await??,
        0
    );

    let mut direct = TcpStream::connect(address).await?;
    let raw = hello()?;
    direct.write_all(&raw).await?;
    flight(&mut direct, &raw).await?;
    direct
        .write_all(&wire::record(0x17, &fixture("init")?)?)
        .await?;
    let (mut dc_peer, _) = timeout(Duration::from_secs(1), dc.accept()).await??;
    let mut header = [0; 64];
    timeout(Duration::from_secs(1), dc_peer.read_exact(&mut header)).await??;
    let mut decode = AesCtr::new_from_slices(&header[8..40], &header[40..56])?;
    wire::crypt(&mut decode, &mut header);
    assert_eq!(&header[56..60], &[0xdd; 4]);

    drop((dc_peer, direct, cover_peer, stalled));
    let _ = stop.send(());
    timeout(Duration::from_secs(1), server).await???;
    Ok(())
}

#[tokio::test]
async fn diagnostics_attribute_dc_close_after_reply() -> Result<()> {
    let (mut dc_peer, dc_reader) = tokio::io::duplex(1024);
    let (client_writer, _client_peer) = tokio::io::duplex(1024);
    let decoder = AesCtr::new_from_slices(&[0; 32], &[0; 16])?;
    let encoder = AesCtr::new_from_slices(&[0; 32], &[0; 16])?;
    dc_peer.write_all(b"reply bytes").await?;
    drop(dc_peer);
    let stats = RelayStats::default();
    download(
        dc_reader,
        client_writer,
        decoder,
        encoder,
        true,
        Duration::from_secs(1),
        &stats,
    )
    .await?;
    let summary = stats.summary();
    assert_eq!(summary["initiator"], "dc_eof");
    assert_eq!(summary["class"], "dc_closed_after_reply");
    assert_eq!(summary["downloaded_bytes"], 11);
    assert_eq!(summary["dc_reads"], 1);
    Ok(())
}

#[tokio::test]
async fn diagnostics_attribute_client_close_before_reply() -> Result<()> {
    let (client_peer, reader) = tokio::io::duplex(1024);
    let (writer, _dc_peer) = tokio::io::duplex(1024);
    let decoder = AesCtr::new_from_slices(&[0; 32], &[0; 16])?;
    let encoder = AesCtr::new_from_slices(&[0; 32], &[0; 16])?;
    drop(client_peer);
    let stats = RelayStats::default();
    upload(
        reader,
        writer,
        Some(TlsReader::default()),
        decoder,
        encoder,
        Duration::from_secs(1),
        &stats,
    )
    .await?;
    let summary = stats.summary();
    assert_eq!(summary["initiator"], "client_eof");
    assert_eq!(summary["class"], "client_closed_before_any_dc_reply");
    Ok(())
}

#[tokio::test]
async fn downstream_activity_keeps_relay_alive_and_dc_eof_ends_it() -> Result<()> {
    let (mut dc_peer, dc_reader) = tokio::io::duplex(1024);
    let (client_writer, mut client_peer) = tokio::io::duplex(1024);
    let (client_input, client_reader) = tokio::io::duplex(1024);
    let (dc_writer, _dc_input) = tokio::io::duplex(1024);
    let stats = RelayStats::default();
    let idle = Duration::from_millis(250);
    let cipher = || AesCtr::new_from_slices(&[0; 32], &[0; 16]);
    let relay = relay_until_end(
        &stats,
        idle,
        upload(
            client_reader,
            dc_writer,
            Some(TlsReader::default()),
            cipher()?,
            cipher()?,
            idle,
            &stats,
        ),
        download(
            dc_reader,
            client_writer,
            cipher()?,
            cipher()?,
            true,
            idle,
            &stats,
        ),
    );
    let peers = async {
        for byte in 0..8u8 {
            tokio::time::sleep(Duration::from_millis(45)).await;
            dc_peer.write_all(&[byte]).await?;
            assert_eq!(read_record(&mut client_peer).await?, (0x17, vec![byte]));
        }
        dc_peer.shutdown().await?;
        assert_eq!(client_peer.read(&mut [0u8]).await?, 0);
        Ok::<_, anyhow::Error>(())
    };
    timeout(Duration::from_secs(2), async {
        tokio::try_join!(relay, peers)
    })
    .await??;
    assert_eq!(stats.summary()["initiator"], "dc_eof");
    assert_eq!(stats.summary()["downloaded_bytes"], 8);
    drop(client_input);
    Ok(())
}

#[tokio::test]
async fn dc_eof_sends_fin_while_client_write_half_is_open() -> Result<()> {
    let cover = cover_mock().await?;
    let dc = TcpListener::bind("127.0.0.1:0").await?;
    let mut config = state(cover.addr, dc.local_addr()?);
    Arc::get_mut(&mut config).context("unique state")?.idle = Duration::from_secs(10);
    let dc_task = tokio::spawn(async move {
        let (mut peer, _) = dc.accept().await?;
        peer.read_exact(&mut [0; 64]).await?;
        peer.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    });
    let (mut client, task) = proxy(config).await?;
    let raw = hello()?;
    client.write_all(&raw).await?;
    flight(&mut client, &raw).await?;
    client
        .write_all(&wire::record(0x17, &fixture("init")?)?)
        .await?;
    assert_eq!(
        timeout(Duration::from_secs(1), client.read(&mut [0u8]))
            .await
            .context("client did not see FIN promptly")??,
        0
    );
    timeout(Duration::from_secs(5), task)
        .await
        .context("relay did not finish its bounded drain")???;
    timeout(Duration::from_secs(1), dc_task).await???;
    Ok(())
}

#[tokio::test]
async fn proxy_v2_forwards_client_hello_and_relays() -> Result<()> {
    let cover = cover_mock().await?;
    let dc = TcpListener::bind("127.0.0.1:0").await?;
    let mut config = state(cover.addr, dc.local_addr()?);
    Arc::get_mut(&mut config)
        .context("unique state")?
        .proxy_protocol = true;
    let dc_task = tokio::spawn(async move {
        let (mut peer, _) = dc.accept().await?;
        let mut hdr = [0u8; 64];
        peer.read_exact(&mut hdr).await?;
        peer.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    });
    let (mut client, task) = proxy(config).await?;
    let mut pp = vec![
        0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a, 0x21, 0x11, 0x00,
        0x0c,
    ];
    pp.extend_from_slice(&[203, 0, 113, 10, 198, 51, 100, 2, 0x9c, 0x40, 0x01, 0xbb]);
    client.write_all(&pp).await?;
    let raw = hello()?;
    client.write_all(&raw).await?;
    flight(&mut client, &raw).await?;
    client
        .write_all(&wire::record(0x17, &fixture("init")?)?)
        .await?;
    assert_eq!(
        timeout(Duration::from_secs(1), client.read(&mut [0u8])).await??,
        0
    );
    timeout(Duration::from_secs(5), task).await???;
    timeout(Duration::from_secs(1), dc_task).await???;
    Ok(())
}

#[tokio::test]
async fn proxy_v2_invalid_header_never_falls_back_to_cover() -> Result<()> {
    let mut cover = cover_mock().await?;
    let mut config = state(cover.addr, "127.0.0.1:1".parse()?);
    Arc::get_mut(&mut config)
        .context("unique state")?
        .proxy_protocol = true;
    let (mut client, task) = proxy(config).await?;
    let raw = hello()?;
    client.write_all(&raw).await?;
    let read_result = timeout(Duration::from_secs(1), client.read(&mut [0u8])).await?;
    assert!(matches!(read_result, Ok(0) | Err(_)));
    assert!(timeout(Duration::from_secs(1), task).await??.is_err());
    assert!(cover.received.try_recv().is_err());
    Ok(())
}

#[tokio::test]
async fn proxy_v2_empty_eof_is_clean_for_healthchecks() -> Result<()> {
    let cover = cover_mock().await?;
    let mut config = state(cover.addr, "127.0.0.1:1".parse()?);
    Arc::get_mut(&mut config)
        .context("unique state")?
        .proxy_protocol = true;
    let (client, task) = proxy(config).await?;
    drop(client);
    timeout(Duration::from_secs(1), task).await???;
    Ok(())
}

#[tokio::test]
async fn proxy_v2_untrusted_peer_rejected_before_reading_header_or_cover() -> Result<()> {
    let mut cover = cover_mock().await?;
    let dc = TcpListener::bind("127.0.0.1:0").await?;
    let mut config = state(cover.addr, dc.local_addr()?);
    Arc::get_mut(&mut config)
        .context("unique state")?
        .proxy_protocol = true;

    // Case A: Non-loopback untrusted peer simulated directly via connection_with_peer_and_drain.
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (cl_fut, srv_fut) = (TcpStream::connect(addr), listener.accept());
    let (cl_res, srv_res) = tokio::join!(cl_fut, srv_fut);
    let mut client = cl_res?;
    let (srv_stream, _) = srv_res?;
    let cfg_clone = config.clone();
    let task = tokio::spawn(async move {
        serve::connection_with_peer_and_drain(
            srv_stream,
            Some("203.0.113.50:41234".parse()?),
            cfg_clone,
            serve::inactive_drain_rx(),
        )
        .await
    });
    let mut pp = vec![
        0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a, 0x21, 0x11, 0x00,
        0x0c,
    ];
    pp.extend_from_slice(&[203, 0, 113, 10, 198, 51, 100, 2, 0x9c, 0x40, 0x01, 0xbb]);
    let _ = client.write_all(&pp).await;
    let _ = client.write_all(&hello()?).await;
    assert!(timeout(Duration::from_secs(1), task).await??.is_err());
    assert!(cover.received.try_recv().is_err());

    // Case B: Explicit CIDR allowlist rejects non-loopback peers outside 10.203.0.0/24 (e.g. 10.204.0.99),
    // while keeping container loopback self-probes (127.0.0.1) working.
    let mut config_cidr = state(cover.addr, dc.local_addr()?);
    {
        let st_mut = Arc::get_mut(&mut config_cidr).context("unique state")?;
        st_mut.proxy_protocol = true;
        st_mut.proxy_protocol_allow_from = vec![config::IpCidr::parse("10.203.0.0/24")?];
    }
    let (cl2_res, srv2_res) = tokio::join!(TcpStream::connect(addr), listener.accept());
    let mut client2 = cl2_res?;
    let (srv2_stream, _) = srv2_res?;
    let cfg_cidr_clone = config_cidr.clone();
    let task2 = tokio::spawn(async move {
        serve::connection_with_peer_and_drain(
            srv2_stream,
            Some("10.204.0.99:41234".parse()?),
            cfg_cidr_clone,
            serve::inactive_drain_rx(),
        )
        .await
    });
    let _ = client2.write_all(&pp).await;
    assert!(timeout(Duration::from_secs(1), task2).await??.is_err());
    assert!(cover.received.try_recv().is_err());
    Ok(())
}

#[tokio::test]
async fn proxy_v2_explicit_allow_from_cidr_accepts_trusted_proxy_peer() -> Result<()> {
    let cover = cover_mock().await?;
    let dc = TcpListener::bind("127.0.0.1:0").await?;
    let mut config = state(cover.addr, dc.local_addr()?);
    {
        let st_mut = Arc::get_mut(&mut config).context("unique state")?;
        st_mut.proxy_protocol = true;
        st_mut.proxy_protocol_allow_from = vec![config::IpCidr::parse("127.0.0.0/8")?];
    }
    let dc_task = tokio::spawn(async move {
        let (mut peer, _) = dc.accept().await?;
        let mut hdr = [0u8; 64];
        peer.read_exact(&mut hdr).await?;
        peer.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    });
    let (mut client, task) = proxy(config).await?;
    let mut pp = vec![
        0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a, 0x21, 0x11, 0x00,
        0x0c,
    ];
    pp.extend_from_slice(&[203, 0, 113, 10, 198, 51, 100, 2, 0x9c, 0x40, 0x01, 0xbb]);
    client.write_all(&pp).await?;
    let raw = hello()?;
    client.write_all(&raw).await?;
    flight(&mut client, &raw).await?;
    client
        .write_all(&wire::record(0x17, &fixture("init")?)?)
        .await?;
    assert_eq!(
        timeout(Duration::from_secs(1), client.read(&mut [0u8])).await??,
        0
    );
    timeout(Duration::from_secs(5), task).await???;
    timeout(Duration::from_secs(1), dc_task).await???;
    Ok(())
}

#[tokio::test]
async fn bind_listener_accepts_optional_mss() -> Result<()> {
    let listener = bind_listener("127.0.0.1:0".parse()?, Some(92))?;
    assert!(listener.local_addr()?.port() > 0);
    Ok(())
}

#[tokio::test]
async fn multi_secret_and_flight_shaping_authenticate_and_relay() -> Result<()> {
    let mut cover = cover_mock().await?;
    let dc = TcpListener::bind("127.0.0.1:0").await?;
    let dc_addr = dc.local_addr()?;
    let mut cfg = state(cover.addr, dc_addr);
    let state_mut = Arc::get_mut(&mut cfg).context("unique state")?;
    state_mut.secrets = std::sync::RwLock::new(Arc::new(vec![
        NamedSecret {
            name: "other".into(),
            key: Zeroizing::new([0x11u8; 16]),
        },
        NamedSecret {
            name: "alice".into(),
            key: Zeroizing::new(secret()),
        },
    ]));
    state_mut.flight_shaping = true;
    state_mut.handshake = Duration::from_secs(1);

    let (mut client, task) = proxy(cfg).await?;
    let dc_task = tokio::spawn(async move {
        let (mut peer, _) = dc.accept().await?;
        let mut header = [0u8; 64];
        peer.read_exact(&mut header).await?;
        let mut decode = AesCtr::new_from_slices(&header[8..40], &header[40..56])?;
        let mut plain = header;
        wire::crypt(&mut decode, &mut plain);
        let mut payload = vec![0; CLIENT_PAYLOAD.len()];
        peer.read_exact(&mut payload).await?;
        wire::crypt(&mut decode, &mut payload);
        assert_eq!(payload, CLIENT_PAYLOAD);
        let reversed: Vec<_> = header[8..56].iter().rev().copied().collect();
        let mut encode = AesCtr::new_from_slices(&reversed[..32], &reversed[32..])?;
        let mut reply = DC_REPLY.to_vec();
        wire::crypt(&mut encode, &mut reply);
        peer.write_all(&reply).await?;
        peer.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    });

    let raw = hello()?;
    client.write_all(&raw).await?;
    flight(&mut client, &raw).await?;
    let mut bytes = fixture("init")?;
    bytes.extend_from_slice(&fixture("payload")?);
    client.write_all(&wire::record(0x17, &bytes)?).await?;
    client.shutdown().await?;
    let mut reply = Vec::new();
    while reply.len() < DC_REPLY.len() {
        let (kind, part) = read_record(&mut client).await?;
        assert_eq!(kind, 0x17);
        reply.extend_from_slice(&part);
    }
    assert_eq!(reply, fixture("reply")?);
    timeout(Duration::from_secs(3), task).await???;
    timeout(Duration::from_secs(3), dc_task).await???;
    assert!(cover.received.try_recv().is_err());
    Ok(())
}

#[tokio::test]
async fn edge_to_egress_with_failover_relays_end_to_end() -> Result<()> {
    let cover = cover_mock().await?;
    let dc = TcpListener::bind("127.0.0.1:0").await?;
    let dc_addr = dc.local_addr()?;

    let token = [0x5au8; 16];
    let bad_dc = closed_port().await?;
    let bad_egress = TcpListener::bind("127.0.0.1:0").await?;
    let bad_egress_addr = bad_egress.local_addr()?;
    let (bad_tx, bad_rx) = tokio::sync::oneshot::channel::<()>();
    let bad_task = tokio::spawn(serve_egress(
        bad_egress,
        Arc::new(HashMap::from([(2, bad_dc)])),
        token,
        8,
        Duration::from_millis(200),
        Duration::from_secs(2),
        Duration::from_millis(50),
        Arc::new(telemetry::Counters::default()),
        async move {
            let _ = bad_rx.await;
        },
    ));

    let egress_listener = TcpListener::bind("127.0.0.1:0").await?;
    let egress_addr = egress_listener.local_addr()?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let egress_dcs = Arc::new(HashMap::from([(2, dc_addr)]));
    let egress_counters = Arc::new(telemetry::Counters::default());
    let egress_task = tokio::spawn(serve_egress(
        egress_listener,
        egress_dcs,
        token,
        8,
        Duration::from_millis(200),
        Duration::from_secs(2),
        Duration::from_millis(50),
        egress_counters,
        async move {
            let _ = shutdown_rx.await;
        },
    ));

    // Verify wrong token is rejected by egress.
    let mut rogue = TcpStream::connect(egress_addr).await?;
    let mut bad_preface = [0u8; 24];
    bad_preface[..4].copy_from_slice(&EGRESS_MAGIC);
    bad_preface[4..6].copy_from_slice(&2i16.to_le_bytes());
    bad_preface[8..24].copy_from_slice(&[0xff; 16]);
    rogue.write_all(&bad_preface).await?;
    assert_eq!(rogue.read(&mut [0u8; 1]).await?, 0);

    let mut cfg = state(cover.addr, "127.0.0.1:1".parse()?);
    let state_mut = Arc::get_mut(&mut cfg).context("unique state")?;
    state_mut.dcs.clear();
    state_mut.egress_upstreams = vec![bad_egress_addr.into(), egress_addr.into()];
    state_mut.egress_strategy = EgressStrategy::Ordered;
    state_mut.egress_token = token;
    state_mut.handshake = Duration::from_secs(2);

    let (mut client, task) = proxy(cfg).await?;
    let dc_task = tokio::spawn(async move {
        let (mut peer, _) = dc.accept().await?;
        let mut header = [0u8; 64];
        peer.read_exact(&mut header).await?;
        let mut decode = AesCtr::new_from_slices(&header[8..40], &header[40..56])?;
        let mut plain = header;
        wire::crypt(&mut decode, &mut plain);
        let mut payload = vec![0; CLIENT_PAYLOAD.len()];
        peer.read_exact(&mut payload).await?;
        wire::crypt(&mut decode, &mut payload);
        assert_eq!(payload, CLIENT_PAYLOAD);
        let reversed: Vec<_> = header[8..56].iter().rev().copied().collect();
        let mut encode = AesCtr::new_from_slices(&reversed[..32], &reversed[32..])?;
        let mut reply = DC_REPLY.to_vec();
        wire::crypt(&mut encode, &mut reply);
        peer.write_all(&reply).await?;
        peer.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    });

    let raw = hello()?;
    client.write_all(&raw).await?;
    flight(&mut client, &raw).await?;
    let mut bytes = fixture("init")?;
    bytes.extend_from_slice(&fixture("payload")?);
    client.write_all(&wire::record(0x17, &bytes)?).await?;
    client.shutdown().await?;
    let mut reply = Vec::new();
    while reply.len() < DC_REPLY.len() {
        let (kind, part) = read_record(&mut client).await?;
        assert_eq!(kind, 0x17);
        reply.extend_from_slice(&part);
    }
    assert_eq!(reply, fixture("reply")?);
    timeout(Duration::from_secs(3), task).await???;
    timeout(Duration::from_secs(3), dc_task).await???;
    let _ = bad_tx.send(());
    let _ = shutdown_tx.send(());
    timeout(Duration::from_secs(2), bad_task).await???;
    timeout(Duration::from_secs(2), egress_task).await???;
    Ok(())
}

#[tokio::test]
async fn edge_ordered_fails_over_on_ack_timeout() -> Result<()> {
    let cover = cover_mock().await?;
    let dc = TcpListener::bind("127.0.0.1:0").await?;
    let dc_addr = dc.local_addr()?;
    let token = [0x33u8; 16];

    // Stalled egress: accepts TCP, reads preface, never sends ACK.
    let stalled_listener = TcpListener::bind("127.0.0.1:0").await?;
    let stalled_addr = stalled_listener.local_addr()?;
    let stalled_task = tokio::spawn(async move {
        if let Ok((mut s, _)) = stalled_listener.accept().await {
            let mut buf = [0u8; 88];
            let _ = s.read_exact(&mut buf).await;
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });

    let egress_listener = TcpListener::bind("127.0.0.1:0").await?;
    let egress_addr = egress_listener.local_addr()?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let egress_task = tokio::spawn(serve_egress(
        egress_listener,
        Arc::new(HashMap::from([(2, dc_addr)])),
        token,
        8,
        Duration::from_millis(500),
        Duration::from_secs(1),
        Duration::from_millis(50),
        Arc::new(telemetry::Counters::default()),
        async move {
            let _ = shutdown_rx.await;
        },
    ));

    let mut cfg = state(cover.addr, "127.0.0.1:1".parse()?);
    let state_mut = Arc::get_mut(&mut cfg).context("unique state")?;
    state_mut.dcs.clear();
    state_mut.egress_upstreams = vec![stalled_addr.into(), egress_addr.into()];
    state_mut.egress_strategy = EgressStrategy::Ordered;
    state_mut.egress_token = token;
    state_mut.handshake = Duration::from_millis(800);
    let dc_task = tokio::spawn(async move {
        let (mut peer, _) = dc.accept().await?;
        let mut header = [0u8; 64];
        peer.read_exact(&mut header).await?;
        let mut decode = AesCtr::new_from_slices(&header[8..40], &header[40..56])?;
        let mut plain = header;
        wire::crypt(&mut decode, &mut plain);
        let mut payload = vec![0; CLIENT_PAYLOAD.len()];
        peer.read_exact(&mut payload).await?;
        wire::crypt(&mut decode, &mut payload);
        assert_eq!(payload, CLIENT_PAYLOAD);
        let reversed: Vec<_> = header[8..56].iter().rev().copied().collect();
        let mut encode = AesCtr::new_from_slices(&reversed[..32], &reversed[32..])?;
        let mut reply = DC_REPLY.to_vec();
        wire::crypt(&mut encode, &mut reply);
        peer.write_all(&reply).await?;
        peer.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    });

    let (mut client, task) = proxy(cfg).await?;
    let raw = hello()?;
    client.write_all(&raw).await?;
    flight(&mut client, &raw).await?;
    let mut bytes = fixture("init")?;
    bytes.extend_from_slice(&fixture("payload")?);
    client.write_all(&wire::record(0x17, &bytes)?).await?;
    client.shutdown().await?;
    let mut reply = Vec::new();
    while reply.len() < DC_REPLY.len() {
        let (kind, part) = read_record(&mut client).await?;
        assert_eq!(kind, 0x17);
        reply.extend_from_slice(&part);
    }
    assert_eq!(reply, fixture("reply")?);
    timeout(Duration::from_secs(3), task).await???;
    timeout(Duration::from_secs(3), dc_task).await???;
    stalled_task.abort();
    let _ = shutdown_tx.send(());
    timeout(Duration::from_secs(2), egress_task).await???;
    Ok(())
}

#[tokio::test]
async fn probe_egress_separates_tcp_token_and_dc_failures() -> Result<()> {
    let token = [0x5au8; 16];
    let ok_dc = TcpListener::bind("127.0.0.1:0").await?;
    let ok_dc_addr = ok_dc.local_addr()?;
    let _ok_dc_task = tokio::spawn(async move {
        let _ = ok_dc.accept().await;
    });
    let good_egress = TcpListener::bind("127.0.0.1:0").await?;
    let good_addr = good_egress.local_addr()?;
    let (good_tx, good_rx) = tokio::sync::oneshot::channel::<()>();
    let good_task = tokio::spawn(serve_egress(
        good_egress,
        Arc::new(HashMap::from([(2, ok_dc_addr)])),
        token,
        8,
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::from_millis(50),
        Arc::new(telemetry::Counters::default()),
        async move {
            let _ = good_rx.await;
        },
    ));

    let bad_dc = closed_port().await?;
    let bad_egress = TcpListener::bind("127.0.0.1:0").await?;
    let bad_addr = bad_egress.local_addr()?;
    let (bad_tx, bad_rx) = tokio::sync::oneshot::channel::<()>();
    let bad_task = tokio::spawn(serve_egress(
        bad_egress,
        Arc::new(HashMap::from([(2, bad_dc)])),
        token,
        8,
        Duration::from_millis(300),
        Duration::from_secs(1),
        Duration::from_millis(50),
        Arc::new(telemetry::Counters::default()),
        async move {
            let _ = bad_rx.await;
        },
    ));

    let closed_addr = closed_port().await?;
    let p_ok = probe_egress_endpoint(good_addr, 2, &token, Duration::from_secs(1)).await;
    assert!(p_ok.tcp_reachable && p_ok.token_status == "accepted" && p_ok.dc_reachable);
    let p_dc = probe_egress_endpoint(bad_addr, 2, &token, Duration::from_secs(2)).await;
    assert!(p_dc.tcp_reachable && p_dc.token_status == "accepted" && !p_dc.dc_reachable);
    let p_tok = probe_egress_endpoint(good_addr, 2, &[0xff; 16], Duration::from_secs(1)).await;
    assert!(
        p_tok.tcp_reachable
            && p_tok.token_status == "unknown"
            && p_tok.detail.contains("closed before ACK")
            && !p_tok.dc_reachable
    );
    let p_tcp = probe_egress_endpoint(closed_addr, 2, &token, Duration::from_secs(1)).await;
    assert!(!p_tcp.tcp_reachable && !p_tcp.dc_reachable);

    let _ = good_tx.send(());
    let _ = bad_tx.send(());
    timeout(Duration::from_secs(2), good_task).await???;
    timeout(Duration::from_secs(2), bad_task).await???;
    Ok(())
}

#[tokio::test]
async fn users_hot_reload_add_and_delete_during_active_download() -> Result<()> {
    let mut cover = cover_mock().await?;
    let dc = TcpListener::bind("127.0.0.1:0").await?;
    let dc_addr = dc.local_addr()?;

    let dir = std::env::temp_dir().join(format!(
        "mtevil-users-hot-reload-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    std::fs::create_dir_all(&dir)?;
    let users_path = dir.join("users.json");
    // Start with ONLY `users_file` (no `secret_file`) containing a single initial user `bob`,
    // so we test both background adding of `alice` and background deletion of the LAST user!
    std::fs::write(
        &users_path,
        format!("{{\"bob\":\"{}\"}}\n", hex::encode([0x44u8; 16])),
    )?;

    let file_cfg = Config {
        role: Role::Direct,
        listen: "127.0.0.1:0".parse()?,
        secret_file: None,
        users_file: Some(users_path.clone()),
        replay_file: None,
        sni: "example.com".into(),
        cover: cover.addr.to_string(),
        enable_dd: true,
        proxy_protocol: false,
        proxy_protocol_allow_from: Vec::new(),
        dc: vec![format!("2={dc_addr}")],
        egress_upstreams: Vec::new(),
        egress_strategy: EgressStrategy::RoundRobin,
        egress_token_file: None,
        egress_ws_path: None,
        egress_ws_pool_size: 4,
        egress_tls_ca_file: None,
        max_connections: 16,
        client_hello_timeout_secs: 2,
        handshake_timeout_secs: 2,
        idle_timeout_secs: 5,
        drain_timeout_secs: 1,
        fake_tls_cert_bytes: wire::DEFAULT_CERT_BYTES,
        fake_tls_cert_bytes_explicit: false,
        fake_tls_cert_jitter: 0,
        flight_shaping: false,
        client_mss: None,
        client_mss_bulk: None,
        alert_webhook_url: None,
        egress_cooldown_base_ms: config::default_egress_cooldown_base_ms(),
        egress_cooldown_max_ms: config::default_egress_cooldown_max_ms(),
        egress_probe_interval_secs: config::default_egress_probe_interval_secs(),
        egress_probe_degraded_interval_secs: config::default_egress_probe_degraded_interval_secs(),
        egress_hedge_ms: config::default_egress_hedge_ms(),
        egress_accept_legacy: config::default_egress_accept_legacy(),
        egress_use_mtv3: config::default_egress_use_mtv3(),
        egress_allow_from: Vec::new(),
        egress_max_failed_per_ip: config::default_egress_max_failed_per_ip(),
        egress_nonce_cache_capacity: None,
        dc_media_override: config::default_dc_media_override(),
        dc_probe_interval_secs: config::default_dc_probe_interval_secs(),
        cover_dns_ttl_secs: config::default_cover_dns_ttl_secs(),
        diagnostics: false,
        metrics_listen: None,
        me: config::MeConfig::default(),
    };

    let mut proxy_state = state(cover.addr, dc_addr);
    {
        let sm = Arc::get_mut(&mut proxy_state).context("unique state")?;
        sm.secrets = std::sync::RwLock::new(Arc::new(file_cfg.secrets()?));
        sm.enable_dd = true;
        sm.client_hello = Duration::from_secs(1);
        sm.handshake = Duration::from_secs(1);
        sm.idle = Duration::from_secs(3);
    }

    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let reload_task = spawn_users_reloader(
        proxy_state.clone(),
        file_cfg.clone(),
        Duration::from_millis(60),
        stop_rx,
    );

    // 1. Malformed JSON must not clobber existing `bob` when background reloader runs.
    std::fs::write(&users_path, "{invalid json")?;
    tokio::time::sleep(Duration::from_millis(160)).await;
    assert_eq!(proxy_state.current_secrets().len(), 1);
    assert_eq!(proxy_state.current_secrets()[0].name, "bob");

    // 2. Replace with ONLY `alice` (using the fixture secret) and wait for background reloader.
    {
        let _lock = lock_users_file(&users_path)?;
        let mut map = std::collections::BTreeMap::new();
        map.insert("alice".to_string(), hex::encode(secret()));
        write_users_map_atomic(&users_path, &map)?;
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    while proxy_state
        .current_secrets()
        .first()
        .map(|s| s.name.as_str())
        != Some("alice")
    {
        ensure!(
            Instant::now() < deadline,
            "background reloader did not load alice"
        );
        tokio::time::sleep(Duration::from_millis(30)).await;
    }

    // 3. Open an active session for `alice` and keep it open while deleting the LAST user `alice`!
    let (mut alice_open, alice_task) = proxy(proxy_state.clone()).await?;
    let dc_task = tokio::spawn(async move {
        let (mut peer, _) = dc.accept().await?;
        let mut header = [0u8; 64];
        peer.read_exact(&mut header).await?;
        let mut decode = AesCtr::new_from_slices(&header[8..40], &header[40..56])?;
        let mut plain = header;
        wire::crypt(&mut decode, &mut plain);
        let mut payload = vec![0; CLIENT_PAYLOAD.len()];
        peer.read_exact(&mut payload).await?;
        wire::crypt(&mut decode, &mut payload);
        assert_eq!(payload, CLIENT_PAYLOAD);
        let reversed: Vec<_> = header[8..56].iter().rev().copied().collect();
        let mut encode = AesCtr::new_from_slices(&reversed[..32], &reversed[32..])?;
        let mut reply = DC_REPLY.to_vec();
        wire::crypt(&mut encode, &mut reply);
        peer.write_all(&reply).await?;
        peer.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    });

    let raw = hello()?;
    alice_open.write_all(&raw).await?;
    flight(&mut alice_open, &raw).await?;

    // Delete the LAST user (`alice`) leaving `{}` in `users.json`, and wait for background reloader!
    {
        let _lock = lock_users_file(&users_path)?;
        let map = std::collections::BTreeMap::new();
        write_users_map_atomic(&users_path, &map)?;
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    while !proxy_state.current_secrets().is_empty() {
        ensure!(
            Instant::now() < deadline,
            "background reloader did not revoke the last deleted user"
        );
        tokio::time::sleep(Duration::from_millis(30)).await;
    }

    // 4. New connection with `alice`'s deleted last secret is rejected to cover.
    let (mut alice_new, new_task) = proxy(proxy_state.clone()).await?;
    alice_new.write_all(&hello()?).await?;
    alice_new.shutdown().await?;
    let relayed_to_cover = timeout(Duration::from_secs(2), cover.received.recv())
        .await?
        .context("deleted last user hello must go to cover")?;
    assert!(!relayed_to_cover.is_empty());
    timeout(Duration::from_secs(2), new_task).await???;

    // 5. Meanwhile, `alice_open` (already authenticated before deletion) completes its download!
    let mut bytes = fixture("init")?;
    bytes.extend_from_slice(&fixture("payload")?);
    alice_open.write_all(&wire::record(0x17, &bytes)?).await?;
    alice_open.shutdown().await?;
    let mut reply = Vec::new();
    while reply.len() < DC_REPLY.len() {
        let (kind, part) = read_record(&mut alice_open).await?;
        assert_eq!(kind, 0x17);
        reply.extend_from_slice(&part);
    }
    assert_eq!(reply, fixture("reply")?);
    timeout(Duration::from_secs(2), alice_task).await???;
    timeout(Duration::from_secs(2), dc_task).await???;

    let _ = stop_tx.send(());
    let _ = reload_task.await;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[tokio::test]
async fn ordered_egress_cooldown_8_parallel_skip_primary_and_single_probe_recovers() -> Result<()> {
    let cover = cover_mock().await?;
    let token = [0x5au8; 16];

    // Primary egress: controllable mode (0 = fail by closing before ACK, 1 = healthy relay to DC).
    let primary_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let primary_mode = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let primary_listener = TcpListener::bind("127.0.0.1:0").await?;
    let primary_addr = primary_listener.local_addr()?;
    let primary_hits_clone = primary_hits.clone();
    let primary_mode_clone = primary_mode.clone();
    let primary_task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = primary_listener.accept().await {
            primary_hits_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mode = primary_mode_clone.load(std::sync::atomic::Ordering::SeqCst);
            tokio::spawn(async move {
                if mode == 0 {
                    // Fail immediately before ACK (node failure).
                    let _ = stream.shutdown().await;
                    return;
                }
                let mut preface = [0u8; 88];
                if stream.read_exact(&mut preface).await.is_ok() {
                    let dc_req = i16::from_le_bytes([preface[4], preface[5]]).abs();
                    if mode == 2 && dc_req == 2 {
                        let _ = stream.write_all(&[EGRESS_ACK_ERR]).await;
                    } else {
                        let _ = stream.write_all(&[EGRESS_ACK_OK]).await;
                    }
                }
            });
        }
    });

    // Backup egress: always healthy (accepts MTV2 preface and replies EGRESS_ACK_OK).
    let backup_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let backup_listener = TcpListener::bind("127.0.0.1:0").await?;
    let backup_addr = backup_listener.local_addr()?;
    let backup_hits_clone = backup_hits.clone();
    let backup_task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = backup_listener.accept().await {
            backup_hits_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::spawn(async move {
                let mut preface = [0u8; 88];
                if stream.read_exact(&mut preface).await.is_ok() {
                    let _ = stream.write_all(&[EGRESS_ACK_OK]).await;
                }
            });
        }
    });

    let mut cfg = state(cover.addr, "127.0.0.1:1".parse()?);
    {
        let sm = Arc::get_mut(&mut cfg).context("unique state")?;
        sm.dcs.clear();
        sm.egress_upstreams = vec![primary_addr.into(), backup_addr.into()];
        sm.egress_strategy = EgressStrategy::Ordered;
        sm.egress_token = token;
        sm.egress_health = std::sync::Mutex::new(EgressHealth::new(2));
        sm.egress_cooldown = Duration::from_millis(250);
        sm.egress_cooldown_max = Duration::from_millis(250);
        sm.handshake = Duration::from_secs(2);
    }

    // 1. First connection hits failing primary (primary_hits: 1) and fails over to backup (backup_hits: 1).
    let hdr = [0u8; 64];
    let (_s1, route1) = connect_upstream(&cfg, 2, &hdr).await?;
    assert_eq!(route1, "egress");
    assert_eq!(primary_hits.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(backup_hits.load(std::sync::atomic::Ordering::SeqCst), 1);

    // 2. While primary is in cooldown, 8 parallel connections MUST all go through backup
    //    with ZERO connection attempts to primary!
    let mut join_set = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let st = cfg.clone();
        join_set.spawn(async move { connect_upstream(&st, 2, &[0u8; 64]).await });
    }
    while let Some(res) = join_set.join_next().await {
        let (_s, route) = res??;
        assert_eq!(route, "egress");
    }
    assert_eq!(
        primary_hits.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "primary must receive 0 attempts during active cooldown"
    );
    assert_eq!(backup_hits.load(std::sync::atomic::Ordering::SeqCst), 9);

    // 3. After cooldown expires, restore primary to healthy and verify single probe recovers primary.
    tokio::time::sleep(Duration::from_millis(400)).await;
    primary_mode.store(1, std::sync::atomic::Ordering::SeqCst);
    let (_s2, _route2) = connect_upstream(&cfg, 2, &hdr).await?;
    assert_eq!(primary_hits.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(backup_hits.load(std::sync::atomic::Ordering::SeqCst), 9);

    // 4. DC-specific negative ACK (mode 2: DC 2 returns EGRESS_ACK_ERR, DC 4 returns EGRESS_ACK_OK):
    //    DC 2 fails over to backup and enters DC-specific cooldown on primary, while DC 4 still uses primary!
    primary_mode.store(2, std::sync::atomic::Ordering::SeqCst);
    let (_s3, _) = connect_upstream(&cfg, 2, &hdr).await?;
    assert_eq!(primary_hits.load(std::sync::atomic::Ordering::SeqCst), 3);
    assert_eq!(backup_hits.load(std::sync::atomic::Ordering::SeqCst), 10);

    // Next DC 2 request during cooldown skips primary completely:
    let (_s4, _) = connect_upstream(&cfg, 2, &hdr).await?;
    assert_eq!(primary_hits.load(std::sync::atomic::Ordering::SeqCst), 3);
    assert_eq!(backup_hits.load(std::sync::atomic::Ordering::SeqCst), 11);

    // Meanwhile DC 4 request is NOT in cooldown on primary and succeeds on primary:
    let (_s5, _) = connect_upstream(&cfg, 4, &hdr).await?;
    assert_eq!(primary_hits.load(std::sync::atomic::Ordering::SeqCst), 4);
    assert_eq!(backup_hits.load(std::sync::atomic::Ordering::SeqCst), 11);

    primary_task.abort();
    backup_task.abort();
    Ok(())
}

#[tokio::test]
async fn runtime_stats_file_tracks_edge_and_egress_byte_counters() -> Result<()> {
    let cover = cover_mock().await?;
    let dc = TcpListener::bind("127.0.0.1:0").await?;
    let dc_addr = dc.local_addr()?;
    let token = [0x77u8; 16];

    let egress_listener = TcpListener::bind("127.0.0.1:0").await?;
    let egress_addr = egress_listener.local_addr()?;
    let egress_counters = Arc::new(telemetry::Counters::default());
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let egress_task = tokio::spawn(serve_egress(
        egress_listener,
        Arc::new(HashMap::from([(2, dc_addr)])),
        token,
        8,
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::from_millis(50),
        egress_counters.clone(),
        async move {
            let _ = shutdown_rx.await;
        },
    ));

    let mut edge_state = state(cover.addr, "127.0.0.1:1".parse()?);
    {
        let sm = Arc::get_mut(&mut edge_state).context("unique state")?;
        sm.dcs.clear();
        sm.egress_upstreams = vec![egress_addr.into()];
        sm.egress_strategy = EgressStrategy::Ordered;
        sm.egress_token = token;
        sm.handshake = Duration::from_secs(1);
    }

    let dc_task = tokio::spawn(async move {
        let (mut peer, _) = dc.accept().await?;
        let mut header = [0u8; 64];
        peer.read_exact(&mut header).await?;
        let mut decode = AesCtr::new_from_slices(&header[8..40], &header[40..56])?;
        let mut plain = header;
        wire::crypt(&mut decode, &mut plain);
        let mut payload = vec![0; CLIENT_PAYLOAD.len()];
        peer.read_exact(&mut payload).await?;
        wire::crypt(&mut decode, &mut payload);
        assert_eq!(payload, CLIENT_PAYLOAD);
        let reversed: Vec<_> = header[8..56].iter().rev().copied().collect();
        let mut encode = AesCtr::new_from_slices(&reversed[..32], &reversed[32..])?;
        let mut reply = DC_REPLY.to_vec();
        wire::crypt(&mut encode, &mut reply);
        peer.write_all(&reply).await?;
        peer.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    });

    let (mut client, task) = proxy(edge_state.clone()).await?;
    let raw = hello()?;
    client.write_all(&raw).await?;
    flight(&mut client, &raw).await?;
    let mut bytes = fixture("init")?;
    bytes.extend_from_slice(&fixture("payload")?);
    client.write_all(&wire::record(0x17, &bytes)?).await?;
    client.shutdown().await?;
    let mut reply = Vec::new();
    while reply.len() < DC_REPLY.len() {
        let (kind, part) = read_record(&mut client).await?;
        assert_eq!(kind, 0x17);
        reply.extend_from_slice(&part);
    }
    assert_eq!(reply, fixture("reply")?);
    timeout(Duration::from_secs(2), task).await???;
    timeout(Duration::from_secs(2), dc_task).await???;

    let edge_snap = edge_state.counters.snapshot_json("edge");
    assert_eq!(edge_snap["completed_sessions"].as_u64(), Some(1));
    assert_eq!(edge_snap["failed_sessions"].as_u64(), Some(0));
    assert!(
        edge_snap["downstream_rx_bytes"].as_u64().unwrap_or(0) > (raw.len() + bytes.len()) as u64
    );
    assert!(edge_snap["downstream_tx_bytes"].as_u64().unwrap_or(0) > DC_REPLY.len() as u64);
    assert_eq!(
        edge_snap["upstream_tx_bytes"].as_u64(),
        Some((88 + CLIENT_PAYLOAD.len()) as u64)
    );
    assert_eq!(
        edge_snap["upstream_rx_bytes"].as_u64(),
        Some((1 + DC_REPLY.len()) as u64)
    );

    let dir = std::env::temp_dir().join(format!("mtevil-stats-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let stats_file = dir.join("runtime-stats.json");
    write_runtime_stats_atomic(&stats_file, &edge_state.counters, "edge", None)?;
    let parsed: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&stats_file)?)?;
    assert_eq!(parsed["role"].as_str(), Some("edge"));
    assert_eq!(
        parsed["upstream_tx_bytes"].as_u64(),
        Some((88 + CLIENT_PAYLOAD.len()) as u64)
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = shutdown_tx.send(());
    timeout(Duration::from_secs(2), egress_task).await???;
    Ok(())
}

#[tokio::test]
async fn probe_telegram_e2e_verifies_handshake_and_res_pq_reply() -> Result<()> {
    let cover = cover_mock().await?;
    let dc = TcpListener::bind("127.0.0.1:0").await?;
    let dc_addr = dc.local_addr()?;

    // Mock Telegram DC responding to req_pq_multi#be7e8ef1 with resPQ#05162463 echoing nonce.
    let dc_task = tokio::spawn(async move {
        let (mut peer, _) = dc.accept().await?;
        let mut header = [0u8; 64];
        peer.read_exact(&mut header).await?;
        let mut decode = AesCtr::new_from_slices(&header[8..40], &header[40..56])?;
        let mut plain = header;
        wire::crypt(&mut decode, &mut plain);
        let mut len_buf = [0u8; 4];
        peer.read_exact(&mut len_buf).await?;
        wire::crypt(&mut decode, &mut len_buf);
        let req_len = (u32::from_le_bytes(len_buf) & 0x7fff_ffff) as usize;
        assert_eq!(req_len, 40);
        let mut req_payload = vec![0u8; req_len];
        peer.read_exact(&mut req_payload).await?;
        wire::crypt(&mut decode, &mut req_payload);
        assert_eq!(&req_payload[20..24], &[0xf1, 0x8e, 0x7e, 0xbe]);
        let nonce: [u8; 16] = req_payload[24..40].try_into()?;

        let reversed: Vec<_> = header[8..56].iter().rev().copied().collect();
        let mut encode = AesCtr::new_from_slices(&reversed[..32], &reversed[32..])?;
        let mut resp = Vec::with_capacity(44);
        resp.extend_from_slice(&40u32.to_le_bytes());
        resp.extend_from_slice(&0u64.to_le_bytes()); // auth_key_id = 0
        resp.extend_from_slice(&1u64.to_le_bytes()); // msg_id
        resp.extend_from_slice(&20u32.to_le_bytes()); // msg_len
        resp.extend_from_slice(&[0x63, 0x24, 0x16, 0x05]); // resPQ#05162463
        resp.extend_from_slice(&nonce);
        wire::crypt(&mut encode, &mut resp);
        peer.write_all(&resp).await?;
        peer.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    });

    let proxy_state = state(cover.addr, dc_addr);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_addr = listener.local_addr()?;
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let srv_task = tokio::spawn(serve(listener, proxy_state, 8, async move {
        let _ = stop_rx.await;
    }));

    let dir = std::env::temp_dir().join(format!(
        "mtevil-probe-e2e-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    std::fs::create_dir_all(&dir)?;
    let sec_path = dir.join("proxy-secret");
    std::fs::write(&sec_path, format!("{}\n", hex::encode(secret())))?;

    let cfg = Config {
        role: Role::Direct,
        listen: proxy_addr,
        secret_file: Some(sec_path),
        users_file: None,
        replay_file: None,
        sni: "example.com".into(),
        cover: cover.addr.to_string(),
        enable_dd: false,
        proxy_protocol: false,
        proxy_protocol_allow_from: Vec::new(),
        dc: vec![format!("2={dc_addr}")],
        egress_upstreams: Vec::new(),
        egress_strategy: EgressStrategy::RoundRobin,
        egress_token_file: None,
        egress_ws_path: None,
        egress_ws_pool_size: 4,
        egress_tls_ca_file: None,
        max_connections: 16,
        client_hello_timeout_secs: 2,
        handshake_timeout_secs: 2,
        idle_timeout_secs: 5,
        drain_timeout_secs: 1,
        fake_tls_cert_bytes: wire::DEFAULT_CERT_BYTES,
        fake_tls_cert_bytes_explicit: false,
        fake_tls_cert_jitter: 0,
        flight_shaping: false,
        client_mss: None,
        client_mss_bulk: None,
        alert_webhook_url: None,
        egress_cooldown_base_ms: config::default_egress_cooldown_base_ms(),
        egress_cooldown_max_ms: config::default_egress_cooldown_max_ms(),
        egress_probe_interval_secs: config::default_egress_probe_interval_secs(),
        egress_probe_degraded_interval_secs: config::default_egress_probe_degraded_interval_secs(),
        egress_hedge_ms: config::default_egress_hedge_ms(),
        egress_accept_legacy: config::default_egress_accept_legacy(),
        egress_use_mtv3: config::default_egress_use_mtv3(),
        egress_allow_from: Vec::new(),
        egress_max_failed_per_ip: config::default_egress_max_failed_per_ip(),
        egress_nonce_cache_capacity: None,
        dc_media_override: config::default_dc_media_override(),
        dc_probe_interval_secs: config::default_dc_probe_interval_secs(),
        cover_dns_ttl_secs: config::default_cover_dns_ttl_secs(),
        diagnostics: false,
        metrics_listen: None,
        me: config::MeConfig::default(),
    };

    let rtt_ms = probe_telegram_e2e(&cfg, proxy_addr, 2, Duration::from_secs(3)).await?;
    assert!(rtt_ms < 3000);

    let _ = stop_tx.send(());
    timeout(Duration::from_secs(2), srv_task).await???;
    timeout(Duration::from_secs(2), dc_task).await???;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn alert_webhook_requires_a_success_response() -> Result<()> {
    use std::io::{BufRead, BufReader, Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let url = format!("http://{}/alerts", listener.local_addr()?);
    let server = std::thread::spawn(move || -> std::io::Result<()> {
        for status in ["503 Unavailable", "204 No Content"] {
            let (mut stream, _) = listener.accept()?;
            stream.set_read_timeout(Some(Duration::from_secs(3)))?;
            let mut reader = BufReader::new(&mut stream);
            let mut line = String::new();
            loop {
                line.clear();
                if reader.read_line(&mut line)? == 0 || line == "\r\n" {
                    break;
                }
            }
            let mut body = [0; 2];
            reader.read_exact(&mut body)?;
            assert_eq!(&body, b"{}");
            write!(stream, "HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n")?;
        }
        Ok(())
    });
    assert!(send_http_alert_webhook(&url, "{}").is_err());
    send_http_alert_webhook(&url, "{}")?;
    server
        .join()
        .map_err(|_| anyhow::anyhow!("webhook server panicked"))??;
    Ok(())
}

#[tokio::test]
async fn background_egress_alerts_without_client_traffic() -> Result<()> {
    let primary = TcpListener::bind("127.0.0.1:0").await?;
    let primary_addr = primary.local_addr()?;
    let backup = TcpListener::bind("127.0.0.1:0").await?;
    let backup_addr = backup.local_addr()?;
    let primary_up = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = primary_up.clone();
    let primary_task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = primary.accept().await {
            let mut preface = [0; 88];
            if stream.read_exact(&mut preface).await.is_ok() {
                let ack = if flag.load(std::sync::atomic::Ordering::Relaxed) {
                    EGRESS_ACK_OK
                } else {
                    EGRESS_ACK_ERR
                };
                let _ = stream.write_all(&[ack]).await;
            }
        }
    });
    let backup_task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = backup.accept().await {
            let mut preface = [0; 88];
            if stream.read_exact(&mut preface).await.is_ok() {
                let _ = stream.write_all(&[EGRESS_ACK_OK]).await;
            }
        }
    });

    let mut cfg = state(primary_addr, backup_addr);
    let inner = Arc::get_mut(&mut cfg).context("unique state")?;
    inner.egress_upstreams = vec![primary_addr.into(), backup_addr.into()];
    inner.egress_strategy = EgressStrategy::Ordered;
    inner.egress_health = std::sync::Mutex::new(EgressHealth::new(2));
    let monitor = tokio::spawn(monitor_edge_egress(cfg.clone(), Duration::from_millis(25)));

    let wait_for_route = |expected| {
        let cfg = cfg.clone();
        async move {
            timeout(Duration::from_secs(2), async {
                loop {
                    if cfg
                        .egress_health
                        .lock()
                        .map(|health| health.route_state)
                        .ok()
                        == Some(expected)
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
        }
    };
    wait_for_route(EdgeRouteState::FailoverBackup(1)).await?;
    primary_up.store(true, std::sync::atomic::Ordering::Relaxed);
    wait_for_route(EdgeRouteState::PrimaryOk).await?;

    for task in [monitor, primary_task, backup_task] {
        task.abort();
    }
    Ok(())
}

#[tokio::test]
async fn edge_route_alerts_emit_once_per_state_transition() -> Result<()> {
    let cover = cover_mock().await?;
    let token = [0x99u8; 16];

    let primary_up = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let backup_up = Arc::new(std::sync::atomic::AtomicBool::new(true));

    let make_egress = |flag: Arc<std::sync::atomic::AtomicBool>| async move {
        let l = TcpListener::bind("127.0.0.1:0").await?;
        let addr = l.local_addr()?;
        let task = tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                if !flag.load(std::sync::atomic::Ordering::SeqCst) {
                    let _ = s.shutdown().await;
                    continue;
                }
                tokio::spawn(async move {
                    let mut buf = [0u8; 88];
                    if s.read_exact(&mut buf).await.is_ok() {
                        let _ = s.write_all(&[EGRESS_ACK_OK]).await;
                    }
                });
            }
        });
        Ok::<_, anyhow::Error>((addr, task))
    };

    let (primary_addr, p_task) = make_egress(primary_up.clone()).await?;
    let (backup_addr, b_task) = make_egress(backup_up.clone()).await?;

    let dir = std::env::temp_dir().join(format!(
        "mtevil-edge-alerts-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    std::fs::create_dir_all(&dir)?;
    let alerts_path = dir.join("edge-alerts.jsonl");

    let mut cfg = state(cover.addr, "127.0.0.1:1".parse()?);
    {
        let sm = Arc::get_mut(&mut cfg).context("unique state")?;
        sm.dcs.clear();
        sm.egress_upstreams = vec![primary_addr.into(), backup_addr.into()];
        sm.egress_strategy = EgressStrategy::Ordered;
        sm.egress_token = token;
        sm.egress_health = std::sync::Mutex::new(EgressHealth::new(2));
        sm.egress_cooldown = Duration::from_millis(80);
        sm.egress_cooldown_max = Duration::from_millis(160);
        sm.handshake = Duration::from_secs(2);
        sm.alerts_file = Some(alerts_path.clone());
    }

    let hdr = [0u8; 64];
    // 1. Primary down, backup up -> 3 consecutive connections must emit ONLY ONE failover_backup alert.
    for _ in 0..3 {
        let (_s, _) = connect_upstream(&cfg, 2, &hdr).await?;
    }
    // 2. Both down -> 2 consecutive failures must emit ONLY ONE all_down alert.
    backup_up.store(false, std::sync::atomic::Ordering::SeqCst);
    for _ in 0..2 {
        assert!(connect_upstream(&cfg, 2, &hdr).await.is_err());
    }
    // 3. Wait for cooldown, primary recovers -> 2 consecutive connections must emit ONLY ONE primary_ok alert.
    tokio::time::sleep(Duration::from_millis(250)).await;
    primary_up.store(true, std::sync::atomic::Ordering::SeqCst);
    for _ in 0..2 {
        let (_s, _) = connect_upstream(&cfg, 2, &hdr).await?;
    }

    let lines: Vec<serde_json::Value> = std::fs::read_to_string(&alerts_path)?
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let states: Vec<&str> = lines.iter().filter_map(|v| v["state"].as_str()).collect();
    assert_eq!(states, vec!["failover_backup", "all_down", "primary_ok"]);

    p_task.abort();
    b_task.abort();
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[tokio::test]
async fn edge_round_robin_alerts_ignore_healthy_alternation_and_track_availability() -> Result<()> {
    let cover = cover_mock().await?;
    let token = [0x88u8; 16];

    let node1_up = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let node2_up = Arc::new(std::sync::atomic::AtomicBool::new(true));

    let make_egress = |flag: Arc<std::sync::atomic::AtomicBool>| async move {
        let l = TcpListener::bind("127.0.0.1:0").await?;
        let addr = l.local_addr()?;
        let task = tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                if !flag.load(std::sync::atomic::Ordering::SeqCst) {
                    let _ = s.shutdown().await;
                    continue;
                }
                tokio::spawn(async move {
                    let mut buf = [0u8; 88];
                    if s.read_exact(&mut buf).await.is_ok() {
                        let _ = s.write_all(&[EGRESS_ACK_OK]).await;
                    }
                });
            }
        });
        Ok::<_, anyhow::Error>((addr, task))
    };

    let (addr1, t1) = make_egress(node1_up.clone()).await?;
    let (addr2, t2) = make_egress(node2_up.clone()).await?;

    let dir = std::env::temp_dir().join(format!(
        "mtevil-rr-alerts-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    std::fs::create_dir_all(&dir)?;
    let alerts_path = dir.join("edge-alerts.jsonl");

    let mut cfg = state(cover.addr, "127.0.0.1:1".parse()?);
    {
        let sm = Arc::get_mut(&mut cfg).context("unique state")?;
        sm.dcs.clear();
        sm.egress_upstreams = vec![addr1.into(), addr2.into()];
        sm.egress_strategy = EgressStrategy::RoundRobin;
        sm.egress_token = token;
        sm.egress_health = std::sync::Mutex::new(EgressHealth::new(2));
        sm.egress_cooldown = Duration::from_millis(80);
        sm.egress_cooldown_max = Duration::from_millis(80);
        sm.handshake = Duration::from_secs(2);
        sm.alerts_file = Some(alerts_path.clone());
    }

    let hdr = [0u8; 64];
    // 1. Healthy alternation across 6 connections must emit ZERO alerts!
    for _ in 0..6 {
        let (_s, _) = connect_upstream(&cfg, 2, &hdr).await?;
    }
    assert!(
        !alerts_path.exists(),
        "healthy round-robin alternation must not emit any alerts"
    );

    // 2. Genuine failure of node 2 while node 1 stays healthy -> emits exactly ONE degraded alert.
    node2_up.store(false, std::sync::atomic::Ordering::SeqCst);
    for _ in 0..4 {
        let (_s, _) = connect_upstream(&cfg, 2, &hdr).await?;
    }

    // 3. Both nodes down -> emits exactly ONE all_down alert.
    node1_up.store(false, std::sync::atomic::Ordering::SeqCst);
    for _ in 0..2 {
        assert!(connect_upstream(&cfg, 2, &hdr).await.is_err());
    }

    // 4. Both nodes recover after cooldown -> after both nodes handle traffic, emits primary_ok (all recovered).
    tokio::time::sleep(Duration::from_millis(130)).await;
    node1_up.store(true, std::sync::atomic::Ordering::SeqCst);
    node2_up.store(true, std::sync::atomic::Ordering::SeqCst);
    for _ in 0..4 {
        let (_s, _) = connect_upstream(&cfg, 2, &hdr).await?;
    }

    let lines: Vec<serde_json::Value> = std::fs::read_to_string(&alerts_path)?
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let states: Vec<&str> = lines.iter().filter_map(|v| v["state"].as_str()).collect();
    assert_eq!(
        states,
        vec!["degraded", "all_down", "degraded", "primary_ok"]
    );

    t1.abort();
    t2.abort();
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[tokio::test]
async fn media_dc_negative_ids_route_to_dedicated_address_with_fallback_and_zero_dc_ping_skips_dc(
) -> Result<()> {
    let main_dc2 = TcpListener::bind("127.0.0.1:0").await?;
    let main_dc2_addr = main_dc2.local_addr()?;
    let media_dc2 = TcpListener::bind("127.0.0.1:0").await?;
    let media_dc2_addr = media_dc2.local_addr()?;
    let main_dc4 = TcpListener::bind("127.0.0.1:0").await?;
    let main_dc4_addr = main_dc4.local_addr()?;

    let mut dcs = HashMap::new();
    dcs.insert(2, main_dc2_addr);
    dcs.insert(-2, media_dc2_addr);
    dcs.insert(4, main_dc4_addr);

    // 1. lookup_dc_addr routes -2 to dedicated media DC, 2 to main DC, and -4 falls back to 4.
    assert_eq!(lookup_dc_addr(&dcs, -2), Some(media_dc2_addr));
    assert_eq!(lookup_dc_addr(&dcs, 2), Some(main_dc2_addr));
    assert_eq!(lookup_dc_addr(&dcs, -4), Some(main_dc4_addr));

    // 2. Real egress server handles dc_id=0 MTV2 health probe with EGRESS_ACK_OK WITHOUT dialing Telegram DC.
    let token = [0x55u8; 16];
    let egress_listener = TcpListener::bind("127.0.0.1:0").await?;
    let egress_addr = egress_listener.local_addr()?;
    let counters = Arc::new(telemetry::Counters::default());
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let egress_task = tokio::spawn(serve_egress(
        egress_listener,
        Arc::new(dcs),
        token,
        16,
        Duration::from_secs(2),
        Duration::from_secs(5),
        Duration::from_secs(1),
        counters,
        async {
            let _ = stop_rx.await;
        },
    ));

    let probe = probe_egress_endpoint(egress_addr, 0, &token, Duration::from_secs(2)).await;
    assert!(probe.tcp_reachable);
    assert_eq!(probe.token_status, "accepted");
    assert!(probe.dc_reachable);

    // Verify no connection was made to main_dc2 or media_dc2 during dc_id=0 probe.
    assert!(
        timeout(Duration::from_millis(40), main_dc2.accept())
            .await
            .is_err(),
        "dc_id=0 ping must not dial Telegram DC"
    );

    let _ = stop_tx.send(());
    let _ = egress_task.await;
    Ok(())
}

#[tokio::test]
async fn allowed_sni_file_accepts_previous_and_current_sni_without_breaking_links() -> Result<()> {
    let cover = cover_mock().await?;
    let dc = TcpListener::bind("127.0.0.1:0").await?;
    let dc_addr = dc.local_addr()?;

    let dir = std::env::temp_dir().join(format!(
        "mtevil-allowed-sni-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    std::fs::create_dir_all(&dir)?;
    let sec_path = dir.join("proxy-secret");
    std::fs::write(&sec_path, format!("{}\n", hex::encode(secret())))?;
    let allowed_path = dir.join("allowed-sni.txt");
    std::fs::write(&allowed_path, "example.com\nvk.com\n")?;

    let cfg = Config {
        role: Role::Direct,
        listen: "127.0.0.1:24443".parse()?,
        secret_file: Some(sec_path),
        users_file: None,
        replay_file: None,
        sni: "ya.ru".into(),
        cover: cover.addr.to_string(),
        enable_dd: false,
        proxy_protocol: false,
        proxy_protocol_allow_from: Vec::new(),
        dc: vec![format!("2={dc_addr}")],
        egress_upstreams: Vec::new(),
        egress_strategy: EgressStrategy::RoundRobin,
        egress_token_file: None,
        egress_ws_path: None,
        egress_ws_pool_size: 4,
        egress_tls_ca_file: None,
        max_connections: 16,
        client_hello_timeout_secs: 2,
        handshake_timeout_secs: 2,
        idle_timeout_secs: 5,
        drain_timeout_secs: 1,
        fake_tls_cert_bytes: wire::DEFAULT_CERT_BYTES,
        fake_tls_cert_bytes_explicit: false,
        fake_tls_cert_jitter: 0,
        flight_shaping: false,
        client_mss: None,
        client_mss_bulk: None,
        alert_webhook_url: None,
        egress_cooldown_base_ms: config::default_egress_cooldown_base_ms(),
        egress_cooldown_max_ms: config::default_egress_cooldown_max_ms(),
        egress_probe_interval_secs: config::default_egress_probe_interval_secs(),
        egress_probe_degraded_interval_secs: config::default_egress_probe_degraded_interval_secs(),
        egress_hedge_ms: config::default_egress_hedge_ms(),
        egress_accept_legacy: config::default_egress_accept_legacy(),
        egress_use_mtv3: config::default_egress_use_mtv3(),
        egress_allow_from: Vec::new(),
        egress_max_failed_per_ip: config::default_egress_max_failed_per_ip(),
        egress_nonce_cache_capacity: None,
        dc_media_override: config::default_dc_media_override(),
        dc_probe_interval_secs: config::default_dc_probe_interval_secs(),
        cover_dns_ttl_secs: config::default_cover_dns_ttl_secs(),
        diagnostics: false,
        metrics_listen: None,
        me: config::MeConfig::default(),
    };
    assert_eq!(cfg.allowed_snis(), "ya.ru,example.com,vk.com");

    let mut proxy_state = state(cover.addr, dc_addr);
    {
        let sm = Arc::get_mut(&mut proxy_state).context("unique state")?;
        sm.sni = "ya.ru".into();
        sm.allowed_snis = std::sync::RwLock::new(Arc::new(cfg.allowed_snis()));
    }

    // Client connecting with old SNI "example.com" still authenticates even though primary sni is "ya.ru".
    let (mut client, task) = proxy(proxy_state.clone()).await?;
    let raw = hello()?;
    client.write_all(&raw).await?;
    flight(&mut client, &raw).await?;
    client.shutdown().await?;
    assert!(timeout(Duration::from_secs(1), task).await??.is_err());

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[tokio::test]
async fn dc_candidates_fail_over_when_first_candidate_unreachable() -> Result<()> {
    let dead_addr = closed_port().await?;
    let live_dc = TcpListener::bind("127.0.0.1:0").await?;
    let live_addr = live_dc.local_addr()?;

    let dc_task = tokio::spawn(async move {
        let (_peer, _) = live_dc.accept().await?;
        Ok::<_, anyhow::Error>(())
    });

    let stream = connect_dc_candidates(&[dead_addr, live_addr], Duration::from_secs(2)).await?;
    assert_eq!(stream.peer_addr()?, live_addr);
    timeout(Duration::from_secs(1), dc_task).await???;

    let mut std_dcs = HashMap::new();
    std_dcs.insert(2, SocketAddr::from(([149, 154, 167, 51], 443)));
    std_dcs.insert(4, SocketAddr::from(([149, 154, 167, 91], 443)));
    let c_neg2_0 = lookup_dc_candidates(&std_dcs, -2, 0);
    let c_neg2_1 = lookup_dc_candidates(&std_dcs, -2, 1);
    assert_eq!(c_neg2_0.len(), 3);
    assert_eq!(c_neg2_0[0], SocketAddr::from(([149, 154, 167, 151], 443)));
    assert_eq!(c_neg2_1[0], SocketAddr::from(([149, 154, 167, 220], 443)));
    let c_pos2 = lookup_dc_candidates(&std_dcs, 2, 0);
    assert_eq!(
        c_pos2,
        vec![
            SocketAddr::from(([149, 154, 167, 51], 443)),
            SocketAddr::from(([149, 154, 167, 220], 443)),
        ]
    );
    Ok(())
}

struct FaultInjectingAcceptor {
    inner: TcpListener,
    injected: std::collections::VecDeque<std::io::Error>,
}

impl Acceptor for FaultInjectingAcceptor {
    async fn accept_conn(&mut self) -> std::io::Result<(TcpStream, SocketAddr)> {
        if let Some(err) = self.injected.pop_front() {
            return Err(err);
        }
        self.inner.accept().await
    }
}

#[tokio::test]
async fn accept_loop_survives_emfile_and_econnaborted_bursts_and_shuts_down_cleanly() -> Result<()>
{
    use std::collections::VecDeque;
    use std::sync::atomic::Ordering::Relaxed;

    // 1. Direct/Edge serve() survives a series of EMFILE, ENFILE, ENOBUFS, ENOMEM, and ECONNABORTED
    let mut cover = cover_mock().await?;
    let proxy_state = state(cover.addr, closed_port().await?);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_addr = listener.local_addr()?;

    let mut injected = VecDeque::new();
    injected.push_back(std::io::Error::new(
        std::io::ErrorKind::ConnectionAborted,
        "peer aborted before accept",
    ));
    injected.push_back(std::io::Error::new(
        std::io::ErrorKind::ConnectionReset,
        "peer reset",
    ));
    injected.push_back(std::io::Error::new(
        std::io::ErrorKind::Interrupted,
        "eintr",
    ));
    injected.push_back(std::io::Error::new(
        std::io::ErrorKind::WouldBlock,
        "eagain",
    ));
    // Burst of 3 EMFILE + 1 ENFILE + 1 ENOBUFS + 1 ENOMEM
    injected.push_back(std::io::Error::from_raw_os_error(24)); // EMFILE
    injected.push_back(std::io::Error::from_raw_os_error(24)); // EMFILE
    injected.push_back(std::io::Error::from_raw_os_error(24)); // EMFILE
    injected.push_back(std::io::Error::from_raw_os_error(23)); // ENFILE
    injected.push_back(std::io::Error::from_raw_os_error(105)); // ENOBUFS
    injected.push_back(std::io::Error::from_raw_os_error(12)); // ENOMEM

    let acceptor = FaultInjectingAcceptor {
        inner: listener,
        injected,
    };
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let srv_state = proxy_state.clone();
    let srv_task = tokio::spawn(serve(acceptor, srv_state, 8, async move {
        let _ = stop_rx.await;
    }));

    // Real client connection must succeed after the error burst is absorbed!
    let mut client = TcpStream::connect(proxy_addr).await?;
    client.write_all(b"GET / HTTP/1.1\r\n\r\n").await?;
    client.shutdown().await?;
    let mut reply = Vec::new();
    timeout(Duration::from_secs(2), client.read_to_end(&mut reply)).await??;
    assert_eq!(reply, COVER_REPLY);
    let _ = timeout(Duration::from_secs(1), cover.received.recv()).await?;

    // Verify per-kind accept_errors counters recorded every injected error.
    let ae = &proxy_state.counters.accept_errors;
    assert_eq!(ae.connection_aborted.load(Relaxed), 1);
    assert_eq!(ae.connection_reset.load(Relaxed), 1);
    assert_eq!(ae.interrupted.load(Relaxed), 1);
    assert_eq!(ae.would_block.load(Relaxed), 1);
    assert_eq!(ae.emfile.load(Relaxed), 3);
    assert_eq!(ae.enfile.load(Relaxed), 1);
    assert_eq!(ae.enobufs.load(Relaxed), 1);
    assert_eq!(ae.enomem.load(Relaxed), 1);
    assert_eq!(ae.fatal.load(Relaxed), 0);
    assert_eq!(ae.total(), 10);

    // Shutdown still works cleanly.
    let _ = stop_tx.send(());
    timeout(Duration::from_secs(2), srv_task).await???;

    // 2. serve_egress() also survives EMFILE + ECONNABORTED and continues serving MTV2 health probes.
    let egress_listener = TcpListener::bind("127.0.0.1:0").await?;
    let egress_addr = egress_listener.local_addr()?;
    let egress_counters = Arc::new(telemetry::Counters::default());
    let token = [0x42u8; 16];
    let mut eg_injected = VecDeque::new();
    eg_injected.push_back(std::io::Error::new(
        std::io::ErrorKind::ConnectionAborted,
        "aborted",
    ));
    eg_injected.push_back(std::io::Error::from_raw_os_error(24)); // EMFILE
    let eg_acceptor = FaultInjectingAcceptor {
        inner: egress_listener,
        injected: eg_injected,
    };
    let (eg_stop_tx, eg_stop_rx) = tokio::sync::oneshot::channel::<()>();
    let eg_task = tokio::spawn(serve_egress(
        eg_acceptor,
        Arc::new(HashMap::from([(2, closed_port().await?)])),
        token,
        8,
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::from_millis(50),
        egress_counters.clone(),
        async move {
            let _ = eg_stop_rx.await;
        },
    ));

    let probe = probe_egress_endpoint(egress_addr, 0, &token, Duration::from_secs(2)).await;
    assert!(probe.dc_reachable);
    assert_eq!(egress_counters.accept_errors.emfile.load(Relaxed), 1);
    assert_eq!(
        egress_counters
            .accept_errors
            .connection_aborted
            .load(Relaxed),
        1
    );
    let _ = eg_stop_tx.send(());
    timeout(Duration::from_secs(2), eg_task).await???;

    // 3. Fatal error (EBADF = 9) terminates the listener with Err and increments fatal counter.
    let fatal_listener = TcpListener::bind("127.0.0.1:0").await?;
    let fatal_state = state(cover.addr, closed_port().await?);
    let mut fatal_injected = VecDeque::new();
    fatal_injected.push_back(std::io::Error::from_raw_os_error(9)); // EBADF
    let fatal_acceptor = FaultInjectingAcceptor {
        inner: fatal_listener,
        injected: fatal_injected,
    };
    let res = serve(
        fatal_acceptor,
        fatal_state.clone(),
        4,
        std::future::pending(),
    )
    .await;
    assert!(res.is_err());
    assert_eq!(fatal_state.counters.accept_errors.fatal.load(Relaxed), 1);
    Ok(())
}

#[test]
fn fd_budget_clamps_effective_max_connections_and_fails_fast_below_16() -> Result<()> {
    let sample_proc_limits = "\
Limit                     Soft Limit           Hard Limit           Units     
Max cpu time              unlimited            unlimited            seconds   
Max open files            4096                 4096                 files     
Max processes             128                  128                  processes 
";
    assert_eq!(
        parse_proc_self_limits_nofile(sample_proc_limits),
        Some(4096)
    );
    let unlimited_limits =
        "Max open files            unlimited            unlimited            files\n";
    assert_eq!(
        parse_proc_self_limits_nofile(unlimited_limits),
        Some(usize::MAX)
    );

    // configured 4096 with nofile 4096 -> (4096 - 128) / 2 = 1984
    assert_eq!(compute_effective_max_connections(4096, Some(4096))?, 1984);
    // configured 256 with nofile 4096 -> min(256, 1984) = 256
    assert_eq!(compute_effective_max_connections(256, Some(4096))?, 256);
    // configured 4096 with nofile 8704 (4096*2 + 512) -> min(4096, (8704-128)/2=4288) = 4096
    assert_eq!(compute_effective_max_connections(4096, Some(8704))?, 4096);
    // Boundary: nofile = 160 -> (160 - 128) / 2 = 16 -> ok
    assert_eq!(compute_effective_max_connections(256, Some(160))?, 16);
    // Below 16: nofile = 159 -> (159 - 128) / 2 = 15 -> fail-fast Err
    assert!(compute_effective_max_connections(256, Some(159)).is_err());
    // Configured < 16 -> fail-fast Err
    assert!(compute_effective_max_connections(15, Some(4096)).is_err());
    assert!(compute_effective_max_connections(15, None).is_err());
    Ok(())
}

#[tokio::test]
async fn round_robin_circuit_breaker_skips_cooldown_node_and_preserves_rr_offset() -> Result<()> {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
    let cover = cover_mock().await?;
    let token = [0x66u8; 16];

    let spawn_node = |up: Arc<AtomicBool>, hits: Arc<AtomicUsize>| async move {
        let l = TcpListener::bind("127.0.0.1:0").await?;
        let addr = l.local_addr()?;
        let task = tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                hits.fetch_add(1, SeqCst);
                if !up.load(SeqCst) {
                    let _ = s.shutdown().await;
                    continue;
                }
                tokio::spawn(async move {
                    let mut preface = [0u8; 88];
                    if s.read_exact(&mut preface).await.is_ok() {
                        let _ = s.write_all(&[EGRESS_ACK_OK]).await;
                    }
                });
            }
        });
        Ok::<_, anyhow::Error>((addr, task))
    };

    let n0_up = Arc::new(AtomicBool::new(true));
    let n1_up = Arc::new(AtomicBool::new(false)); // node 1 starts dead
    let n2_up = Arc::new(AtomicBool::new(true));
    let h0 = Arc::new(AtomicUsize::new(0));
    let h1 = Arc::new(AtomicUsize::new(0));
    let h2 = Arc::new(AtomicUsize::new(0));

    let (addr0, t0) = spawn_node(n0_up.clone(), h0.clone()).await?;
    let (addr1, t1) = spawn_node(n1_up.clone(), h1.clone()).await?;
    let (addr2, t2) = spawn_node(n2_up.clone(), h2.clone()).await?;

    let mut cfg = state(cover.addr, "127.0.0.1:1".parse()?);
    {
        let sm = Arc::get_mut(&mut cfg).context("unique state")?;
        sm.dcs.clear();
        sm.egress_upstreams = vec![addr0.into(), addr1.into(), addr2.into()];
        sm.egress_strategy = EgressStrategy::RoundRobin;
        sm.egress_token = token;
        sm.egress_health = std::sync::Mutex::new(EgressHealth::new(3));
        sm.egress_cooldown = Duration::from_millis(250);
        sm.egress_cooldown_max = Duration::from_millis(250);
        sm.handshake = Duration::from_secs(2);
    }

    let hdr = [0u8; 64];
    // Connection 0 (start=0): hits node 0 -> succeeds.
    let (_s, _) = connect_upstream(&cfg, 2, &hdr).await?;
    assert_eq!(
        (h0.load(SeqCst), h1.load(SeqCst), h2.load(SeqCst)),
        (1, 0, 0)
    );

    // Connection 1 (start=1): hits dead node 1 (h1=1), puts node 1 into cooldown,
    // and advances in RR order to node 2 (h2=1).
    let (_s, _) = connect_upstream(&cfg, 2, &hdr).await?;
    assert_eq!(
        (h0.load(SeqCst), h1.load(SeqCst), h2.load(SeqCst)),
        (1, 1, 1)
    );

    // Next 6 connections during cooldown: node 1 MUST receive 0 hits!
    // Look at RR starts:
    // start=2 -> node 2 (h2=2)
    // start=0 -> node 0 (h0=2)
    // start=1 -> skips node 1 -> node 2 (h2=3)
    // start=2 -> node 2 (h2=4)
    // start=0 -> node 0 (h0=3)
    // start=1 -> skips node 1 -> node 2 (h2=5)
    for _ in 0..6 {
        let (_s, _) = connect_upstream(&cfg, 2, &hdr).await?;
    }
    assert_eq!(
        h1.load(SeqCst),
        1,
        "dead node in cooldown must be skipped in round-robin"
    );
    assert_eq!(h0.load(SeqCst), 3);
    assert_eq!(h2.load(SeqCst), 5);

    // After cooldown expires and node 1 recovers, node 1 is probed and rejoins rotation.
    tokio::time::sleep(Duration::from_millis(350)).await;
    n1_up.store(true, SeqCst);
    for _ in 0..3 {
        let (_s, _) = connect_upstream(&cfg, 2, &hdr).await?;
    }
    assert_eq!(h1.load(SeqCst), 2);

    t0.abort();
    t1.abort();
    t2.abort();
    Ok(())
}

#[tokio::test]
async fn all_nodes_in_cooldown_fail_open_forces_soonest_probe_with_storm_protection() -> Result<()>
{
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
    let cover = cover_mock().await?;
    let token = [0x44u8; 16];

    let n0_up = Arc::new(AtomicBool::new(false));
    let n1_up = Arc::new(AtomicBool::new(false));
    let h0 = Arc::new(AtomicUsize::new(0));
    let h1 = Arc::new(AtomicUsize::new(0));

    let spawn_node = |up: Arc<AtomicBool>, hits: Arc<AtomicUsize>| async move {
        let l = TcpListener::bind("127.0.0.1:0").await?;
        let addr = l.local_addr()?;
        let task = tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                hits.fetch_add(1, SeqCst);
                if !up.load(SeqCst) {
                    let _ = s.shutdown().await;
                    continue;
                }
                tokio::spawn(async move {
                    let mut preface = [0u8; 88];
                    if s.read_exact(&mut preface).await.is_ok() {
                        let _ = s.write_all(&[EGRESS_ACK_OK]).await;
                    }
                });
            }
        });
        Ok::<_, anyhow::Error>((addr, task))
    };

    let (addr0, t0) = spawn_node(n0_up.clone(), h0.clone()).await?;
    let (addr1, t1) = spawn_node(n1_up.clone(), h1.clone()).await?;

    let mut cfg = state(cover.addr, "127.0.0.1:1".parse()?);
    {
        let sm = Arc::get_mut(&mut cfg).context("unique state")?;
        sm.dcs.clear();
        sm.egress_upstreams = vec![addr0.into(), addr1.into()];
        sm.egress_strategy = EgressStrategy::Ordered;
        sm.egress_token = token;
        sm.egress_health = std::sync::Mutex::new(EgressHealth::new(2));
        // Long 15-second cooldown to prove we do NOT wait 15s when all nodes are in cooldown!
        sm.egress_cooldown = Duration::from_secs(15);
        sm.handshake = Duration::from_secs(2);
    }

    let hdr = [0u8; 64];
    // 1. Both nodes fail -> both enter cooldown.
    assert!(connect_upstream(&cfg, 2, &hdr).await.is_err());
    assert_eq!((h0.load(SeqCst), h1.load(SeqCst)), (1, 1));
    // Set deterministic distinct expiry deadlines (node 0 expires in 10s, node 1 in 20s)
    // so try_claim_forced_soonest deterministically selects node 0 first regardless of ±20% jitter.
    {
        let now = Instant::now();
        let mut h = cfg.egress_health.lock().unwrap_or_else(|e| e.into_inner());
        h.nodes[0].until = Some(now + Duration::from_secs(10));
        h.nodes[1].until = Some(now + Duration::from_secs(20));
    }

    // 2. Verify storm protection on try_claim_forced_soonest:
    //    First claim gets node 0 (soonest expiry); second concurrent claim gets node 1;
    //    third concurrent claim gets None (at most 1 concurrent forced probe per node!).
    {
        let c1 = EgressHealth::try_claim_forced_soonest(&cfg.egress_health, 2, 2);
        let c2 = EgressHealth::try_claim_forced_soonest(&cfg.egress_health, 2, 2);
        let c3 = EgressHealth::try_claim_forced_soonest(&cfg.egress_health, 2, 2);
        assert_eq!(c1.as_ref().map(|(idx, _)| *idx), Some(0));
        assert_eq!(c2.as_ref().map(|(idx, _)| *idx), Some(1));
        assert!(
            c3.is_none(),
            "at most one concurrent forced probe per node allowed"
        );
        // Dropping c1 and c2 without completion releases probing flags cleanly.
    }

    // 3. Immediately (0ms sleep, while 15s cooldown is active!) bring node 0 back up.
    //    The next client connection MUST succeed immediately via forced probe on node 0!
    n0_up.store(true, SeqCst);
    let (_s, route) = connect_upstream(&cfg, 2, &hdr).await?;
    assert_eq!(route, "egress");
    assert_eq!(h0.load(SeqCst), 2);
    assert_eq!(h1.load(SeqCst), 1);

    t0.abort();
    t1.abort();
    Ok(())
}

#[test]
fn egress_cooldown_exponential_backoff_jitter_reset_and_node_vs_dc_separation() -> Result<()> {
    // 1. Exponential growth ×2 up to max
    assert_eq!(
        compute_egress_cooldown_unclamped_ms(3_000, 60_000, 1),
        3_000
    );
    assert_eq!(
        compute_egress_cooldown_unclamped_ms(3_000, 60_000, 2),
        6_000
    );
    assert_eq!(
        compute_egress_cooldown_unclamped_ms(3_000, 60_000, 3),
        12_000
    );
    assert_eq!(
        compute_egress_cooldown_unclamped_ms(3_000, 60_000, 4),
        24_000
    );
    assert_eq!(
        compute_egress_cooldown_unclamped_ms(3_000, 60_000, 5),
        48_000
    );
    assert_eq!(
        compute_egress_cooldown_unclamped_ms(3_000, 60_000, 6),
        60_000
    );
    assert_eq!(
        compute_egress_cooldown_unclamped_ms(3_000, 60_000, 99),
        60_000
    );

    // 2. ±20% jitter boundaries (-200..=200 permille)
    assert_eq!(apply_cooldown_jitter_ms(3_000, -200), 2_400);
    assert_eq!(apply_cooldown_jitter_ms(3_000, 0), 3_000);
    assert_eq!(apply_cooldown_jitter_ms(3_000, 200), 3_600);
    for _ in 0..64 {
        let d = compute_egress_cooldown(Duration::from_millis(3_000), Duration::from_secs(60), 1);
        assert!(
            (2_400..=3_600).contains(&(d.as_millis() as u64)),
            "jitter out of ±20% range: {d:?}"
        );
    }

    // 3. Separate failure counters for node failure vs DC failure, and reset on success.
    let health = std::sync::Mutex::new(EgressHealth::new(1));
    let base = Duration::from_millis(1_000);
    let max = Duration::from_millis(10_000);

    // First node failure -> failures = 1
    let c1 = EgressHealth::try_claim(&health, 0, 2, Instant::now()).context("claim 1")?;
    c1.record_node_failure(base, max);
    assert_eq!(
        health.lock().unwrap_or_else(|e| e.into_inner()).nodes[0].failures,
        1
    );

    // Second forced node failure -> failures = 2
    let (_, c2) =
        EgressHealth::try_claim_forced_soonest(&health, 1, 2).context("forced claim 2")?;
    c2.record_node_failure(base, max);
    assert_eq!(
        health.lock().unwrap_or_else(|e| e.into_inner()).nodes[0].failures,
        2
    );

    // DC failure on DC 2 clears node probe & node failures (since node accepted TCP+token)
    // and increments DC 2 failure counter to 1 while leaving DC 4 untouched!
    let (_, c3) =
        EgressHealth::try_claim_forced_soonest(&health, 1, 2).context("forced claim 3")?;
    c3.record_dc_failure(base, max);
    {
        let h = health.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(h.nodes[0].failures, 0);
        assert!(h.nodes[0].until.is_none());
        assert_eq!(h.dc_slots.get(&(0, 2)).map(|s| s.failures), Some(1));
        assert!(!h.dc_slots.contains_key(&(0, 4)));
    }

    // Success on DC 2 resets DC 2 failure counter to 0.
    let (_, c4) =
        EgressHealth::try_claim_forced_soonest(&health, 1, 2).context("forced claim 4")?;
    c4.record_success();
    {
        let h = health.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(h.dc_slots.get(&(0, 2)).map(|s| s.failures), Some(0));
        assert!(h.dc_slots.get(&(0, 2)).and_then(|s| s.until).is_none());
    }
    Ok(())
}

#[tokio::test]
async fn background_probe_rotates_dcs_sets_and_clears_breaker_cooldown_and_switches_interval(
) -> Result<()> {
    let primary = TcpListener::bind("127.0.0.1:0").await?;
    let primary_addr = primary.local_addr()?;
    let backup = TcpListener::bind("127.0.0.1:0").await?;
    let backup_addr = backup.local_addr()?;
    let primary_up = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seen_dcs = Arc::new(std::sync::Mutex::new(Vec::<i16>::new()));
    let flag = primary_up.clone();
    let seen_clone = seen_dcs.clone();
    let primary_task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = primary.accept().await {
            let mut preface = [0; 88];
            if stream.read_exact(&mut preface).await.is_ok() {
                let dc_id = i16::from_le_bytes([preface[4], preface[5]]);
                seen_clone
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(dc_id);
                let ack = if flag.load(std::sync::atomic::Ordering::Relaxed) {
                    EGRESS_ACK_OK
                } else {
                    EGRESS_ACK_ERR
                };
                let _ = stream.write_all(&[ack]).await;
            }
        }
    });
    let backup_task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = backup.accept().await {
            let mut preface = [0; 88];
            if stream.read_exact(&mut preface).await.is_ok() {
                let _ = stream.write_all(&[EGRESS_ACK_OK]).await;
            }
        }
    });

    let mut cfg = state(primary_addr, backup_addr);
    {
        let inner = Arc::get_mut(&mut cfg).context("unique state")?;
        inner.egress_upstreams = vec![primary_addr.into(), backup_addr.into()];
        inner.egress_strategy = EgressStrategy::Ordered;
        inner.egress_health = std::sync::Mutex::new(EgressHealth::new(2));
        // Long 30s cooldown to prove that background probe recovery clears cooldown directly!
        inner.egress_cooldown = Duration::from_secs(30);
        inner.egress_cooldown_max = Duration::from_secs(60);
        inner.egress_probe_interval = Duration::from_millis(40);
        inner.egress_probe_degraded_interval = Duration::from_millis(10);
    }

    let monitor = tokio::spawn(monitor_edge_egress(cfg.clone(), Duration::from_millis(40)));

    // 1. Wait until primary fails at least 2 background probes -> primary is placed into 30s cooldown!
    timeout(Duration::from_secs(2), async {
        loop {
            let in_cooldown = cfg
                .egress_health
                .lock()
                .map(|h| {
                    h.route_state == EdgeRouteState::FailoverBackup(1)
                        && h.nodes.first().and_then(|s| s.until).is_some()
                })
                .unwrap_or(false);
            if in_cooldown {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;

    // 2. Restore primary -> background probe (running at fast 10ms degraded interval)
    //    must clear primary's 30s cooldown automatically without any client traffic!
    primary_up.store(true, std::sync::atomic::Ordering::Relaxed);
    timeout(Duration::from_secs(2), async {
        loop {
            let recovered = cfg
                .egress_health
                .lock()
                .map(|h| {
                    h.route_state == EdgeRouteState::PrimaryOk
                        && h.nodes.first().and_then(|s| s.until).is_none()
                        && h.nodes.first().map(|s| s.failures) == Some(0)
                })
                .unwrap_or(false);
            if recovered {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;

    // 3. Verify DC rotation covered [2, 4, -2, -4].
    timeout(Duration::from_secs(2), async {
        loop {
            let len = seen_dcs.lock().unwrap_or_else(|e| e.into_inner()).len();
            if len >= 4 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    let dcs_snapshot = seen_dcs.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert_eq!(&dcs_snapshot[..4], &[2, 4, -2, -4]);

    for task in [monitor, primary_task, backup_task] {
        task.abort();
    }
    Ok(())
}

#[tokio::test]
async fn hedged_connect_starts_backup_after_hedge_ms_and_tracks_metrics() -> Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
    let cover = cover_mock().await?;
    let token = [0x51u8; 16];

    let primary_delay_ms = Arc::new(AtomicU64::new(500));
    let backup_delay_ms = Arc::new(AtomicU64::new(0));

    let spawn_delayed_egress = |delay_ms: Arc<AtomicU64>| async move {
        let l = TcpListener::bind("127.0.0.1:0").await?;
        let addr = l.local_addr()?;
        let task = tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let wait = delay_ms.load(Relaxed);
                tokio::spawn(async move {
                    let mut preface = [0u8; 88];
                    if s.read_exact(&mut preface).await.is_ok() {
                        if wait > 0 {
                            tokio::time::sleep(Duration::from_millis(wait)).await;
                        }
                        let _ = s.write_all(&[EGRESS_ACK_OK]).await;
                    }
                });
            }
        });
        Ok::<_, anyhow::Error>((addr, task))
    };

    let (primary_addr, p_task) = spawn_delayed_egress(primary_delay_ms.clone()).await?;
    let (backup_addr, b_task) = spawn_delayed_egress(backup_delay_ms.clone()).await?;

    let mut cfg = state(cover.addr, "127.0.0.1:1".parse()?);
    {
        let sm = Arc::get_mut(&mut cfg).context("unique state")?;
        sm.dcs.clear();
        sm.egress_upstreams = vec![primary_addr.into(), backup_addr.into()];
        sm.egress_strategy = EgressStrategy::Ordered;
        sm.egress_token = token;
        sm.egress_health = std::sync::Mutex::new(EgressHealth::new(2));
        sm.egress_hedge_ms = 40;
        sm.handshake = Duration::from_secs(2);
    }

    let hdr = [0u8; 64];
    // 1. Primary stalls for 500ms (> hedge_ms=40ms), backup responds in 0ms:
    //    Hedge starts after 40ms, backup wins well before 500ms!
    let t0 = Instant::now();
    let (_s1, route1) = connect_upstream(&cfg, 2, &hdr).await?;
    assert_eq!(route1, "egress");
    assert!(
        t0.elapsed() < Duration::from_millis(350),
        "hedged connect should complete via backup well before primary's 500ms delay"
    );
    assert_eq!(cfg.counters.hedge_started.load(Relaxed), 1);
    assert_eq!(cfg.counters.hedge_won_by_backup.load(Relaxed), 1);

    // Clear cooldown on primary so we can test primary winning after hedge starts.
    EgressHealth::apply_background_probe(
        &cfg.egress_health,
        0,
        2,
        BackgroundProbeOutcome::PositiveAck,
        cfg.egress_cooldown,
        cfg.egress_cooldown_max,
    );

    // 2. Primary responds in 80ms (> hedge_ms=40ms), backup responds in 400ms:
    //    Hedge starts at 40ms (hedge_started=2), but primary wins at 80ms (hedge_won_by_backup stays 1)!
    primary_delay_ms.store(80, Relaxed);
    backup_delay_ms.store(400, Relaxed);
    let (_s2, route2) = connect_upstream(&cfg, 2, &hdr).await?;
    assert_eq!(route2, "egress");
    assert_eq!(cfg.counters.hedge_started.load(Relaxed), 2);
    assert_eq!(cfg.counters.hedge_won_by_backup.load(Relaxed), 1);

    p_task.abort();
    b_task.abort();
    Ok(())
}

#[tokio::test]
async fn egress_mtv3_verifies_hmac_rejects_replay_skew_legacy_toggle_and_security_limits(
) -> Result<()> {
    let cover = cover_mock().await?;
    let dc = TcpListener::bind("127.0.0.1:0").await?;
    let dc_addr = dc.local_addr()?;
    let token = [0x9au8; 16];

    let dc_task = tokio::spawn(async move {
        while let Ok((mut peer, _)) = dc.accept().await {
            tokio::spawn(async move {
                let mut header = [0u8; 64];
                if peer.read_exact(&mut header).await.is_err() {
                    return;
                }
                let mut decode = match AesCtr::new_from_slices(&header[8..40], &header[40..56]) {
                    Ok(c) => c,
                    Err(_) => return,
                };
                let mut plain = header;
                wire::crypt(&mut decode, &mut plain);
                let mut payload = vec![0; CLIENT_PAYLOAD.len()];
                if peer.read_exact(&mut payload).await.is_ok() {
                    wire::crypt(&mut decode, &mut payload);
                    if payload == CLIENT_PAYLOAD {
                        let reversed: Vec<_> = header[8..56].iter().rev().copied().collect();
                        if let Ok(mut encode) =
                            AesCtr::new_from_slices(&reversed[..32], &reversed[32..])
                        {
                            let mut reply = DC_REPLY.to_vec();
                            wire::crypt(&mut encode, &mut reply);
                            let _ = peer.write_all(&reply).await;
                            let _ = peer.shutdown().await;
                        }
                    }
                }
            });
        }
    });

    // 1. Start egress with MTV3 required (`accept_legacy = false`), `allow_from = ["127.0.0.1/32"]`,
    //    `max_failed_per_ip = 4`, `max_unauth_handshakes = 2`.
    let egress_listener = TcpListener::bind("127.0.0.1:0").await?;
    let egress_addr = egress_listener.local_addr()?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let sec_cfg = EgressSecurityConfig {
        accept_legacy: false,
        allow_from: vec![config::IpCidr::parse("127.0.0.1/32")?],
        max_failed_per_ip: 4,
        failed_window: Duration::from_secs(60),
        max_unauth_handshakes: 2,
        dc_media_overrides: default_media_override_map(),
        nonce_cache_capacity: 16_384,
        me: None,
        ws_path: None,
    };
    let egress_task = tokio::spawn(serve_egress_with_security(
        egress_listener,
        Arc::new(HashMap::from([(2, dc_addr)])),
        token,
        16,
        Duration::from_millis(400),
        Duration::from_secs(1),
        Duration::from_millis(50),
        Arc::new(telemetry::Counters::default()),
        sec_cfg,
        async move {
            let _ = shutdown_rx.await;
        },
    ));

    // 2. End-to-end relay over MTV3 (`egress_use_mtv3 = true`) succeeds!
    let mut edge_state = state(cover.addr, "127.0.0.1:1".parse()?);
    {
        let sm = Arc::get_mut(&mut edge_state).context("unique state")?;
        sm.dcs.clear();
        sm.egress_upstreams = vec![egress_addr.into()];
        sm.egress_strategy = EgressStrategy::Ordered;
        sm.egress_token = token;
        sm.egress_use_mtv3 = true;
        sm.handshake = Duration::from_secs(1);
    }
    let (mut client, task) = proxy(edge_state.clone()).await?;
    let raw = hello()?;
    client.write_all(&raw).await?;
    flight(&mut client, &raw).await?;
    let mut bytes = fixture("init")?;
    bytes.extend_from_slice(&fixture("payload")?);
    client.write_all(&wire::record(0x17, &bytes)?).await?;
    client.shutdown().await?;
    let mut reply = Vec::new();
    while reply.len() < DC_REPLY.len() {
        let (kind, part) = read_record(&mut client).await?;
        assert_eq!(kind, 0x17);
        reply.extend_from_slice(&part);
    }
    assert_eq!(reply, fixture("reply")?);
    timeout(Duration::from_secs(2), task).await???;
    assert_eq!(
        edge_state
            .counters
            .upstream_tx_bytes
            .load(std::sync::atomic::Ordering::Relaxed),
        (wire::EGRESS_PREFACE_V3_LEN + CLIENT_PAYLOAD.len()) as u64
    );

    // 3. Valid MTV3 ping (`dc = 0`) succeeds once, and replaying the exact same preface (same nonce) is rejected!
    let now_secs = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let replay_nonce = [0x77u8; 16];
    let ping_preface =
        wire::build_egress_preface_v3(&token, 0, now_secs, &replay_nonce, &[0u8; 64])?;
    {
        let mut s1 = TcpStream::connect(egress_addr).await?;
        s1.write_all(&ping_preface).await?;
        let mut ack = [0u8; 1];
        s1.read_exact(&mut ack).await?;
        assert_eq!(ack[0], EGRESS_ACK_OK);
    }
    // Replay of identical MTV3 preface -> rejected (EOF before ACK)! (Failure #1 for 127.0.0.1)
    {
        let mut s_replay = TcpStream::connect(egress_addr).await?;
        let _ = s_replay.write_all(&ping_preface).await;
        assert_eq!(s_replay.read(&mut [0u8; 1]).await.unwrap_or(0), 0);
    }

    // 4. Wrong HMAC token -> rejected! (Failure #2 for 127.0.0.1)
    {
        let bad_hmac =
            wire::build_egress_preface_v3(&[0x11u8; 16], 0, now_secs, &[0x88u8; 16], &[0u8; 64])?;
        let mut s_bad = TcpStream::connect(egress_addr).await?;
        let _ = s_bad.write_all(&bad_hmac).await;
        assert_eq!(s_bad.read(&mut [0u8; 1]).await.unwrap_or(0), 0);
    }

    // 5. Expired timestamp (now - 45s, outside ±30s window) -> rejected! (Failure #3 for 127.0.0.1)
    {
        let expired = wire::build_egress_preface_v3(
            &token,
            0,
            now_secs.saturating_sub(45),
            &[0x89u8; 16],
            &[0u8; 64],
        )?;
        let mut s_exp = TcpStream::connect(egress_addr).await?;
        let _ = s_exp.write_all(&expired).await;
        assert_eq!(s_exp.read(&mut [0u8; 1]).await.unwrap_or(0), 0);
    }

    // 6. Legacy MTV2 when `accept_legacy = false` -> rejected! (Failure #4 for 127.0.0.1 -> hits max_failed_per_ip = 4)
    {
        let legacy = build_egress_wire_preface(&token, 0, &[0u8; 64], false)?;
        let mut s_leg = TcpStream::connect(egress_addr).await?;
        let _ = s_leg.write_all(&legacy).await;
        assert_eq!(s_leg.read(&mut [0u8; 1]).await.unwrap_or(0), 0);
    }

    // 7. Per-IP sliding window rate limit (`max_failed_per_ip = 4` reached):
    //    Even a fresh valid MTV3 preface from 127.0.0.1 is now rejected immediately!
    {
        let valid_after_limit =
            wire::build_egress_preface_v3(&token, 0, now_secs, &[0x90u8; 16], &[0u8; 64])?;
        let mut s_limited = TcpStream::connect(egress_addr).await?;
        let _ = s_limited.write_all(&valid_after_limit).await;
        assert_eq!(s_limited.read(&mut [0u8; 1]).await.unwrap_or(0), 0);
    }

    // 8. Check CIDR allowlist rejection (`allow_from = ["10.203.0.0/24"]` rejects 127.0.0.1)
    //    and unauthenticated handshake concurrency limit (`max_unauth_handshakes = 1`).
    let egress2_listener = TcpListener::bind("127.0.0.1:0").await?;
    let egress2_addr = egress2_listener.local_addr()?;
    let (shutdown2_tx, shutdown2_rx) = tokio::sync::oneshot::channel::<()>();
    let sec_cfg_deny = EgressSecurityConfig {
        accept_legacy: true,
        allow_from: vec![config::IpCidr::parse("10.203.0.0/24")?],
        max_failed_per_ip: 16,
        failed_window: Duration::from_secs(60),
        max_unauth_handshakes: 1,
        dc_media_overrides: default_media_override_map(),
        nonce_cache_capacity: 16_384,
        me: None,
        ws_path: None,
    };
    let egress2_task = tokio::spawn(serve_egress_with_security(
        egress2_listener,
        Arc::new(HashMap::from([(2, dc_addr)])),
        token,
        16,
        Duration::from_millis(400),
        Duration::from_secs(1),
        Duration::from_millis(50),
        Arc::new(telemetry::Counters::default()),
        sec_cfg_deny,
        async move {
            let _ = shutdown2_rx.await;
        },
    ));
    {
        let fresh = wire::build_egress_preface_v3(&token, 0, now_secs, &[0x91u8; 16], &[0u8; 64])?;
        let mut s_denied = TcpStream::connect(egress2_addr).await?;
        let _ = s_denied.write_all(&fresh).await;
        assert_eq!(s_denied.read(&mut [0u8; 1]).await.unwrap_or(0), 0);
    }

    // 9. Public listen warning helper classification:
    assert!(config::is_loopback_or_private_ip("127.0.0.1".parse()?));
    assert!(config::is_loopback_or_private_ip("10.203.0.1".parse()?));
    assert!(config::is_loopback_or_private_ip("100.64.0.1".parse()?));
    assert!(config::is_loopback_or_private_ip("::1".parse()?));
    assert!(config::is_loopback_or_private_ip("fd00::1".parse()?));
    assert!(!config::is_loopback_or_private_ip("203.0.113.10".parse()?));
    assert!(!config::is_loopback_or_private_ip("0.0.0.0".parse()?));

    let _ = shutdown_tx.send(());
    let _ = shutdown2_tx.send(());
    timeout(Duration::from_secs(2), egress_task).await???;
    timeout(Duration::from_secs(2), egress2_task).await???;
    dc_task.abort();
    Ok(())
}

#[tokio::test]
async fn dc_media_override_is_configurable_and_background_dc_self_check_leaves_routing_unchanged(
) -> Result<()> {
    use std::sync::atomic::Ordering::Relaxed;
    let live_dc = TcpListener::bind("127.0.0.1:0").await?;
    let live_addr = live_dc.local_addr()?;
    let dead_addr = closed_port().await?;
    let custom_media_a: SocketAddr = "127.0.0.1:40151".parse()?;
    let custom_media_b: SocketAddr = "127.0.0.1:40220".parse()?;

    let dc_task = tokio::spawn(async move { while let Ok((_peer, _)) = live_dc.accept().await {} });

    // 1. Custom dc_media_override replaces hardcoded candidates and rotates negative media DCs.
    let dcs = HashMap::from([(2i16, live_addr)]);
    let overrides = HashMap::from([(-2i16, vec![custom_media_a, custom_media_b])]);
    let seq0 = lookup_dc_candidates_with_overrides(&dcs, &overrides, -2, 0);
    let seq1 = lookup_dc_candidates_with_overrides(&dcs, &overrides, -2, 1);
    assert_eq!(seq0, vec![custom_media_a, custom_media_b, live_addr]);
    assert_eq!(seq1, vec![custom_media_b, custom_media_a, live_addr]);

    // 2. Background DC self-check updates metrics (`dc_self_check_ok` / `dc_self_check_failed`)
    //    without modifying `dcs` or `overrides` routing tables.
    let self_check_dcs = HashMap::from([(2i16, live_addr), (4i16, dead_addr)]);
    let self_check_overrides = HashMap::new();
    let counters = telemetry::Counters::default();
    let (ok, fail) = run_dc_reachability_check_once(
        &self_check_dcs,
        &self_check_overrides,
        &counters,
        Duration::from_millis(300),
    )
    .await;
    assert_eq!((ok, fail), (1, 1));
    assert_eq!(counters.dc_self_check_ok.load(Relaxed), 1);
    assert_eq!(counters.dc_self_check_failed.load(Relaxed), 1);
    // Routing candidates for DC 4 remain unchanged after self-check failure:
    assert_eq!(
        lookup_dc_candidates_with_overrides(&self_check_dcs, &self_check_overrides, 4, 0),
        vec![dead_addr]
    );

    dc_task.abort();
    Ok(())
}

#[tokio::test]
async fn inv04_cover_dns_caches_and_preserves_last_known_good_on_failure_or_timeout() -> Result<()>
{
    use std::sync::atomic::Ordering::Relaxed;
    let counters = telemetry::Counters::default();
    let resolver = CoverResolver::new("cover.invalid:443".into(), Duration::from_secs(60));
    assert!(!resolver.is_static_ip());
    assert!(resolver.next_addr().is_none());

    // 1. Initial DNS failure leaves cache empty and increments cover_dns_fail.
    let ok = resolver
        .refresh_with(Duration::from_millis(100), &counters, |_| async {
            Err(std::io::Error::other("nxdomain"))
        })
        .await;
    assert!(!ok);
    assert!(resolver.next_addr().is_none());
    assert_eq!(counters.cover_dns_fail.load(Relaxed), 1);

    // 2. Successful DNS resolution populates cache with round-robin addresses.
    let a1: SocketAddr = "127.0.0.1:4431".parse()?;
    let a2: SocketAddr = "127.0.0.1:4432".parse()?;
    let ok = resolver
        .refresh_with(Duration::from_millis(100), &counters, |_| async move {
            Ok(vec![a1, a2])
        })
        .await;
    assert!(ok);
    assert_eq!(resolver.next_addr(), Some(a1));
    assert_eq!(resolver.next_addr(), Some(a2));

    // 3. Subsequent DNS error AND DNS timeout preserve last-known-good addresses!
    let ok_err = resolver
        .refresh_with(Duration::from_millis(100), &counters, |_| async {
            Err(std::io::Error::other("servfail"))
        })
        .await;
    assert!(!ok_err);
    assert_eq!(counters.cover_dns_fail.load(Relaxed), 2);
    assert_eq!(resolver.next_addr(), Some(a1));

    let ok_timeout = resolver
        .refresh_with(Duration::from_millis(30), &counters, |_| async {
            tokio::time::sleep(Duration::from_millis(200)).await;
            Ok(vec!["127.0.0.1:9999".parse().unwrap_or(a1)])
        })
        .await;
    assert!(!ok_timeout);
    assert_eq!(counters.cover_dns_fail.load(Relaxed), 3);
    // Last-known-good still served immediately without blocking data path:
    assert_eq!(resolver.next_addr(), Some(a2));
    Ok(())
}

#[tokio::test]
async fn diagnostics_flag_gates_timeline_marks_and_preserves_close_attribution() -> Result<()> {
    for diag in [false, true] {
        let (mut dc_peer, dc_reader) = tokio::io::duplex(4096);
        let (client_writer, mut client_peer) = tokio::io::duplex(4096);
        let decoder = AesCtr::new_from_slices(&[0; 32], &[0; 16])?;
        let encoder = AesCtr::new_from_slices(&[0; 32], &[0; 16])?;
        let stats = RelayStats {
            diagnostics: diag,
            ..RelayStats::default()
        };
        let writer = tokio::spawn(async move {
            dc_peer.write_all(b"chunk-one").await?;
            dc_peer.write_all(b"chunk-two").await?;
            dc_peer.shutdown().await?;
            Ok::<_, anyhow::Error>(())
        });
        let reader = tokio::spawn(async move {
            let mut buf = Vec::new();
            client_peer.read_to_end(&mut buf).await?;
            Ok::<_, anyhow::Error>(buf)
        });
        download(
            dc_reader,
            client_writer,
            decoder,
            encoder,
            false,
            Duration::from_secs(1),
            &stats,
        )
        .await?;
        writer.await??;
        let received = reader.await??;
        assert_eq!(received.len(), 18);

        let summary = stats.summary();
        assert_eq!(summary["initiator"], "dc_eof");
        let events = summary["timeline"]["events"]
            .as_array()
            .context("timeline events array")?;
        if diag {
            assert!(
                events.iter().any(|e| e[1] == "dc_read")
                    && events.iter().any(|e| e[1] == "client_write"),
                "diagnostics=true must record per-chunk timeline marks"
            );
        } else {
            assert!(
                events
                    .iter()
                    .all(|e| e[1] != "dc_read" && e[1] != "client_write"),
                "diagnostics=false must skip per-chunk timeline marks"
            );
            assert!(events.iter().any(|e| e[1] == "dc_eof"));
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "manual T12 loopback throughput benchmark"]
async fn bench_t12_relay_loopback_throughput() -> Result<()> {
    const TOTAL_BYTES: usize = 64 * 1024 * 1024;
    const CHUNK: usize = 16 * 1024;
    for diag in [true, false] {
        let dc_listener = TcpListener::bind("127.0.0.1:0").await?;
        let dc_addr = dc_listener.local_addr()?;
        let cl_listener = TcpListener::bind("127.0.0.1:0").await?;
        let cl_addr = cl_listener.local_addr()?;

        let dc_sender = tokio::spawn(async move {
            let (mut s, _) = dc_listener.accept().await?;
            let payload = vec![0x5au8; CHUNK];
            let mut rem = TOTAL_BYTES;
            while rem > 0 {
                let n = rem.min(CHUNK);
                s.write_all(&payload[..n]).await?;
                rem -= n;
            }
            s.shutdown().await?;
            Ok::<_, anyhow::Error>(())
        });
        let cl_sink = tokio::spawn(async move {
            let (mut s, _) = cl_listener.accept().await?;
            let mut buf = vec![0u8; 64 * 1024];
            let mut got = 0usize;
            loop {
                let n = s.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                got += n;
            }
            Ok::<_, anyhow::Error>(got)
        });

        let dc_stream = TcpStream::connect(dc_addr).await?;
        let cl_stream = TcpStream::connect(cl_addr).await?;
        let stats = RelayStats {
            counters: Some(Arc::new(telemetry::Counters::default())),
            client_fd: stream_raw_fd(&cl_stream),
            diagnostics: diag,
            ..RelayStats::default()
        };
        let decoder = AesCtr::new_from_slices(&[0u8; 32], &[0u8; 16])?;
        let encoder = AesCtr::new_from_slices(&[0u8; 32], &[0u8; 16])?;
        let t0 = Instant::now();
        download(
            dc_stream,
            cl_stream,
            decoder,
            encoder,
            true,
            Duration::from_secs(10),
            &stats,
        )
        .await?;
        let elapsed = t0.elapsed();
        dc_sender.await??;
        let got = cl_sink.await??;
        let mib_per_s = (TOTAL_BYTES as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64();
        eprintln!(
            "T12 bench diagnostics={diag}: {TOTAL_BYTES} bytes (framed rx={got}) in {:.1} ms ({:.1} MiB/s)",
            elapsed.as_secs_f64() * 1000.0,
            mib_per_s
        );
    }
    Ok(())
}

#[tokio::test]
async fn metrics_endpoint_serves_prometheus_text_and_returns_404_on_other_paths() -> Result<()> {
    use std::sync::atomic::Ordering::Relaxed;
    let cover = cover_mock().await?;
    let mut st = state(cover.addr, "127.0.0.1:1".parse()?);
    {
        let sm = Arc::get_mut(&mut st).context("unique state")?;
        sm.egress_upstreams = vec!["10.203.0.1:29443".parse()?, "10.203.0.2:29443".parse()?];
        sm.egress_health = std::sync::Mutex::new(EgressHealth::new(2));
        // Put node 0 in open cooldown to verify breaker_state{node} = 1 vs 0.
        let mut h = sm.egress_health.lock().unwrap_or_else(|e| e.into_inner());
        h.nodes[0].until = Some(Instant::now() + Duration::from_secs(30));
    }
    st.counters.active.store(3, Relaxed);
    st.counters.accept_errors.record("emfile");
    st.counters.egress_failover_total.store(2, Relaxed);
    st.counters.hedge_started.store(4, Relaxed);
    st.counters.hedge_won_by_backup.store(1, Relaxed);
    st.counters.cover_rejected.store(5, Relaxed);
    st.counters.replay_full.store(6, Relaxed);
    st.counters.replay_flush_failed.store(7, Relaxed);
    st.counters.forced_close.store(8, Relaxed);
    st.counters.egress_legacy_connections.store(9, Relaxed);
    st.counters.egress_mtv3_connections.store(10, Relaxed);

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let srv = spawn_metrics_server(
        listener,
        st.counters.clone(),
        Some(st.clone()),
        Some(4096),
        stop_rx,
    );

    // 1. GET /metrics returns HTTP 200 and Prometheus text metrics.
    let mut s = TcpStream::connect(addr).await?;
    s.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    let mut resp = String::new();
    timeout(Duration::from_secs(2), s.read_to_string(&mut resp)).await??;
    assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"));
    for needle in [
        "mtevil_active_sessions 3",
        "mtevil_accept_errors_total{kind=\"emfile\"} 1",
        "mtevil_breaker_state{node=\"10.203.0.1:29443\"} 1",
        "mtevil_breaker_state{node=\"10.203.0.2:29443\"} 0",
        "mtevil_egress_failover_total 2",
        "mtevil_hedge_started_total 4",
        "mtevil_hedge_won_by_backup_total 1",
        "mtevil_cover_rejected_total 5",
        "mtevil_replay_full_total 6",
        "mtevil_replay_flush_failed_total 7",
        "mtevil_forced_close_total 8",
        "mtevil_egress_legacy_connections_total 9",
        "mtevil_egress_mtv3_connections_total 10",
        "mtevil_fd_limit 4096",
        "mtevil_fd_used ",
    ] {
        assert!(
            resp.contains(needle),
            "missing metric line: {needle}\n{resp}"
        );
    }

    // 2. Non-/metrics path returns HTTP 404.
    let mut s404 = TcpStream::connect(addr).await?;
    s404.write_all(b"GET /secret HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    let mut resp404 = String::new();
    timeout(Duration::from_secs(2), s404.read_to_string(&mut resp404)).await??;
    assert!(resp404.starts_with("HTTP/1.1 404 Not Found\r\n"));

    let _ = stop_tx.send(());
    timeout(Duration::from_secs(2), srv).await??;
    Ok(())
}

#[tokio::test]
async fn inv02_replay_flush_failure_increments_metric() -> Result<()> {
    use std::sync::atomic::Ordering::Relaxed;
    // Point replay_file to an impossible path (existing regular file as parent dir) so flush fails.
    let dir = std::env::temp_dir().join(format!(
        "mtevil-replay-fail-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    std::fs::create_dir_all(&dir)?;
    let blocker = dir.join("not-a-dir");
    std::fs::write(&blocker, b"block")?;
    let bad_path = blocker.join("replay.bin");

    let (mut cache, _status) =
        ReplayCache::load_with_status(bad_path, 64, Duration::from_secs(120));
    assert_eq!(
        cache.check_and_insert([0xabu8; 32], Instant::now()),
        Decision::Fresh
    );
    let counters = telemetry::Counters::default();
    if cache.flush_snapshot().is_err() {
        counters.replay_flush_failed.fetch_add(1, Relaxed);
    }
    assert_eq!(counters.replay_flush_failed.load(Relaxed), 1);

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[tokio::test]
async fn inv10_f29_graceful_shutdown_completes_within_drain_timeout() -> Result<()> {
    let cover = cover_mock().await?;
    let mut st = state(cover.addr, "127.0.0.1:1".parse()?);
    Arc::get_mut(&mut st).context("unique state")?.drain = Duration::from_millis(250);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let srv = tokio::spawn(serve(listener, st.clone(), 16, async move {
        let _ = stop_rx.await;
    }));

    let _held = TcpStream::connect(addr).await?;
    tokio::time::sleep(Duration::from_millis(40)).await;

    let t0 = Instant::now();
    let _ = stop_tx.send(());
    timeout(Duration::from_secs(2), srv).await???;
    let elapsed = t0.elapsed();
    assert!(
        elapsed <= Duration::from_millis(900),
        "serve() shutdown exceeded drain_timeout=250ms: {elapsed:?}"
    );
    Ok(())
}

#[tokio::test]
async fn inv10_f23_hedge_zero_disabled_at_most_one_hedge_and_loser_closed() -> Result<()> {
    use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
    let cover = cover_mock().await?;

    // Helper: mock egress that sleeps `ack_delay_ms`, sends ACK_OK, and tracks EOF on loser socket.
    async fn spawn_delay_egress(
        ack_delay_ms: u64,
    ) -> Result<(
        SocketAddr,
        Arc<AtomicUsize>,
        Arc<AtomicUsize>,
        tokio::task::JoinHandle<()>,
    )> {
        let l = TcpListener::bind("127.0.0.1:0").await?;
        let addr = l.local_addr()?;
        let hits = Arc::new(AtomicUsize::new(0));
        let closed = Arc::new(AtomicUsize::new(0));
        let h_cl = hits.clone();
        let c_cl = closed.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else {
                    break;
                };
                h_cl.fetch_add(1, Relaxed);
                let c_inner = c_cl.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 88];
                    if s.read_exact(&mut buf).await.is_ok() {
                        if ack_delay_ms > 0 {
                            tokio::time::sleep(Duration::from_millis(ack_delay_ms)).await;
                        }
                        let _ = s.write_all(&[EGRESS_ACK_OK]).await;
                        let mut drain = [0u8; 16];
                        let _ = timeout(Duration::from_secs(2), s.read(&mut drain)).await;
                    }
                    c_inner.fetch_add(1, Relaxed);
                });
            }
        });
        Ok((addr, hits, closed, task))
    }

    // 1. egress_hedge_ms = 0: slow primary (120ms) completes without starting backup hedge.
    let (p1, p1_hits, _, t1) = spawn_delay_egress(120).await?;
    let (b1, b1_hits, _, t2) = spawn_delay_egress(0).await?;
    let mut st0 = state(cover.addr, "127.0.0.1:1".parse()?);
    {
        let sm = Arc::get_mut(&mut st0).context("unique state")?;
        sm.egress_upstreams = vec![p1.into(), b1.into()];
        sm.egress_strategy = EgressStrategy::Ordered;
        sm.egress_health = std::sync::Mutex::new(EgressHealth::new(2));
        sm.egress_hedge_ms = 0;
        sm.egress_use_mtv3 = false;
        sm.handshake = Duration::from_secs(3);
    }
    let s = connect_upstream(&st0, 2, &[0x11; 64]).await?;
    drop(s);
    assert_eq!(st0.counters.hedge_started.load(Relaxed), 0);
    assert_eq!(st0.counters.hedge_won_by_backup.load(Relaxed), 0);
    assert_eq!(p1_hits.load(Relaxed), 1);
    assert_eq!(b1_hits.load(Relaxed), 0);

    // 2. egress_hedge_ms = 40 with 3 nodes: at most ONE hedge per connection, loser socket closes cleanly.
    let (p2, p2_hits, p2_closed, t3) = spawn_delay_egress(350).await?;
    let (b2, b2_hits, b2_closed, t4) = spawn_delay_egress(10).await?;
    let (b3, b3_hits, _, t5) = spawn_delay_egress(0).await?;
    let mut st1 = state(cover.addr, "127.0.0.1:1".parse()?);
    {
        let sm = Arc::get_mut(&mut st1).context("unique state")?;
        sm.egress_upstreams = vec![p2.into(), b2.into(), b3.into()];
        sm.egress_strategy = EgressStrategy::Ordered;
        sm.egress_health = std::sync::Mutex::new(EgressHealth::new(3));
        sm.egress_hedge_ms = 40;
        sm.egress_use_mtv3 = false;
        sm.handshake = Duration::from_secs(3);
    }
    let s = connect_upstream(&st1, 2, &[0x22; 64]).await?;
    drop(s);
    assert_eq!(st1.counters.hedge_started.load(Relaxed), 1);
    assert_eq!(st1.counters.hedge_won_by_backup.load(Relaxed), 1);
    assert_eq!(p2_hits.load(Relaxed), 1);
    assert_eq!(b2_hits.load(Relaxed), 1);
    assert_eq!(b3_hits.load(Relaxed), 0, "at most one hedge per connection");
    // Wait briefly and confirm both losing primary and dropped backup sockets observed peer close (no FD leak).
    tokio::time::sleep(Duration::from_millis(450)).await;
    assert_eq!(
        p2_closed.load(Relaxed),
        1,
        "losing primary socket must be closed after backup wins"
    );
    assert_eq!(
        b2_closed.load(Relaxed),
        1,
        "winning backup socket must be closed after stream drop"
    );

    for t in [t1, t2, t3, t4, t5] {
        t.abort();
    }
    Ok(())
}

#[tokio::test]
#[ignore = "manual B4 stress test: 10000 hedged connections FD leak check"]
async fn inv10_f23_hedge_10000_connections_no_fd_leak() -> Result<()> {
    use std::sync::atomic::Ordering::Relaxed;
    let cover = cover_mock().await?;

    let l_slow = TcpListener::bind("127.0.0.1:0").await?;
    let a_slow = l_slow.local_addr()?;
    let t_slow = tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l_slow.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 88];
                if s.read_exact(&mut buf).await.is_ok() {
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    let _ = s.write_all(&[EGRESS_ACK_OK]).await;
                }
            });
        }
    });

    let l_fast = TcpListener::bind("127.0.0.1:0").await?;
    let a_fast = l_fast.local_addr()?;
    let t_fast = tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l_fast.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 88];
                if s.read_exact(&mut buf).await.is_ok() {
                    let _ = s.write_all(&[EGRESS_ACK_OK]).await;
                }
            });
        }
    });

    let mut st = state(cover.addr, "127.0.0.1:1".parse()?);
    {
        let sm = Arc::get_mut(&mut st).context("unique state")?;
        sm.egress_upstreams = vec![a_slow.into(), a_fast.into()];
        sm.egress_strategy = EgressStrategy::Ordered;
        sm.egress_health = std::sync::Mutex::new(EgressHealth::new(2));
        sm.egress_hedge_ms = 2;
        sm.egress_use_mtv3 = false;
        sm.handshake = Duration::from_secs(3);
    }

    let fd_before = detect_fd_used();
    let sem = Arc::new(Semaphore::new(32));
    let mut joins = Vec::with_capacity(10_000);
    for _ in 0..10_000u64 {
        let p = sem.clone().acquire_owned().await?;
        let st_c = st.clone();
        joins.push(tokio::spawn(async move {
            let _p = p;
            if let Ok(s) = connect_upstream(&st_c, 2, &[0x33; 64]).await {
                drop(s);
            }
        }));
    }
    for j in joins {
        let _ = j.await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(st.counters.hedge_started.load(Relaxed) <= 10_000);
    if let (Some(before), Some(after)) = (fd_before, detect_fd_used()) {
        assert!(
            after <= before + 32,
            "FD leak after 10000 hedged connections: before={before} after={after}"
        );
    }
    t_slow.abort();
    t_fast.abort();
    Ok(())
}

#[tokio::test]
async fn inv10_f31_egress_aborted_prefaces_never_rate_limit_but_bad_hmac_does() -> Result<()> {
    use std::sync::atomic::Ordering::Relaxed;
    let dc_listener = TcpListener::bind("127.0.0.1:0").await?;
    let dc_addr = dc_listener.local_addr()?;
    let dc_task = tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = dc_listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut hdr = [0u8; 64];
                let _ = s.read_exact(&mut hdr).await;
            });
        }
    });

    let egress_listener = TcpListener::bind("127.0.0.1:0").await?;
    let egress_addr = egress_listener.local_addr()?;
    let mut dcs = HashMap::new();
    dcs.insert(2, dc_addr);
    let token = [0x44u8; 16];
    let counters = Arc::new(telemetry::Counters::default());
    let mut sec = EgressSecurityConfig::default_for(64);
    sec.max_failed_per_ip = 16;
    sec.max_unauth_handshakes = 64;
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let srv = tokio::spawn(serve_egress_with_security(
        egress_listener,
        Arc::new(dcs),
        token,
        64,
        Duration::from_secs(2),
        Duration::from_secs(2),
        Duration::from_secs(1),
        counters.clone(),
        sec,
        async move {
            let _ = stop_rx.await;
        },
    ));

    // 1. 200 aborted prefaces (empty close or partial MTV3 header, simulating hedge cancellations)
    //    must NEVER trigger IP rate-limiting.
    for i in 0..200u32 {
        let mut s = TcpStream::connect(egress_addr).await?;
        if i.is_multiple_of(2) {
            let _ = s.write_all(b"MTV3").await;
        }
        drop(s);
    }
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert!(
        counters.egress_preface_aborted.load(Relaxed) >= 150,
        "expected aborted preface counter to increment (got {})",
        counters.egress_preface_aborted.load(Relaxed)
    );

    // Valid MTV3 connection from the same IP still succeeds!
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let ok_preface = wire::build_egress_preface_v3(&token, 2, now, &[0x11; 16], &[0x22; 64])?;
    let mut s_ok = TcpStream::connect(egress_addr).await?;
    s_ok.write_all(&ok_preface).await?;
    let mut ack = [0u8; 1];
    timeout(Duration::from_secs(2), s_ok.read_exact(&mut ack)).await??;
    assert_eq!(ack[0], EGRESS_ACK_OK);
    drop(s_ok);

    // 2. 17 invalid HMACs from the same IP MUST trigger rate-limit.
    let mut bad_preface = ok_preface;
    bad_preface[30] ^= 0xff;
    for _ in 0..17 {
        let mut s = TcpStream::connect(egress_addr).await?;
        let _ = s.write_all(&bad_preface).await;
        let mut buf = [0u8; 1];
        let _ = timeout(Duration::from_millis(500), s.read(&mut buf)).await;
    }

    // Subsequent valid MTV3 connection from the same IP is now rate-limited (EOF without ACK).
    let ok_preface2 = wire::build_egress_preface_v3(&token, 2, now, &[0x12; 16], &[0x22; 64])?;
    let mut s_blocked = TcpStream::connect(egress_addr).await?;
    let _ = s_blocked.write_all(&ok_preface2).await;
    let mut buf = [0u8; 1];
    let n = timeout(Duration::from_secs(2), s_blocked.read(&mut buf))
        .await?
        .unwrap_or(0);
    assert_eq!(n, 0, "IP must be rate-limited after 17 invalid HMACs");

    let _ = stop_tx.send(());
    let _ = timeout(Duration::from_secs(2), srv).await;
    dc_task.abort();
    Ok(())
}

#[tokio::test]
async fn inv10_f31_egress_nonce_cache_30000_valid_hmacs_zero_rejections_and_duplicate_penalized(
) -> Result<()> {
    use std::sync::atomic::Ordering::Relaxed;
    let token = [0x55u8; 16];
    let peer_ip: std::net::IpAddr = "127.0.0.1".parse()?;
    let mut cfg = EgressSecurityConfig::default_for(256);
    cfg.nonce_cache_capacity = 16_384;
    let sec = EgressRuntimeSecurity::new(cfg);
    let counters = telemetry::Counters::default();
    let now_secs = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let base_instant = Instant::now();

    let t0 = Instant::now();
    let mut first_key = [0u8; 32];
    for i in 0..30_000u32 {
        let mut nonce = [0u8; 16];
        nonce[..4].copy_from_slice(&i.to_le_bytes());
        let preface = wire::build_egress_preface_v3(&token, 2, now_secs, &nonce, &[0x33; 64])?;
        let parsed = wire::verify_egress_preface_v3(
            &preface,
            &token,
            now_secs,
            wire::EGRESS_V3_MAX_SKEW_SECS,
        )?;
        let mut replay_key = [0u8; 32];
        replay_key[..8].copy_from_slice(&parsed.timestamp.to_le_bytes());
        replay_key[8..24].copy_from_slice(&parsed.nonce);
        replay_key[24..26].copy_from_slice(&parsed.dc.to_le_bytes());
        if i == 0 {
            first_key = replay_key;
        }
        let decision = sec
            .nonce_replay
            .lock()
            .await
            .check_and_insert(replay_key, base_instant);
        match decision {
            Decision::Fresh => {}
            Decision::Full => {
                counters.egress_nonce_cache_full.fetch_add(1, Relaxed);
            }
            Decision::Duplicate => bail!("unexpected duplicate at {i}"),
        }
    }
    assert!(
        t0.elapsed() < Duration::from_secs(10),
        "30000 valid MTV3 verifications took too long: {:?}",
        t0.elapsed()
    );
    assert_eq!(
        counters.egress_nonce_cache_full.load(Relaxed),
        30_000 - 16_384
    );
    assert!(
        sec.check_peer_allowed(peer_ip).is_ok(),
        "valid connections while nonce cache full must never penalize IP"
    );

    // Real duplicate of an active cached nonce MUST be rejected and penalize IP.
    let dup = sec
        .nonce_replay
        .lock()
        .await
        .check_and_insert(first_key, base_instant);
    assert_eq!(dup, Decision::Duplicate);
    sec.record_auth_failure(peer_ip);
    assert_eq!(
        sec.failed_by_ip
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entries
            .get(&peer_ip)
            .map(|q| q.len()),
        Some(1)
    );
    Ok(())
}

#[test]
fn inv10_f31_ip_failure_tracker_evicts_oldest_and_tracks_metric() -> Result<()> {
    use std::sync::atomic::Ordering::Relaxed;
    let mut tracker = IpFailureTracker::with_capacity(Duration::from_secs(60), 2, 3);
    let counters = telemetry::Counters::default();
    let base = Instant::now();
    let ip1: std::net::IpAddr = "203.0.113.1".parse()?;
    let ip2: std::net::IpAddr = "203.0.113.2".parse()?;
    let ip3: std::net::IpAddr = "203.0.113.3".parse()?;
    let ip4: std::net::IpAddr = "203.0.113.4".parse()?;

    assert!(!tracker.record_failure(ip1, base));
    assert!(!tracker.record_failure(ip2, base + Duration::from_secs(1)));
    assert!(!tracker.record_failure(ip3, base + Duration::from_secs(2)));
    assert_eq!(tracker.entries.len(), 3);

    // 4th distinct IP must evict oldest (ip1) instead of silently ignoring ip4.
    if tracker.record_failure(ip4, base + Duration::from_secs(3)) {
        counters
            .egress_failed_tracker_evictions
            .fetch_add(1, Relaxed);
    }
    assert_eq!(counters.egress_failed_tracker_evictions.load(Relaxed), 1);
    assert_eq!(tracker.entries.len(), 3);
    assert!(!tracker.entries.contains_key(&ip1));
    assert!(tracker.entries.contains_key(&ip4));

    // ip4 can now accumulate failures and hit rate-limit.
    assert!(!tracker.record_failure(ip4, base + Duration::from_secs(4)));
    assert!(tracker.is_rate_limited(ip4, base + Duration::from_secs(4)));
    Ok(())
}

#[tokio::test]
async fn inv10_f24_forced_probe_single_flight_200_concurrent_connections() -> Result<()> {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};
    let cover = cover_mock().await?;

    // Node 0 stays dead (refuses/closes without ACK), Node 1 recovers and responds after 60ms.
    let n0_alive = Arc::new(AtomicBool::new(false));
    let n1_alive = Arc::new(AtomicBool::new(false));
    let n1_hits = Arc::new(AtomicUsize::new(0));

    async fn spawn_toggle_egress(
        alive: Arc<AtomicBool>,
        hits: Arc<AtomicUsize>,
        ack_delay_ms: u64,
    ) -> Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
        let l = TcpListener::bind("127.0.0.1:0").await?;
        let addr = l.local_addr()?;
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else {
                    break;
                };
                let alive_c = alive.clone();
                let hits_c = hits.clone();
                tokio::spawn(async move {
                    if !alive_c.load(Relaxed) {
                        drop(s);
                        return;
                    }
                    let mut buf = [0u8; 88];
                    if s.read_exact(&mut buf).await.is_ok() {
                        hits_c.fetch_add(1, Relaxed);
                        if ack_delay_ms > 0 {
                            tokio::time::sleep(Duration::from_millis(ack_delay_ms)).await;
                        }
                        let _ = s.write_all(&[EGRESS_ACK_OK]).await;
                    }
                });
            }
        });
        Ok((addr, task))
    }

    let n0_hits = Arc::new(AtomicUsize::new(0));
    let (addr0, t0) = spawn_toggle_egress(n0_alive.clone(), n0_hits.clone(), 0).await?;
    let (addr1, t1) = spawn_toggle_egress(n1_alive.clone(), n1_hits.clone(), 60).await?;

    let mut st = state(cover.addr, "127.0.0.1:1".parse()?);
    {
        let sm = Arc::get_mut(&mut st).context("unique state")?;
        sm.egress_upstreams = vec![addr0.into(), addr1.into()];
        sm.egress_strategy = EgressStrategy::Ordered;
        sm.egress_health = std::sync::Mutex::new(EgressHealth::new(2));
        sm.egress_cooldown = Duration::from_secs(30);
        sm.egress_cooldown_max = Duration::from_secs(60);
        sm.egress_hedge_ms = 0;
        sm.egress_use_mtv3 = false;
        sm.handshake = Duration::from_secs(5);
    }

    // 1. Both nodes down -> put both into 30s cooldown.
    assert!(connect_upstream(&st, 2, &[0x10; 64]).await.is_err());

    // 2. Bring node 1 back up while both are still in 30s cooldown.
    n1_alive.store(true, Relaxed);
    // Ensure node 1 expires slightly sooner so forced probe targets node 1 first (or even if node 0 is probed, <= 1 error!).
    let mut joins = Vec::with_capacity(200);
    for _ in 0..200 {
        let st_c = st.clone();
        joins.push(tokio::spawn(async move {
            connect_upstream(&st_c, 2, &[0x20; 64]).await.is_ok()
        }));
    }
    let mut ok = 0usize;
    let mut fail = 0usize;
    for j in joins {
        if j.await? {
            ok += 1;
        } else {
            fail += 1;
        }
    }
    assert!(
        fail <= 1,
        "single-flight forced probe must keep errors <= 1 out of 200 concurrent connections (ok={ok}, fail={fail})"
    );
    assert!(
        ok >= 199,
        "expected >= 199 connections routed to recovered node (ok={ok})"
    );
    assert!(n1_hits.load(Relaxed) >= 199);

    t0.abort();
    t1.abort();
    Ok(())
}

#[tokio::test]
async fn inv10_f24_background_probe_separates_transport_negative_ack_and_positive_ack() -> Result<()>
{
    let health = std::sync::Mutex::new(EgressHealth::new(1));
    let base = Duration::from_secs(10);
    let max = Duration::from_secs(60);

    // 1. Node responds PositiveAck on DC 2 and DC 4, and NegativeAck on DC -2.
    EgressHealth::apply_background_probe(
        &health,
        0,
        2,
        BackgroundProbeOutcome::PositiveAck,
        base,
        max,
    );
    EgressHealth::apply_background_probe(
        &health,
        0,
        4,
        BackgroundProbeOutcome::PositiveAck,
        base,
        max,
    );
    EgressHealth::apply_background_probe(
        &health,
        0,
        -2,
        BackgroundProbeOutcome::NegativeAck,
        base,
        max,
    );

    // Routes for DC 2 and DC 4 MUST NOT be skipped; only (node 0, DC -2) is in cooldown!
    let now = Instant::now();
    assert!(
        EgressHealth::try_claim(&health, 0, 2, now).is_some(),
        "DC 2 must stay available when only DC -2 returned negative ACK"
    );
    assert!(
        EgressHealth::try_claim(&health, 0, 4, now).is_some(),
        "DC 4 must stay available when only DC -2 returned negative ACK"
    );
    assert!(
        EgressHealth::try_claim(&health, 0, -2, now).is_none(),
        "DC -2 must be in cooldown after negative ACK"
    );

    // 2. PositiveAck on DC -2 clears DC -2 cooldown.
    EgressHealth::apply_background_probe(
        &health,
        0,
        -2,
        BackgroundProbeOutcome::PositiveAck,
        base,
        max,
    );
    assert!(EgressHealth::try_claim(&health, 0, -2, Instant::now()).is_some());

    // 3. TransportFailure marks the whole node in cooldown for ALL DCs (2, 4, -2).
    EgressHealth::apply_background_probe(
        &health,
        0,
        -2,
        BackgroundProbeOutcome::TransportFailure,
        base,
        max,
    );
    let now2 = Instant::now();
    assert!(EgressHealth::try_claim(&health, 0, 2, now2).is_none());
    assert!(EgressHealth::try_claim(&health, 0, 4, now2).is_none());
    assert!(EgressHealth::try_claim(&health, 0, -2, now2).is_none());
    Ok(())
}

#[tokio::test]
async fn inv10_f23_round_robin_hedge_adaptive_per_try_and_parallel_node_down_signal() -> Result<()>
{
    use std::sync::atomic::Ordering::Relaxed;
    let cover = cover_mock().await?;

    // 1. Adaptive per_try calculation is per-node: empty -> max; median 10ms -> 300ms min;
    //    unsampled sibling stays at max; median 400ms -> 1200ms.
    let h = std::sync::Mutex::new(EgressHealth::new(2));
    assert_eq!(
        EgressHealth::adaptive_per_try(&h, 0, Duration::from_secs(2)),
        Duration::from_secs(2)
    );
    for _ in 0..5 {
        EgressHealth::record_ack_latency(&h, 0, Duration::from_millis(10));
    }
    assert_eq!(
        EgressHealth::adaptive_per_try(&h, 0, Duration::from_secs(2)),
        Duration::from_millis(300)
    );
    assert_eq!(
        EgressHealth::adaptive_per_try(&h, 1, Duration::from_secs(2)),
        Duration::from_secs(2)
    );
    let h2 = std::sync::Mutex::new(EgressHealth::new(2));
    for _ in 0..5 {
        EgressHealth::record_ack_latency(&h2, 1, Duration::from_millis(400));
    }
    assert_eq!(
        EgressHealth::adaptive_per_try(&h2, 1, Duration::from_secs(2)),
        Duration::from_millis(800)
    );

    // 2. Round-robin with 1 blackhole node and 1 healthy node: 30 parallel connections finish well under 700ms p95!
    let l_blackhole = TcpListener::bind("127.0.0.1:0").await?;
    let a_blackhole = l_blackhole.local_addr()?;
    let t_bh = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = l_blackhole.accept().await {
            held.push(s); // Accept and never send ACK (blackhole)
        }
    });

    let l_live = TcpListener::bind("127.0.0.1:0").await?;
    let a_live = l_live.local_addr()?;
    let t_live = tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l_live.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 88];
                if s.read_exact(&mut buf).await.is_ok() {
                    let _ = s.write_all(&[EGRESS_ACK_OK]).await;
                }
            });
        }
    });

    let mut st = state(cover.addr, "127.0.0.1:1".parse()?);
    {
        let sm = Arc::get_mut(&mut st).context("unique state")?;
        sm.egress_upstreams = vec![a_blackhole.into(), a_live.into()];
        sm.egress_strategy = EgressStrategy::RoundRobin;
        sm.egress_health = std::sync::Mutex::new(EgressHealth::new(2));
        sm.egress_hedge_ms = 200;
        sm.egress_use_mtv3 = false;
        sm.handshake = Duration::from_secs(5);
    }
    // Seed adaptive ACK latency on node 0 from healthy baseline (~5ms -> adaptive per_try = 300ms).
    EgressHealth::record_ack_latency(&st.egress_health, 0, Duration::from_millis(5));

    let mut joins = Vec::with_capacity(30);
    for _ in 0..30 {
        let st_c = st.clone();
        joins.push(tokio::spawn(async move {
            let t0 = Instant::now();
            let res = connect_upstream(&st_c, 2, &[0x44; 64]).await;
            (res.is_ok(), t0.elapsed())
        }));
    }
    let mut lats = Vec::with_capacity(30);
    for j in joins {
        let (ok, d) = j.await?;
        assert!(ok, "round-robin failover connection must succeed");
        lats.push(d);
    }
    lats.sort_unstable();
    let p95 = lats[28];
    assert!(
        p95 <= Duration::from_millis(700),
        "round-robin first-wave p95 must be <= 700ms (got {p95:?})"
    );
    assert!(
        st.counters.hedge_started.load(Relaxed) >= 1,
        "round-robin must start hedge when first node stalls"
    );

    t_bh.abort();
    t_live.abort();
    Ok(())
}

#[test]
fn alert_webhook_bounded_queue_drops_on_overflow_and_tracks_metric() -> Result<()> {
    use std::sync::atomic::Ordering::Relaxed;
    let (gate_tx, gate_rx) = std::sync::mpsc::channel::<()>();
    let gate_rx = Arc::new(std::sync::Mutex::new(gate_rx));
    let started = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let started_c = started.clone();
    let gate_c = gate_rx.clone();

    let dispatcher = AlertWebhookDispatcher::new_with_handler(2, 1, move |_url, _body| {
        started_c.fetch_add(1, Relaxed);
        let _ = gate_c
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .recv_timeout(Duration::from_secs(2));
    });
    let counters = telemetry::Counters::default();

    // Item 1 picked up by the single worker and blocks on gate_rx.
    assert!(dispatcher.try_enqueue("http://127.0.0.1:1".into(), "1".into(), &counters));
    for _ in 0..50 {
        if started.load(Relaxed) >= 1 {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    // Items 2 and 3 fill the bounded queue (capacity=2).
    assert!(dispatcher.try_enqueue("http://127.0.0.1:1".into(), "2".into(), &counters));
    assert!(dispatcher.try_enqueue("http://127.0.0.1:1".into(), "3".into(), &counters));
    // Item 4 overflows the bounded queue and increments alert_webhook_dropped.
    assert!(!dispatcher.try_enqueue("http://127.0.0.1:1".into(), "4".into(), &counters));
    assert_eq!(counters.alert_webhook_dropped.load(Relaxed), 1);

    let _ = gate_tx.send(());
    let _ = gate_tx.send(());
    let _ = gate_tx.send(());
    Ok(())
}

#[tokio::test]
async fn inv10_f32_egress_long_download_exceeding_idle_survives_while_true_idle_closes(
) -> Result<()> {
    let token = [0x77u8; 16];
    let idle = Duration::from_millis(300);

    // 1. Mock DC that streams 10 chunks every 80ms (~800ms > 2.5x idle) while client upload is completely silent.
    let dc_listener = TcpListener::bind("127.0.0.1:0").await?;
    let dc_addr = dc_listener.local_addr()?;
    let dc_task = tokio::spawn(async move {
        let Ok((mut s, _)) = dc_listener.accept().await else {
            return;
        };
        let mut hdr = [0u8; 64];
        if s.read_exact(&mut hdr).await.is_err() {
            return;
        }
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(80)).await;
            if s.write_all(b"0123456789abcdef").await.is_err() {
                return;
            }
        }
        let _ = s.shutdown().await;
    });

    // 2. Second mock DC that stays completely silent (tests true idle timeout).
    let silent_dc_listener = TcpListener::bind("127.0.0.1:0").await?;
    let silent_dc_addr = silent_dc_listener.local_addr()?;
    let silent_dc_task = tokio::spawn(async move {
        let Ok((mut s, _)) = silent_dc_listener.accept().await else {
            return;
        };
        let mut hdr = [0u8; 64];
        let _ = s.read_exact(&mut hdr).await;
        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    let egress_listener = TcpListener::bind("127.0.0.1:0").await?;
    let egress_addr = egress_listener.local_addr()?;
    let mut dcs = HashMap::new();
    dcs.insert(2, dc_addr);
    dcs.insert(4, silent_dc_addr);
    let counters = Arc::new(telemetry::Counters::default());
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let srv = tokio::spawn(serve_egress_with_security(
        egress_listener,
        Arc::new(dcs),
        token,
        16,
        Duration::from_secs(2),
        idle,
        Duration::from_secs(1),
        counters,
        EgressSecurityConfig::default_for(16),
        async move {
            let _ = stop_rx.await;
        },
    ));

    // Case A: Long unidirectional download (> 2.5 * idle) must NOT abort!
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let preface = wire::build_egress_preface_v3(&token, 2, now, &[0x01; 16], &[0xaa; 64])?;
    let mut s = TcpStream::connect(egress_addr).await?;
    s.write_all(&preface).await?;
    let mut ack = [0u8; 1];
    s.read_exact(&mut ack).await?;
    assert_eq!(ack[0], EGRESS_ACK_OK);
    let mut downloaded = Vec::new();
    timeout(Duration::from_secs(3), s.read_to_end(&mut downloaded)).await??;
    assert_eq!(
        downloaded.len(),
        160,
        "long unidirectional download through egress exceeding idle_timeout must complete"
    );

    // Case B: True idle (no progress in either direction) closes right around idle (300ms).
    let preface_silent = wire::build_egress_preface_v3(&token, 4, now, &[0x02; 16], &[0xbb; 64])?;
    let mut s2 = TcpStream::connect(egress_addr).await?;
    s2.write_all(&preface_silent).await?;
    s2.read_exact(&mut ack).await?;
    assert_eq!(ack[0], EGRESS_ACK_OK);
    let t0 = Instant::now();
    let mut buf = [0u8; 16];
    let n = timeout(Duration::from_secs(2), s2.read(&mut buf))
        .await?
        .unwrap_or(0);
    let elapsed = t0.elapsed();
    assert_eq!(n, 0, "true idle egress session must close");
    assert!(
        elapsed >= Duration::from_millis(240) && elapsed <= Duration::from_millis(1200),
        "true idle session should close near idle=300ms (got {elapsed:?})"
    );

    let _ = stop_tx.send(());
    let _ = timeout(Duration::from_secs(2), srv).await;
    dc_task.abort();
    silent_dc_task.abort();
    Ok(())
}

#[tokio::test]
async fn inv10_f23_fast_primary_samples_do_not_timeout_healthy_slower_backup() -> Result<()> {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};
    let cover = cover_mock().await?;

    async fn spawn_controllable_egress(
        ack_delay_ms: u64,
        blackhole: Arc<AtomicBool>,
    ) -> Result<(SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>)> {
        let l = TcpListener::bind("127.0.0.1:0").await?;
        let addr = l.local_addr()?;
        let hits = Arc::new(AtomicUsize::new(0));
        let h_cl = hits.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else {
                    break;
                };
                h_cl.fetch_add(1, Relaxed);
                let bh = blackhole.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 88];
                    if s.read_exact(&mut buf).await.is_ok() {
                        if bh.load(Relaxed) {
                            tokio::time::sleep(Duration::from_secs(10)).await;
                            return;
                        }
                        if ack_delay_ms > 0 {
                            tokio::time::sleep(Duration::from_millis(ack_delay_ms)).await;
                        }
                        let _ = s.write_all(&[EGRESS_ACK_OK]).await;
                        let mut drain = [0u8; 16];
                        let _ = timeout(Duration::from_secs(2), s.read(&mut drain)).await;
                    }
                });
            }
        });
        Ok((addr, hits, task))
    }

    // 1. Ordered strategy: fast primary trains estimator (< 5ms), then becomes unavailable;
    //    healthy slower backup (450ms ACK > 300ms floor, < 2000ms max_per_try) must succeed
    //    both on direct failover and on hedged failover.
    let p_bh = Arc::new(AtomicBool::new(false));
    let b_bh = Arc::new(AtomicBool::new(false));
    let (p_addr, _p_hits, p_task) = spawn_controllable_egress(0, p_bh.clone()).await?;
    let (b_addr, b_hits, b_task) = spawn_controllable_egress(450, b_bh.clone()).await?;

    let mut st = state(cover.addr, "127.0.0.1:1".parse()?);
    {
        let sm = Arc::get_mut(&mut st).context("unique state")?;
        sm.egress_upstreams = vec![p_addr.into(), b_addr.into()];
        sm.egress_strategy = EgressStrategy::Ordered;
        sm.egress_health = std::sync::Mutex::new(EgressHealth::new(2));
        sm.egress_hedge_ms = 80;
        sm.egress_use_mtv3 = false;
        sm.handshake = Duration::from_secs(4);
    }

    // Train fast primary with 8 successful connections.
    for _ in 0..8 {
        let (s, route) = connect_upstream(&st, 2, &[0x11; 64]).await?;
        assert_eq!(route, "egress");
        drop(s);
    }
    assert_eq!(
        b_hits.load(Relaxed),
        0,
        "backup must remain unsampled during training"
    );

    // 1a. Primary blackholed -> hedge fires at 80ms -> backup (450ms ACK) must NOT time out at 300ms.
    p_bh.store(true, Relaxed);
    let t0 = Instant::now();
    let (s, route) = connect_upstream(&st, 2, &[0x22; 64])
        .await
        .context("ordered hedged failover to 450ms healthy backup must succeed")?;
    assert_eq!(route, "egress");
    assert!(t0.elapsed() < Duration::from_secs(4));
    assert_eq!(st.counters.hedge_started.load(Relaxed), 1);
    assert_eq!(st.counters.hedge_won_by_backup.load(Relaxed), 1);
    drop(s);

    // 1b. Next connection while primary is in cooldown goes directly to backup (450ms ACK) and succeeds.
    let (s2, route2) = connect_upstream(&st, 2, &[0x33; 64])
        .await
        .context("ordered direct failover to 450ms healthy backup must succeed")?;
    assert_eq!(route2, "egress");
    drop(s2);

    // 2. Round-robin strategy: fast node 0 trained while node 1 is in cooldown; then node 0
    //    blackholes and node 1 (unsampled, 450ms ACK) must succeed via hedge from node 0.
    let rr_bh0 = Arc::new(AtomicBool::new(false));
    let rr_bh1 = Arc::new(AtomicBool::new(false));
    let (rr0, _rr0_hits, rr0_task) = spawn_controllable_egress(0, rr_bh0.clone()).await?;
    let (rr1, rr1_hits, rr1_task) = spawn_controllable_egress(450, rr_bh1.clone()).await?;

    let mut st_rr = state(cover.addr, "127.0.0.1:1".parse()?);
    {
        let sm = Arc::get_mut(&mut st_rr).context("unique state")?;
        sm.egress_upstreams = vec![rr0.into(), rr1.into()];
        sm.egress_strategy = EgressStrategy::RoundRobin;
        sm.egress_health = std::sync::Mutex::new(EgressHealth::new(2));
        sm.egress_hedge_ms = 80;
        sm.egress_use_mtv3 = false;
        sm.handshake = Duration::from_secs(4);
    }
    // Temporarily put node 1 in cooldown so only node 0 is sampled during training.
    {
        let mut h = st_rr
            .egress_health
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        h.nodes[1].until = Some(Instant::now() + Duration::from_secs(60));
    }
    for _ in 0..6 {
        let (s, _) = connect_upstream(&st_rr, 2, &[0x44; 64]).await?;
        drop(s);
    }
    assert_eq!(rr1_hits.load(Relaxed), 0);

    // Restore node 1, blackhole node 0, and force RR start = 0 so node 0 is attempted first and hedges to node 1.
    {
        let mut h = st_rr
            .egress_health
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        h.nodes[1].until = None;
    }
    st_rr.egress_rr.store(0, Relaxed);
    rr_bh0.store(true, Relaxed);
    let (s_rr, route_rr) = connect_upstream(&st_rr, 2, &[0x55; 64])
        .await
        .context("round-robin hedged failover to 450ms healthy backup must succeed")?;
    assert_eq!(route_rr, "egress");
    assert_eq!(st_rr.counters.hedge_started.load(Relaxed), 1);
    assert_eq!(st_rr.counters.hedge_won_by_backup.load(Relaxed), 1);
    drop(s_rr);

    for t in [p_task, b_task, rr0_task, rr1_task] {
        t.abort();
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inv10_f23_signaled_down_does_not_cascade_failures_or_inflate_cooldown() -> Result<()> {
    use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
    let cover = cover_mock().await?;

    // Mock egress accepts 30 connections, waits until ALL 30 have written their preface and are
    // waiting for ACK, then closes ONLY the 1st connection (real transport EOF) while holding
    // the other 29 open so they cancel via `node_down` (`EgressAttemptErr::SignaledDown`).
    let l = TcpListener::bind("127.0.0.1:0").await?;
    let addr = l.local_addr()?;
    let in_flight = Arc::new(AtomicUsize::new(0));
    let all_ready = Arc::new(tokio::sync::Notify::new());
    let release_fail = Arc::new(tokio::sync::Notify::new());
    let hold_rest = Arc::new(tokio::sync::Notify::new());

    let in_flight_srv = in_flight.clone();
    let all_ready_srv = all_ready.clone();
    let release_fail_srv = release_fail.clone();
    let hold_rest_srv = hold_rest.clone();
    let srv = tokio::spawn(async move {
        for idx in 0..30usize {
            let Ok((mut s, _)) = l.accept().await else {
                break;
            };
            let inf = in_flight_srv.clone();
            let ar = all_ready_srv.clone();
            let rf = release_fail_srv.clone();
            let hr = hold_rest_srv.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 88];
                if s.read_exact(&mut buf).await.is_ok() {
                    if inf.fetch_add(1, Relaxed) + 1 == 30 {
                        ar.notify_one();
                    }
                    if idx == 0 {
                        rf.notified().await;
                        // Drop socket -> real EOF transport failure on attempt #0
                        drop(s);
                    } else {
                        // Hold open until test finishes so attempts 1..30 cancel via node_down
                        hr.notified().await;
                        drop(s);
                    }
                }
            });
        }
    });

    let base_cd = Duration::from_secs(3);
    let mut st = state(cover.addr, "127.0.0.1:1".parse()?);
    {
        let sm = Arc::get_mut(&mut st).context("unique state")?;
        sm.egress_upstreams = vec![addr.into()];
        sm.egress_strategy = EgressStrategy::Ordered;
        sm.egress_health = std::sync::Mutex::new(EgressHealth::new(1));
        sm.egress_cooldown = base_cd;
        sm.egress_cooldown_max = Duration::from_secs(60);
        sm.egress_use_mtv3 = false;
        sm.handshake = Duration::from_secs(10);
    }
    assert_eq!(
        st.egress_health
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .nodes[0]
            .failures,
        0
    );

    let mut joins = Vec::with_capacity(30);
    for _ in 0..30 {
        let st_c = st.clone();
        joins.push(tokio::spawn(async move {
            let Some(claim) = EgressHealth::try_claim(&st_c.egress_health, 0, 2, Instant::now())
            else {
                return Err(anyhow::anyhow!("node 0 must be claimable"));
            };
            let res = dial_egress_candidate(
                &st_c,
                0,
                2,
                2,
                connect::EgressDialMode::DirectStream(&[0x11; 64]),
                Duration::from_secs(5),
            )
            .await;
            let Err(err) = res else {
                return Err(anyhow::anyhow!("all 30 attempts must fail"));
            };
            let is_signaled = matches!(err, EgressAttemptErr::SignaledDown(_));
            let _ = finalize_egress_error(&st_c, 0, claim, err);
            Ok(is_signaled)
        }));
    }

    // Confirm all 30 attempts are in-flight before injecting the single transport failure.
    all_ready.notified().await;
    assert_eq!(in_flight.load(Relaxed), 30);

    let before_fail = Instant::now();
    release_fail.notify_one();

    let mut signaled_count = 0usize;
    for j in joins {
        if j.await?? {
            signaled_count += 1;
        }
    }
    let after_fail = Instant::now();
    hold_rest.notify_waiters();
    srv.abort();

    assert_eq!(
        signaled_count, 29,
        "exactly 29 peer attempts must cancel via SignaledDown"
    );
    let h = st.egress_health.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(
        h.nodes[0].failures, 1,
        "SignaledDown cancellations must not increment slot.failures"
    );
    let until = h.nodes[0].until.context("node 0 must be in cooldown")?;
    let min_assigned = until.saturating_duration_since(after_fail);
    let max_assigned = until.saturating_duration_since(before_fail);
    // Base cooldown is 3s with ±20% jitter -> [2400ms, 3600ms], never inflated to 2*base (6s) or max (60s).
    assert!(
        max_assigned >= Duration::from_millis(2350) && min_assigned <= Duration::from_millis(3650),
        "assigned cooldown must equal base ±20% jitter (min={min_assigned:?}, max={max_assigned:?})"
    );
    Ok(())
}

#[tokio::test]
async fn inv10_f23_ack_timeout_after_preface_is_dc_level_while_connect_timeout_is_node_level(
) -> Result<()> {
    let cover = cover_mock().await?;

    // Mock egress: for DC 2 (DC-A) accepts TCP, reads full 88-byte MTV2 preface, then stalls ACK
    // longer than actual per_try; for DC 4 (DC-B) responds immediately with EGRESS_ACK_OK.
    let l = TcpListener::bind("127.0.0.1:0").await?;
    let addr = l.local_addr()?;
    let srv = tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 88];
                if s.read_exact(&mut buf).await.is_ok() {
                    let dc = i16::from_le_bytes([buf[4], buf[5]]);
                    if dc == 2 {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    } else {
                        let _ = s.write_all(&[EGRESS_ACK_OK]).await;
                        let mut drain = [0u8; 16];
                        let _ = timeout(Duration::from_secs(2), s.read(&mut drain)).await;
                    }
                }
            });
        }
    });

    let mut st = state(cover.addr, "127.0.0.1:1".parse()?);
    {
        let sm = Arc::get_mut(&mut st).context("unique state")?;
        sm.egress_upstreams = vec![addr.into()];
        sm.egress_strategy = EgressStrategy::Ordered;
        sm.egress_health = std::sync::Mutex::new(EgressHealth::new(1));
        sm.egress_cooldown = Duration::from_secs(10);
        sm.egress_cooldown_max = Duration::from_secs(60);
        sm.egress_use_mtv3 = false;
        sm.handshake = Duration::from_secs(4);
    }
    // Seed 4 fast samples on node 0 so adaptive_per_try is active (300ms).
    for _ in 0..4 {
        EgressHealth::record_ack_latency(&st.egress_health, 0, Duration::from_millis(10));
    }
    let max_per_try = Duration::from_secs(2);
    let actual_per_try = EgressHealth::adaptive_per_try(&st.egress_health, 0, max_per_try);

    // Scenario 1: TCP established + full preface written + ACK exceeds actual_per_try (5s > actual_per_try).
    let notifier = EgressHealth::node_down_notifier(&st.egress_health, 0);
    let node_down_fut = notifier.notified();
    tokio::pin!(node_down_fut);
    node_down_fut.as_mut().enable();

    let claim_a =
        EgressHealth::try_claim(&st.egress_health, 0, 2, Instant::now()).context("claim DC-A")?;
    let Err(err_a) = dial_egress_candidate(
        &st,
        0,
        2,
        2,
        connect::EgressDialMode::DirectStream(&[0x11; 64]),
        actual_per_try,
    )
    .await
    else {
        anyhow::bail!("DC-A must time out waiting for ACK");
    };
    assert!(
        matches!(err_a, EgressAttemptErr::DcAckTimeout(_)),
        "ACK timeout after full preface write must be classified as DcAckTimeout"
    );
    let _ = finalize_egress_error(&st, 0, claim_a, err_a);

    // Verify: (node 0, DC 2) is in cooldown, node 0 itself is NOT in cooldown, node_down NOT sent.
    {
        let h = st.egress_health.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            h.nodes[0].until.is_none(),
            "whole node must NOT be cooled down on ACK timeout after preface"
        );
        assert!(
            h.dc_slots.get(&(0, 2)).and_then(|s| s.until).is_some(),
            "(node 0, DC-A) must be in cooldown"
        );
    }
    assert!(
        timeout(Duration::from_millis(20), &mut node_down_fut)
            .await
            .is_err(),
        "node_down must NOT be signaled on DC-level ACK timeout"
    );

    // While DC-A (2) is still in cooldown, DC-B (4) connects cleanly through the SAME node 0!
    let (stream_b, route_b) = connect_upstream(&st, 4, &[0x22; 64])
        .await
        .context("DC-B must succeed through same node while DC-A is in cooldown")?;
    assert_eq!(route_b, "egress");
    drop(stream_b);
    srv.abort();

    // Scenario 2: Real transport failure before preface write (closed port -> connection refused)
    // cools down the whole node AND signals node_down.
    let dead_listener = TcpListener::bind("127.0.0.1:0").await?;
    let dead_addr = dead_listener.local_addr()?;
    drop(dead_listener);

    let mut st2 = state(cover.addr, "127.0.0.1:1".parse()?);
    {
        let sm = Arc::get_mut(&mut st2).context("unique state")?;
        sm.egress_upstreams = vec![dead_addr.into()];
        sm.egress_strategy = EgressStrategy::Ordered;
        sm.egress_health = std::sync::Mutex::new(EgressHealth::new(1));
        sm.egress_cooldown = Duration::from_secs(10);
        sm.egress_cooldown_max = Duration::from_secs(60);
        sm.egress_use_mtv3 = false;
        sm.handshake = Duration::from_secs(4);
    }
    let notifier2 = EgressHealth::node_down_notifier(&st2.egress_health, 0);
    let node_down_fut2 = notifier2.notified();
    tokio::pin!(node_down_fut2);
    node_down_fut2.as_mut().enable();

    let claim_dead = EgressHealth::try_claim(&st2.egress_health, 0, 2, Instant::now())
        .context("claim dead node")?;
    let Err(err_dead) = dial_egress_candidate(
        &st2,
        0,
        2,
        2,
        connect::EgressDialMode::DirectStream(&[0x33; 64]),
        Duration::from_secs(1),
    )
    .await
    else {
        anyhow::bail!("closed port must fail");
    };
    assert!(
        matches!(err_dead, EgressAttemptErr::Node(_)),
        "pre-preface transport error must be Node-level"
    );
    let _ = finalize_egress_error(&st2, 0, claim_dead, err_dead);

    {
        let h2 = st2.egress_health.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            h2.nodes[0].until.is_some(),
            "whole node must be in cooldown after pre-preface transport failure"
        );
    }
    timeout(Duration::from_millis(50), &mut node_down_fut2)
        .await
        .context("node_down must be signaled on pre-preface transport failure")?;
    Ok(())
}

#[test]
fn inv10_f23_compare_per_try_floor_policies_slow_route_vs_blackhole() {
    // Compare Policy A: fixed 800ms floor vs Policy B: max(300ms, 2*p95) clamped to max_per_try=2000ms.
    let max_ms = 2000u64;
    let policy_a = |samples: &[u64]| -> u64 {
        let mut s = samples.to_vec();
        s.sort_unstable();
        let med = s[s.len() / 2];
        med.saturating_mul(3).clamp(800, max_ms)
    };
    let policy_b = |samples: &[u64]| -> u64 {
        let h = std::sync::Mutex::new(EgressHealth::new(1));
        for &ms in samples {
            EgressHealth::record_ack_latency(&h, 0, Duration::from_millis(ms));
        }
        EgressHealth::adaptive_per_try(&h, 0, Duration::from_millis(max_ms)).as_millis() as u64
    };

    // (a) Healthy slow/jittery route: 18 samples at 120ms, 2 tail samples at 420ms -> p95=420ms.
    let mut slow_samples = vec![120u64; 18];
    slow_samples.extend_from_slice(&[420, 420]);
    let per_try_a_slow = policy_a(&slow_samples);
    let per_try_b_slow = policy_b(&slow_samples);
    // Both avoid false timeouts on 500ms tail spikes (A=800ms, B=840ms); Policy B even scales above 800ms for slower tails!
    assert_eq!(per_try_a_slow, 800);
    assert_eq!(per_try_b_slow, 840);

    // (b) Fast route hitting blackhole (no hedge / 2nd attempt): 19 samples at 15ms, 1 at 40ms -> p95=40ms.
    let mut fast_samples = vec![15u64; 19];
    fast_samples.push(40);
    let per_try_a_bh = policy_a(&fast_samples);
    let per_try_b_bh = policy_b(&fast_samples);
    // Policy B cuts unhedged blackhole detection from 800ms down to 300ms (2.67x faster).
    assert_eq!(per_try_a_bh, 800);
    assert_eq!(per_try_b_bh, 300);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inv10_f23_hung_egress_ack_timeout_escalation_and_isolated_dc_isolation() -> Result<()> {
    use std::io::{Read as _, Write as _};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};
    let cover = cover_mock().await?;

    // Helper: hung egress accepts TCP, reads preface, never sends ACK.
    let l_hung = TcpListener::bind("127.0.0.1:0").await?;
    let a_hung = l_hung.local_addr()?;
    let hung_accepts = Arc::new(AtomicUsize::new(0));
    let hung_accepts_srv = hung_accepts.clone();
    let t_hung = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((mut s, _)) = l_hung.accept().await {
            hung_accepts_srv.fetch_add(1, Relaxed);
            let mut buf = [0u8; 88];
            let _ = s.read_exact(&mut buf).await;
            held.push(s);
        }
    });

    // Helper: healthy backup runs on dedicated OS threads so backup replies never contend
    // with Tokio runtime worker scheduling under heavy workspace test concurrency.
    let std_ok = std::net::TcpListener::bind("127.0.0.1:0")?;
    let a_ok = std_ok.local_addr()?;
    let stop_ok = Arc::new(AtomicBool::new(false));
    let stop_ok_srv = stop_ok.clone();
    let ok_thread = std::thread::spawn(move || {
        while let Ok((mut s, _)) = std_ok.accept() {
            if stop_ok_srv.load(Relaxed) {
                break;
            }
            std::thread::spawn(move || {
                let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
                let _ = s.set_write_timeout(Some(Duration::from_secs(2)));
                let mut buf = [0u8; 88];
                if s.read_exact(&mut buf).is_ok() {
                    let _ = s.write_all(&[EGRESS_ACK_OK]);
                    let _ = s.flush();
                    let mut drain = [0u8; 16];
                    let _ = s.read(&mut drain);
                }
            });
        }
    });

    // Scenario 1 ("egress hung: TCP accepted, no ACK"): 21 sequential connections across different DCs
    // with hedge disabled (hedge_ms=0) to isolate per_try escalation directly.
    let mut st = state(cover.addr, "127.0.0.1:1".parse()?);
    {
        let sm = Arc::get_mut(&mut st).context("unique state")?;
        sm.egress_upstreams = vec![a_hung.into(), a_ok.into()];
        sm.egress_strategy = EgressStrategy::Ordered;
        sm.egress_health = std::sync::Mutex::new(EgressHealth::new(2));
        sm.egress_hedge_ms = 0;
        sm.egress_cooldown = Duration::from_secs(10);
        sm.egress_cooldown_max = Duration::from_secs(60);
        sm.egress_use_mtv3 = false;
        sm.handshake = Duration::from_secs(4);
    }
    // Seed 4 fast samples on primary so adaptive per_try = 300ms.
    for _ in 0..4 {
        EgressHealth::record_ack_latency(&st.egress_health, 0, Duration::from_millis(10));
    }

    let dcs: [i16; 7] = [2, 4, -2, -4, 1, 3, 5];
    let mut lats_ms = Vec::with_capacity(21);
    for i in 0..21usize {
        let dc = dcs[i % dcs.len()];
        let t0 = Instant::now();
        let (s, route) = connect_upstream(&st, dc, &[0x11; 64]).await?;
        assert_eq!(route, "egress");
        drop(s);
        lats_ms.push(t0.elapsed().as_millis() as u64);
    }
    lats_ms.sort_unstable();
    let p50 = lats_ms[lats_ms.len() / 2];
    let p95 = lats_ms[((lats_ms.len() * 95).div_ceil(100)).saturating_sub(1)];
    let slow_count = lats_ms.iter().filter(|&&ms| ms >= 250).count();
    let primary_dials = hung_accepts.load(Relaxed);
    eprintln!(
        "F3B_MEASURE_HUNG_EGRESS: p50={p50}ms p95={p95}ms slow_attempts={slow_count}/21 primary_dials={primary_dials}"
    );

    // After escalation on >=2 distinct DCs (2 and 4), primary node 0 MUST be in node-level cooldown!
    {
        let h = st.egress_health.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            h.nodes[0].until.is_some(),
            "hung egress must escalate to node-level cooldown after >=2 distinct DC ACK timeouts"
        );
    }
    // Structurally, primary was dialed only for the first 2 distinct DCs (plus at most 1 probe), not all 21!
    assert!(
        (2..=3).contains(&primary_dials),
        "after escalation primary must only be dialed 2..=3 times out of 21, got {primary_dials}"
    );
    assert!(
        slow_count <= 3,
        "after escalation only <=3 attempts should pay per_try (got {slow_count}/21, p50={p50}ms, p95={p95}ms)"
    );

    // Scenario 2: one slow DC (DC 2) on a healthy node (DC 4 responds OK) -> stays DC-level, node NOT cooled down.
    let l_partial = TcpListener::bind("127.0.0.1:0").await?;
    let a_partial = l_partial.local_addr()?;
    let t_partial = tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l_partial.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 88];
                if s.read_exact(&mut buf).await.is_ok() {
                    let dc = i16::from_le_bytes([buf[4], buf[5]]);
                    if dc == 2 {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    } else {
                        let _ = s.write_all(&[EGRESS_ACK_OK]).await;
                        let mut drain = [0u8; 16];
                        let _ = timeout(Duration::from_secs(2), s.read(&mut drain)).await;
                    }
                }
            });
        }
    });

    let mut st2 = state(cover.addr, "127.0.0.1:1".parse()?);
    {
        let sm = Arc::get_mut(&mut st2).context("unique state")?;
        sm.egress_upstreams = vec![a_partial.into(), a_ok.into()];
        sm.egress_strategy = EgressStrategy::Ordered;
        sm.egress_health = std::sync::Mutex::new(EgressHealth::new(2));
        sm.egress_hedge_ms = 0;
        sm.egress_cooldown = Duration::from_secs(10);
        sm.egress_cooldown_max = Duration::from_secs(60);
        sm.egress_use_mtv3 = false;
        sm.handshake = Duration::from_secs(4);
    }
    for _ in 0..4 {
        EgressHealth::record_ack_latency(&st2.egress_health, 0, Duration::from_millis(10));
    }
    // One isolated ACK timeout on DC 2 fails over to backup, cooling down only (node 0, DC 2).
    let (s_dc2, _) = connect_upstream(&st2, 2, &[0x22; 64]).await?;
    drop(s_dc2);
    {
        let h2 = st2.egress_health.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            h2.nodes[0].until.is_none(),
            "single DC timeout must not cool down whole node"
        );
        assert!(h2.dc_slots.get(&(0, 2)).and_then(|s| s.until).is_some());
    }
    // DC 4 on the SAME primary node 0 succeeds immediately without touching backup!
    let (s_dc4, _) = connect_upstream(&st2, 4, &[0x33; 64]).await?;
    drop(s_dc4);

    stop_ok.store(true, Relaxed);
    let _ = std::net::TcpStream::connect(a_ok);
    let _ = ok_thread.join();
    for t in [t_hung, t_partial] {
        t.abort();
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inv10_f23_hung_egress_30_parallel_single_escalation_and_base_cooldown() -> Result<()> {
    use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
    let cover = cover_mock().await?;

    // Hung egress accepts all 30 TCP connections, reads full preface, never sends ACK.
    let l_hung = TcpListener::bind("127.0.0.1:0").await?;
    let a_hung = l_hung.local_addr()?;
    let in_flight = Arc::new(AtomicUsize::new(0));
    let all_ready = Arc::new(tokio::sync::Notify::new());
    let hold_open = Arc::new(tokio::sync::Notify::new());

    let inf_srv = in_flight.clone();
    let ar_srv = all_ready.clone();
    let ho_srv = hold_open.clone();
    let t_hung = tokio::spawn(async move {
        for _ in 0..30usize {
            let Ok((mut s, _)) = l_hung.accept().await else {
                break;
            };
            let inf = inf_srv.clone();
            let ar = ar_srv.clone();
            let ho = ho_srv.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 88];
                if s.read_exact(&mut buf).await.is_ok() {
                    if inf.fetch_add(1, Relaxed) + 1 == 30 {
                        ar.notify_one();
                    }
                    ho.notified().await;
                    drop(s);
                }
            });
        }
    });

    let base_cd = Duration::from_secs(3);
    let mut st = state(cover.addr, "127.0.0.1:1".parse()?);
    {
        let sm = Arc::get_mut(&mut st).context("unique state")?;
        sm.egress_upstreams = vec![a_hung.into()];
        sm.egress_strategy = EgressStrategy::Ordered;
        sm.egress_health = std::sync::Mutex::new(EgressHealth::new(1));
        sm.egress_cooldown = base_cd;
        sm.egress_cooldown_max = Duration::from_secs(60);
        sm.egress_use_mtv3 = false;
        sm.handshake = Duration::from_secs(10);
    }

    let dcs: [i16; 7] = [2, 4, -2, -4, 1, 3, 5];
    let before_spawn = Instant::now();
    let mut joins = Vec::with_capacity(30);
    for i in 0..30usize {
        let st_c = st.clone();
        let dc = dcs[i % dcs.len()];
        joins.push(tokio::spawn(async move {
            let Some(claim) = EgressHealth::try_claim(&st_c.egress_health, 0, dc, Instant::now())
            else {
                return Err(anyhow::anyhow!(
                    "node 0 must be claimable before first timeout"
                ));
            };
            let res = dial_egress_candidate(
                &st_c,
                0,
                dc,
                dc.abs(),
                connect::EgressDialMode::DirectStream(&[0x11; 64]),
                Duration::from_millis(500),
            )
            .await;
            let Err(err) = res else {
                return Err(anyhow::anyhow!("all 30 attempts to hung egress must fail"));
            };
            let _ = finalize_egress_error(&st_c, 0, claim, err);
            Ok(())
        }));
    }

    // Confirm all 30 attempts started and wrote preface BEFORE the first 500ms timeout fires.
    all_ready.notified().await;
    assert_eq!(in_flight.load(Relaxed), 30);

    for j in joins {
        j.await??;
    }
    let after_joins = Instant::now();
    hold_open.notify_waiters();
    t_hung.abort();

    let h = st.egress_health.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(
        h.nodes[0].failures, 1,
        "30 concurrent hung-egress attempts must trigger exactly ONE escalation (failures == 1)"
    );
    let until = h.nodes[0].until.context("node 0 must be in cooldown")?;
    // Escalation fired between before_spawn + 500ms and after_joins; cooldown is base_cd (3s ± 20% = [2400ms, 3600ms]).
    let min_assigned = until.saturating_duration_since(after_joins);
    let max_assigned = until.saturating_duration_since(before_spawn + Duration::from_millis(500));
    assert!(
        max_assigned >= Duration::from_millis(2350) && min_assigned <= Duration::from_millis(3650),
        "assigned cooldown must equal base ±20% jitter (min={min_assigned:?}, max={max_assigned:?})"
    );
    Ok(())
}

#[tokio::test]
async fn live_cover_stays_open_past_double_handshake_after_first_reply_and_closes_with_fin(
) -> Result<()> {
    let cover_listener = TcpListener::bind("127.0.0.1:0").await?;
    let cover_addr = cover_listener.local_addr()?;
    let cover_srv = tokio::spawn(async move {
        if let Ok((mut s, _)) = cover_listener.accept().await {
            let mut req1 = [0u8; 4];
            if s.read_exact(&mut req1).await.is_ok() {
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\n\r\n1").await;
            }
            let mut req2 = [0u8; 4];
            if s.read_exact(&mut req2).await.is_ok() {
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\n\r\n2").await;
            }
            let _ = s.shutdown().await;
        }
    });

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let mut st = state(cover_addr, closed_port().await?);
    {
        let sm = Arc::get_mut(&mut st).context("unique state")?;
        sm.cover_permits = Semaphore::new(1);
        sm.client_hello = Duration::from_millis(40);
        sm.handshake = Duration::from_millis(120);
        sm.idle = Duration::from_secs(2);
    }
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let srv = tokio::spawn(serve(listener, st.clone(), 8, async move {
        let _ = stop_rx.await;
    }));

    let mut probe = TcpStream::connect(addr).await?;
    probe.write_all(b"GET1").await?;
    let mut reply1 = [0u8; 20];
    timeout(Duration::from_secs(1), probe.read_exact(&mut reply1)).await??;
    assert_eq!(&reply1, b"HTTP/1.1 200 OK\r\n\r\n1");

    // While the first live cover session is kept alive, an excess unauthenticated
    // connection queues briefly (>0 ms) and closes cleanly with FIN (Ok(0)), not RST.
    let mut excess = TcpStream::connect(addr).await?;
    excess.write_all(b"GETX").await?;
    let t_excess = Instant::now();
    let mut eof_buf = [0u8; 1];
    let n_eof = timeout(Duration::from_secs(1), excess.read(&mut eof_buf)).await??;
    assert_eq!(n_eof, 0, "rejected cover connection must close with FIN");
    assert!(
        t_excess.elapsed() >= Duration::from_millis(20),
        "rejected cover connection must wait briefly in queue rather than snapping shut at 0 ms"
    );

    // Hold past 2 * handshake (240 ms) and verify the keep-alive cover connection still works.
    tokio::time::sleep(Duration::from_millis(320)).await;
    probe.write_all(b"GET2").await?;
    let mut reply2 = [0u8; 20];
    timeout(Duration::from_secs(1), probe.read_exact(&mut reply2)).await??;
    assert_eq!(&reply2, b"HTTP/1.1 200 OK\r\n\r\n2");
    probe.shutdown().await?;

    let _ = stop_tx.send(());
    timeout(Duration::from_secs(2), srv).await???;
    let _ = cover_srv.await;
    Ok(())
}

#[tokio::test]
async fn graceful_drain_closes_active_relay_session_with_fin_and_zero_forced_close() -> Result<()> {
    let cover = cover_mock().await?;
    let dc_listener = TcpListener::bind("127.0.0.1:0").await?;
    let dc_addr = dc_listener.local_addr()?;
    let dc_srv = tokio::spawn(async move {
        if let Ok((mut s, _)) = dc_listener.accept().await {
            let mut hdr = [0u8; 64];
            let _ = s.read_exact(&mut hdr).await;
            let mut buf = [0u8; 64];
            let _ = timeout(Duration::from_secs(5), s.read(&mut buf)).await;
        }
    });

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let mut st = state(cover.addr, dc_addr);
    {
        let sm = Arc::get_mut(&mut st).context("unique state")?;
        sm.idle = Duration::from_secs(30);
        sm.drain = Duration::from_millis(600);
    }
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let srv = tokio::spawn(serve(listener, st.clone(), 16, async move {
        let _ = stop_rx.await;
    }));

    let mut client = TcpStream::connect(addr).await?;
    let raw = hello()?;
    client.write_all(&raw).await?;
    flight(&mut client, &raw).await?;
    client
        .write_all(&wire::record(0x17, &fixture("init")?)?)
        .await?;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Trigger server drain while the authenticated relay session is idle.
    let _ = stop_tx.send(());
    let mut eof = [0u8; 1];
    let n = timeout(Duration::from_secs(1), client.read(&mut eof)).await??;
    assert_eq!(
        n, 0,
        "draining server must send clean TCP FIN to active client"
    );
    client.shutdown().await?;

    timeout(Duration::from_secs(2), srv).await???;
    assert_eq!(
        st.counters
            .forced_close
            .load(std::sync::atomic::Ordering::Relaxed),
        0,
        "cooperative FIN drain must complete without forced_close"
    );
    let _ = dc_srv.await;
    Ok(())
}
