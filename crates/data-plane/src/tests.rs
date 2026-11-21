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

fn state(cover: SocketAddr, dc: SocketAddr) -> Arc<State> {
    Arc::new(State {
        secrets: std::sync::RwLock::new(Arc::new(vec![NamedSecret {
            name: "default".into(),
            key: Zeroizing::new(secret()),
        }])),
        sni: "example.com".into(),
        allowed_snis: std::sync::RwLock::new(Arc::new("example.com".into())),
        cover: cover.to_string(),
        enable_dd: false,
        proxy_protocol: false,
        cover_permits: Semaphore::new(8),
        dcs: HashMap::from([(2, dc)]),
        egress_upstreams: Vec::new(),
        egress_strategy: EgressStrategy::RoundRobin,
        egress_token: [0u8; 16],
        egress_rr: std::sync::atomic::AtomicUsize::new(0),
        egress_health: std::sync::Mutex::new(EgressHealth::new(0)),
        egress_cooldown: Duration::from_secs(15),
        client_hello: Duration::from_millis(150),
        handshake: Duration::from_millis(150),
        idle: Duration::from_millis(300),
        drain: Duration::from_millis(20),
        flight: wire::ServerFlightProfile::default(),
        flight_shaping: false,
        client_mss_bulk: None,
        replay: Mutex::new(ReplayCache::new(65536, Duration::from_secs(300))),
        counters: Arc::new(telemetry::Counters::default()),
        alert_webhook_url: None,
        alerts_file: None,
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
    state_mut.egress_upstreams = vec![bad_egress_addr, egress_addr];
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
    state_mut.egress_upstreams = vec![stalled_addr, egress_addr];
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
        dc: vec![format!("2={dc_addr}")],
        egress_upstreams: Vec::new(),
        egress_strategy: EgressStrategy::RoundRobin,
        egress_token_file: None,
        max_connections: 16,
        client_hello_timeout_secs: 2,
        handshake_timeout_secs: 2,
        idle_timeout_secs: 5,
        drain_timeout_secs: 1,
        fake_tls_cert_bytes: wire::DEFAULT_CERT_BYTES,
        fake_tls_cert_jitter: 0,
        flight_shaping: false,
        client_mss: None,
        client_mss_bulk: None,
        alert_webhook_url: None,
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
        sm.egress_upstreams = vec![primary_addr, backup_addr];
        sm.egress_strategy = EgressStrategy::Ordered;
        sm.egress_token = token;
        sm.egress_health = std::sync::Mutex::new(EgressHealth::new(2));
        sm.egress_cooldown = Duration::from_millis(350);
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
        sm.egress_upstreams = vec![egress_addr];
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
    write_runtime_stats_atomic(&stats_file, &edge_state.counters, "edge")?;
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
        dc: vec![format!("2={dc_addr}")],
        egress_upstreams: Vec::new(),
        egress_strategy: EgressStrategy::RoundRobin,
        egress_token_file: None,
        max_connections: 16,
        client_hello_timeout_secs: 2,
        handshake_timeout_secs: 2,
        idle_timeout_secs: 5,
        drain_timeout_secs: 1,
        fake_tls_cert_bytes: wire::DEFAULT_CERT_BYTES,
        fake_tls_cert_jitter: 0,
        flight_shaping: false,
        client_mss: None,
        client_mss_bulk: None,
        alert_webhook_url: None,
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
    inner.egress_upstreams = vec![primary_addr, backup_addr];
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
        sm.egress_upstreams = vec![primary_addr, backup_addr];
        sm.egress_strategy = EgressStrategy::Ordered;
        sm.egress_token = token;
        sm.egress_health = std::sync::Mutex::new(EgressHealth::new(2));
        sm.egress_cooldown = Duration::from_millis(200);
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
        sm.egress_upstreams = vec![addr1, addr2];
        sm.egress_strategy = EgressStrategy::RoundRobin;
        sm.egress_token = token;
        sm.egress_health = std::sync::Mutex::new(EgressHealth::new(2));
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

    // 4. Both nodes recover -> after both nodes handle traffic, emits primary_ok (all recovered).
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
        dc: vec![format!("2={dc_addr}")],
        egress_upstreams: Vec::new(),
        egress_strategy: EgressStrategy::RoundRobin,
        egress_token_file: None,
        max_connections: 16,
        client_hello_timeout_secs: 2,
        handshake_timeout_secs: 2,
        idle_timeout_secs: 5,
        drain_timeout_secs: 1,
        fake_tls_cert_bytes: wire::DEFAULT_CERT_BYTES,
        fake_tls_cert_jitter: 0,
        flight_shaping: false,
        client_mss: None,
        client_mss_bulk: None,
        alert_webhook_url: None,
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
