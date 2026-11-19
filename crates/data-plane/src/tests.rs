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
        secrets: vec![NamedSecret {
            name: "default".into(),
            key: Zeroizing::new(secret()),
        }],
        sni: "example.com".into(),
        cover: cover.to_string(),
        enable_dd: false,
        proxy_protocol: false,
        cover_permits: Semaphore::new(8),
        dcs: HashMap::from([(2, dc)]),
        egress_upstreams: Vec::new(),
        egress_strategy: EgressStrategy::RoundRobin,
        egress_token: [0u8; 16],
        egress_rr: std::sync::atomic::AtomicUsize::new(0),
        client_hello: Duration::from_millis(150),
        handshake: Duration::from_millis(150),
        idle: Duration::from_millis(300),
        drain: Duration::from_millis(20),
        flight: wire::ServerFlightProfile::default(),
        flight_shaping: false,
        client_mss_bulk: None,
        replay: Mutex::new(ReplayCache::new(65536, Duration::from_secs(300))),
        counters: telemetry::Counters::default(),
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
    assert_eq!(timeout(Duration::from_secs(1), client.read(&mut [0u8])).await??, 0);
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
    state_mut.secrets = vec![
        NamedSecret {
            name: "other".into(),
            key: Zeroizing::new([0x11u8; 16]),
        },
        NamedSecret {
            name: "alice".into(),
            key: Zeroizing::new(secret()),
        },
    ];
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
