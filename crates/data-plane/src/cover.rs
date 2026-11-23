use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Probe whether the kernel has a default IPv6 route without sending network packets.
pub(crate) fn probe_ipv6_route() -> bool {
    let Ok(sock) = std::net::UdpSocket::bind("[::]:0") else {
        return false;
    };
    sock.connect("[2001:4860:4860::8888]:443").is_ok()
}

pub(crate) struct CoverResolver {
    pub(crate) target: String,
    pub(crate) ttl: Duration,
    pub(crate) cached: std::sync::RwLock<Option<(Vec<SocketAddr>, Instant)>>,
    pub(crate) rr: AtomicUsize,
    pub(crate) ipv6_available: AtomicBool,
}

impl CoverResolver {
    pub(crate) fn new(target: String, ttl: Duration) -> Self {
        Self::with_ipv6_support(target, ttl, probe_ipv6_route())
    }

    pub(crate) fn with_ipv6_support(target: String, ttl: Duration, ipv6_available: bool) -> Self {
        let initial = target
            .parse::<SocketAddr>()
            .ok()
            .map(|addr| (vec![addr], Instant::now()));
        Self {
            target,
            ttl,
            cached: std::sync::RwLock::new(initial),
            rr: AtomicUsize::new(0),
            ipv6_available: AtomicBool::new(ipv6_available),
        }
    }

    pub(crate) fn is_static_ip(&self) -> bool {
        self.target.parse::<SocketAddr>().is_ok()
    }

    pub(crate) fn mark_ipv6_unreachable(&self) {
        self.ipv6_available.store(false, Ordering::Relaxed);
    }

    pub(crate) fn update_addrs(&self, addrs: Vec<SocketAddr>) {
        if !addrs.is_empty() {
            *self.cached.write().unwrap_or_else(|e| e.into_inner()) = Some((addrs, Instant::now()));
        }
    }

    pub(crate) fn has_cached(&self) -> bool {
        self.cached
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .is_some_and(|(v, _)| !v.is_empty())
    }

    /// Return candidate socket addresses rotated by round-robin, filtering out
    /// non-loopback IPv6 addresses when no IPv6 route is available and IPv4 exists.
    pub(crate) fn candidate_addrs(&self) -> Vec<SocketAddr> {
        let guard = self.cached.read().unwrap_or_else(|e| e.into_inner());
        let Some((addrs, _)) = guard.as_ref() else {
            return Vec::new();
        };
        if addrs.is_empty() {
            return Vec::new();
        }
        let ipv6_ok = self.ipv6_available.load(Ordering::Relaxed);
        let mut filtered: Vec<SocketAddr> = if ipv6_ok {
            addrs.clone()
        } else {
            let v4_or_loopback: Vec<SocketAddr> = addrs
                .iter()
                .copied()
                .filter(|a| a.is_ipv4() || a.ip().is_loopback())
                .collect();
            if v4_or_loopback.is_empty() {
                addrs.clone()
            } else {
                v4_or_loopback
            }
        };
        if filtered.len() > 1 {
            let start = self.rr.fetch_add(1, Ordering::Relaxed) % filtered.len();
            filtered.rotate_left(start);
        }
        filtered
    }

    #[cfg(test)]
    pub(crate) fn next_addr(&self) -> Option<SocketAddr> {
        self.candidate_addrs().into_iter().next()
    }

    pub(crate) async fn refresh_with<F, Fut>(
        &self,
        dns_timeout: Duration,
        counters: &telemetry::Counters,
        resolve_fn: F,
    ) -> bool
    where
        F: FnOnce(String) -> Fut,
        Fut: std::future::Future<Output = std::io::Result<Vec<SocketAddr>>>,
    {
        if self.is_static_ip() {
            return true;
        }
        match timeout(dns_timeout, resolve_fn(self.target.clone())).await {
            Ok(Ok(addrs)) if !addrs.is_empty() => {
                self.update_addrs(addrs);
                true
            }
            outcome => {
                counters.cover_dns_fail.fetch_add(1, Ordering::Relaxed);
                let reason = match outcome {
                    Ok(Ok(_)) => "empty_dns_result".to_string(),
                    Ok(Err(err)) => format!("dns_error: {err}"),
                    Err(_) => "dns_timeout".to_string(),
                };
                telemetry::event(
                    "cover_dns_fail",
                    0,
                    json!({
                        "reason": reason,
                        "has_last_known_good": self.has_cached(),
                    }),
                );
                false
            }
        }
    }

    pub(crate) async fn refresh_once(
        &self,
        dns_timeout: Duration,
        counters: &telemetry::Counters,
    ) -> bool {
        self.refresh_with(dns_timeout, counters, |target| async move {
            let iter = tokio::net::lookup_host(target).await?;
            Ok(iter.collect::<Vec<_>>())
        })
        .await
    }
}

pub(crate) fn spawn_cover_resolver(
    resolver: Arc<CoverResolver>,
    counters: Arc<telemetry::Counters>,
    dns_timeout: Duration,
    mut stop_rx: tokio::sync::oneshot::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let wait = if resolver.has_cached() {
                resolver.ttl
            } else {
                resolver.ttl.min(Duration::from_secs(5))
            };
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = &mut stop_rx => break,
            }
            let _ = resolver.refresh_once(dns_timeout, &counters).await;
        }
    })
}

pub(crate) async fn bounded_cover(
    client: &mut TcpStream,
    raw: Vec<u8>,
    state: &State,
    session_id: u64,
) -> Result<()> {
    // An HTTPS fallback must not queue while holding a slot from the shared listener.
    let Ok(_permit) = state.cover_permits.try_acquire() else {
        state
            .counters
            .cover_rejected
            .fetch_add(1, Ordering::Relaxed);
        telemetry::event("cover_rejected", session_id, json!({"reason":"capacity"}));
        return Ok(());
    };
    // Unauthenticated fallback must not reserve admission slots for the full
    // authenticated-session idle timeout, especially after a partial hello.
    timeout(state.handshake.saturating_mul(2), cover(client, raw, state))
        .await
        .context("cover_budget_expired")?
}

fn is_ipv6_route_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::NetworkUnreachable
            | std::io::ErrorKind::HostUnreachable
            | std::io::ErrorKind::AddrNotAvailable
    ) || matches!(err.raw_os_error(), Some(101 | 113 | 99))
}

pub(crate) async fn connect_cover_stream(
    resolver: &CoverResolver,
    budget: Duration,
) -> Result<TcpStream> {
    let candidates = resolver.candidate_addrs();
    anyhow::ensure!(!candidates.is_empty(), "cover_dns_unavailable");

    let deadline = Instant::now() + budget;
    let mut last_err: Option<anyhow::Error> = None;

    for addr in candidates {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        if remaining.is_zero() {
            break;
        }
        match timeout(remaining, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(err)) => {
                if addr.is_ipv6() && !addr.ip().is_loopback() && is_ipv6_route_error(&err) {
                    resolver.mark_ipv6_unreachable();
                }
                last_err = Some(err.into());
            }
            Err(elapsed) => {
                last_err = Some(elapsed.into());
                break;
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("cover_connect_budget_exhausted")))
}

pub(crate) async fn cover(client: &mut TcpStream, raw: Vec<u8>, state: &State) -> Result<()> {
    let mut upstream = connect_cover_stream(&state.cover_resolver, state.handshake).await?;

    // INV-01: first backend write commits cover; never reconsider the protocol.
    timeout(state.handshake, upstream.write_all(&raw)).await??;
    let (cr, cw) = client.split();
    let (ur, uw) = upstream.split();
    tokio::try_join!(
        plain_copy(cr, uw, state.idle),
        plain_copy(ur, cw, state.idle)
    )?;
    Ok(())
}

const COVER_CALIBRATION_INTERVAL: Duration = Duration::from_secs(86_400);
const CALIBRATION_MAX_BYTES: usize = 65_536;
const CALIBRATION_IDLE_WAIT: Duration = Duration::from_millis(250);

fn push_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn push_ext(out: &mut Vec<u8>, ext_type: u16, body: &[u8]) {
    push_u16(out, ext_type);
    push_u16(out, body.len() as u16);
    out.extend_from_slice(body);
}

/// Build a minimal standards-compliant TLS 1.3 ClientHello for `sni` to probe
/// the real `cover` server's initial ServerHello flight size.
fn build_calibration_client_hello(sni: &str) -> Vec<u8> {
    use rand::RngCore;
    let mut rng = rand::rngs::OsRng;
    let mut random = [0u8; 32];
    let mut session_id = [0u8; 32];
    rng.fill_bytes(&mut random);
    rng.fill_bytes(&mut session_id);
    let key_share_pub = mtevil_proto::x25519::generate_public_key(&mut rng);

    let mut exts = Vec::with_capacity(160);
    if !sni.is_empty() && sni.len() <= 253 {
        let mut sni_ext = Vec::with_capacity(5 + sni.len());
        push_u16(&mut sni_ext, (3 + sni.len()) as u16);
        sni_ext.push(0x00); // host_name
        push_u16(&mut sni_ext, sni.len() as u16);
        sni_ext.extend_from_slice(sni.as_bytes());
        push_ext(&mut exts, 0x0000, &sni_ext);
    }
    // supported_groups: x25519 (0x001d), secp256r1 (0x0017)
    push_ext(&mut exts, 0x000a, &[0x00, 0x04, 0x00, 0x1d, 0x00, 0x17]);
    // ec_point_formats: uncompressed
    push_ext(&mut exts, 0x000b, &[0x01, 0x00]);
    // signature_algorithms: ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, rsa_pkcs1_sha256
    push_ext(
        &mut exts,
        0x000d,
        &[0x00, 0x06, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01],
    );
    // alpn: h2, http/1.1
    push_ext(&mut exts, 0x0010, b"\x00\x0c\x02h2\x08http/1.1");
    // supported_versions: TLS 1.3 (0x0304), TLS 1.2 (0x0303)
    push_ext(&mut exts, 0x002b, &[0x04, 0x03, 0x04, 0x03, 0x03]);
    // key_share: x25519 (0x001d, 32 bytes)
    let mut ks = Vec::with_capacity(38);
    push_u16(&mut ks, 36);
    push_u16(&mut ks, 0x001d);
    push_u16(&mut ks, 32);
    ks.extend_from_slice(&key_share_pub);
    push_ext(&mut exts, 0x0033, &ks);

    let mut body = Vec::with_capacity(72 + exts.len());
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
    body.extend_from_slice(&random);
    body.push(32);
    body.extend_from_slice(&session_id);
    // cipher suites: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256
    push_u16(&mut body, 6);
    push_u16(&mut body, 0x1301);
    push_u16(&mut body, 0x1302);
    push_u16(&mut body, 0x1303);
    // compression_methods: null
    body.extend_from_slice(&[0x01, 0x00]);
    push_u16(&mut body, exts.len() as u16);
    body.extend_from_slice(&exts);

    let hs_len = body.len();
    let rec_len = 4 + hs_len;
    let mut out = Vec::with_capacity(5 + rec_len);
    out.push(0x16);
    out.extend_from_slice(&[0x03, 0x01]);
    push_u16(&mut out, rec_len as u16);
    out.push(0x01); // ClientHello
    out.push(((hs_len >> 16) & 0xff) as u8);
    push_u16(&mut out, (hs_len & 0xffff) as u16);
    out.extend_from_slice(&body);
    out
}

/// Perform one bounded TLS handshake probe against `cover` and return the
/// calibrated `cert_bytes` clamped to `MIN_CERT_BYTES..=MAX_CERT_BYTES`.
pub(crate) async fn measure_cover_flight_cert_bytes(
    resolver: &CoverResolver,
    sni: &str,
    budget: Duration,
) -> Result<usize> {
    let deadline = Instant::now() + budget;
    let mut stream = connect_cover_stream(resolver, budget).await?;
    let hello = build_calibration_client_hello(sni);
    let rem = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| anyhow::anyhow!("cover_calibration_timeout"))?;
    timeout(rem, stream.write_all(&hello)).await??;

    let mut saw_server_hello = false;
    let mut appdata_bytes: usize = 0;
    let mut post_sh_handshake_bytes: usize = 0;
    let mut total_bytes: usize = 0;

    while let Some(rem) = deadline.checked_duration_since(Instant::now()) {
        let wait = if appdata_bytes > 0 {
            rem.min(CALIBRATION_IDLE_WAIT)
        } else {
            rem
        };
        let mut hdr = [0u8; 5];
        match timeout(wait, stream.read_exact(&mut hdr)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => break,
        }
        let rec_type = hdr[0];
        let rec_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        anyhow::ensure!(rec_len <= 16_384 + 256, "cover_tls_record_too_large");
        total_bytes = total_bytes.saturating_add(5 + rec_len);
        anyhow::ensure!(
            total_bytes <= CALIBRATION_MAX_BYTES,
            "cover_tls_flight_exceeds_budget"
        );

        let mut payload = vec![0u8; rec_len];
        let Some(rem_body) = deadline.checked_duration_since(Instant::now()) else {
            anyhow::bail!("cover_calibration_timeout");
        };
        timeout(rem_body, stream.read_exact(&mut payload)).await??;

        match rec_type {
            0x16 => {
                if !saw_server_hello {
                    saw_server_hello = true;
                } else {
                    post_sh_handshake_bytes = post_sh_handshake_bytes.saturating_add(rec_len);
                }
            }
            0x14 => {} // ChangeCipherSpec
            0x17 => {
                appdata_bytes = appdata_bytes.saturating_add(rec_len);
            }
            0x15 => anyhow::bail!("cover_tls_alert_received"),
            _ => break,
        }
    }

    anyhow::ensure!(saw_server_hello, "cover_missing_server_hello");
    let measured = if appdata_bytes > 0 {
        appdata_bytes
    } else {
        post_sh_handshake_bytes
    };
    anyhow::ensure!(measured > 0, "cover_empty_server_flight");
    Ok(measured.clamp(mtevil_proto::MIN_CERT_BYTES, mtevil_proto::MAX_CERT_BYTES))
}

pub(crate) async fn calibrate_cover_once(
    resolver: &CoverResolver,
    sni: &str,
    budget: Duration,
    flight_cert_bytes: &AtomicUsize,
) -> bool {
    match measure_cover_flight_cert_bytes(resolver, sni, budget).await {
        Ok(cert_bytes) => {
            flight_cert_bytes.store(cert_bytes, Ordering::Relaxed);
            telemetry::event(
                "cover_calibrated",
                0,
                json!({
                    "cover": resolver.target,
                    "sni": sni,
                    "cert_bytes": cert_bytes,
                }),
            );
            true
        }
        Err(err) => {
            telemetry::event(
                "cover_calibration_failed",
                0,
                json!({
                    "cover": resolver.target,
                    "sni": sni,
                    "kept_cert_bytes": flight_cert_bytes.load(Ordering::Relaxed),
                    "reason": format!("{err:#}"),
                }),
            );
            false
        }
    }
}

pub(crate) fn spawn_cover_calibrator(
    resolver: Arc<CoverResolver>,
    sni: String,
    budget: Duration,
    flight_cert_bytes: Arc<AtomicUsize>,
    mut stop_rx: tokio::sync::oneshot::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let _ = calibrate_cover_once(&resolver, &sni, budget, &flight_cert_bytes).await;
        loop {
            tokio::select! {
                _ = tokio::time::sleep(COVER_CALIBRATION_INTERVAL) => {}
                _ = &mut stop_rx => break,
            }
            let _ = calibrate_cover_once(&resolver, &sni, budget, &flight_cert_bytes).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn cover_resolver_filters_non_loopback_ipv6_when_route_unavailable() {
        let resolver = CoverResolver::with_ipv6_support(
            "example.com:443".into(),
            Duration::from_secs(60),
            false,
        );
        let v4_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 66, 147, 243)), 443);
        let v4_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(104, 20, 23, 154)), 443);
        let v6_a = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1)),
            443,
        );
        let v6_b = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 2)),
            443,
        );
        resolver.update_addrs(vec![v6_a, v4_a, v6_b, v4_b]);

        for _ in 0..1000 {
            let picked = resolver.next_addr();
            assert!(
                picked == Some(v4_a) || picked == Some(v4_b),
                "unexpected IPv6 pick when route is unavailable: {picked:?}"
            );
        }
    }

    #[tokio::test]
    async fn cover_fails_over_to_second_address_when_first_refuses() -> Result<()> {
        let dead_listener = TcpListener::bind("127.0.0.1:0").await?;
        let dead_addr = dead_listener.local_addr()?;
        drop(dead_listener);

        let live_listener = TcpListener::bind("127.0.0.1:0").await?;
        let live_addr = live_listener.local_addr()?;
        let srv_task = tokio::spawn(async move {
            if let Ok((mut s, _)) = live_listener.accept().await {
                let mut buf = [0u8; 32];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let _ = s.write_all(&buf[..n]).await;
                let _ = s.shutdown().await;
            }
        });

        let client_listener = TcpListener::bind("127.0.0.1:0").await?;
        let client_addr = client_listener.local_addr()?;
        let client_task = tokio::spawn(async move {
            let mut c = TcpStream::connect(client_addr).await?;
            let mut reply = Vec::new();
            c.read_to_end(&mut reply).await?;
            Ok::<_, anyhow::Error>(reply)
        });
        let (mut server_side_client, _) = client_listener.accept().await?;

        let mut st = crate::tests::state(live_addr, "127.0.0.1:1".parse()?);
        if let Some(s) = Arc::get_mut(&mut st) {
            // Windows loopback RST arrives after ~2s; ensure handshake budget covers failover.
            s.handshake = Duration::from_secs(5);
        }
        st.cover_resolver.mark_ipv6_unreachable();
        st.cover_resolver.update_addrs(vec![dead_addr, live_addr]);

        cover(&mut server_side_client, b"GET / HTTP/1.1\r\n".to_vec(), &st).await?;
        drop(server_side_client);

        let reply = client_task.await??;
        assert_eq!(reply, b"GET / HTTP/1.1\r\n");
        let _ = srv_task.await;
        Ok(())
    }

    #[tokio::test]
    async fn calibrate_cover_once_updates_cert_bytes_from_mock_tls_flight() -> Result<()> {
        let srv = TcpListener::bind("127.0.0.1:0").await?;
        let addr = srv.local_addr()?;
        let srv_task = tokio::spawn(async move {
            let (mut s, _) = srv.accept().await?;
            let mut hdr = [0u8; 5];
            s.read_exact(&mut hdr).await?;
            anyhow::ensure!(hdr[0] == 0x16, "expected TLS ClientHello record");
            let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
            let mut body = vec![0u8; len];
            s.read_exact(&mut body).await?;

            // Send ServerHello (122B) + ChangeCipherSpec (1B) + AppData (4320B)
            let mut flight = Vec::new();
            flight.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 122]);
            flight.extend_from_slice(&[0xaa; 122]);
            flight.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 1, 0x01]);
            flight.extend_from_slice(&[0x17, 0x03, 0x03]);
            flight.extend_from_slice(&4320u16.to_be_bytes());
            flight.extend_from_slice(&[0xbb; 4320]);
            s.write_all(&flight).await?;
            let _ = s.shutdown().await;
            Ok::<_, anyhow::Error>(())
        });

        let resolver =
            CoverResolver::with_ipv6_support(addr.to_string(), Duration::from_secs(60), false);
        resolver.update_addrs(vec![addr]);
        let cert_bytes = AtomicUsize::new(mtevil_proto::DEFAULT_CERT_BYTES);
        let ok = calibrate_cover_once(
            &resolver,
            "mozilla.org",
            Duration::from_secs(3),
            &cert_bytes,
        )
        .await;
        assert!(ok);
        assert_eq!(cert_bytes.load(Ordering::Relaxed), 4320);
        srv_task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn calibrate_cover_once_preserves_lkg_on_failure() -> Result<()> {
        let dead = TcpListener::bind("127.0.0.1:0").await?;
        let dead_addr = dead.local_addr()?;
        drop(dead);

        let resolver =
            CoverResolver::with_ipv6_support(dead_addr.to_string(), Duration::from_secs(60), false);
        resolver.update_addrs(vec![dead_addr]);
        let cert_bytes = AtomicUsize::new(4111);
        let ok = calibrate_cover_once(
            &resolver,
            "mozilla.org",
            Duration::from_secs(2),
            &cert_bytes,
        )
        .await;
        assert!(!ok);
        assert_eq!(cert_bytes.load(Ordering::Relaxed), 4111);
        Ok(())
    }
}
