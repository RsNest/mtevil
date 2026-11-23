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

pub(crate) async fn cover(client: &mut TcpStream, raw: Vec<u8>, state: &State) -> Result<()> {
    let candidates = state.cover_resolver.candidate_addrs();
    anyhow::ensure!(!candidates.is_empty(), "cover_dns_unavailable");

    let deadline = Instant::now() + state.handshake;
    let mut upstream_opt = None;
    let mut last_err: Option<anyhow::Error> = None;

    for addr in candidates {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        if remaining.is_zero() {
            break;
        }
        match timeout(remaining, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                upstream_opt = Some(stream);
                break;
            }
            Ok(Err(err)) => {
                if addr.is_ipv6() && !addr.ip().is_loopback() && is_ipv6_route_error(&err) {
                    state.cover_resolver.mark_ipv6_unreachable();
                }
                last_err = Some(err.into());
            }
            Err(elapsed) => {
                last_err = Some(elapsed.into());
                break;
            }
        }
    }

    let mut upstream = match upstream_opt {
        Some(s) => s,
        None => {
            return Err(
                last_err.unwrap_or_else(|| anyhow::anyhow!("cover_connect_budget_exhausted"))
            );
        }
    };

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
}
