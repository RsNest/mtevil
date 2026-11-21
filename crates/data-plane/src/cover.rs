use super::*;

pub(crate) struct CoverResolver {
    pub(crate) target: String,
    pub(crate) ttl: Duration,
    pub(crate) cached: std::sync::RwLock<Option<(Vec<SocketAddr>, Instant)>>,
    pub(crate) rr: std::sync::atomic::AtomicUsize,
}

impl CoverResolver {
    pub(crate) fn new(target: String, ttl: Duration) -> Self {
        let initial = target
            .parse::<SocketAddr>()
            .ok()
            .map(|addr| (vec![addr], Instant::now()));
        Self {
            target,
            ttl,
            cached: std::sync::RwLock::new(initial),
            rr: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub(crate) fn is_static_ip(&self) -> bool {
        self.target.parse::<SocketAddr>().is_ok()
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

    pub(crate) fn next_addr(&self) -> Option<SocketAddr> {
        let guard = self.cached.read().unwrap_or_else(|e| e.into_inner());
        let (addrs, _) = guard.as_ref()?;
        if addrs.is_empty() {
            return None;
        }
        let idx = self.rr.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % addrs.len();
        Some(addrs[idx])
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
                counters
                    .cover_dns_fail
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        telemetry::event("cover_rejected", session_id, json!({"reason":"capacity"}));
        return Ok(());
    };
    // Unauthenticated fallback must not reserve admission slots for the full
    // authenticated-session idle timeout, especially after a partial hello.
    timeout(state.handshake.saturating_mul(2), cover(client, raw, state))
        .await
        .context("cover_budget_expired")?
}

pub(crate) async fn cover(client: &mut TcpStream, raw: Vec<u8>, state: &State) -> Result<()> {
    let addr = state
        .cover_resolver
        .next_addr()
        .context("cover_dns_unavailable")?;
    let mut upstream = timeout(state.handshake, TcpStream::connect(addr)).await??;
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
