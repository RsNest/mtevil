use super::*;

#[derive(Clone)]
pub(crate) struct EgressSecurityConfig {
    pub(crate) accept_legacy: bool,
    pub(crate) allow_from: Vec<config::IpCidr>,
    pub(crate) max_failed_per_ip: usize,
    pub(crate) failed_window: Duration,
    pub(crate) max_unauth_handshakes: usize,
    pub(crate) dc_media_overrides: HashMap<i16, Vec<SocketAddr>>,
}

impl EgressSecurityConfig {
    #[cfg(test)]
    pub(crate) fn default_for(max_connections: usize) -> Self {
        Self {
            accept_legacy: true,
            allow_from: Vec::new(),
            max_failed_per_ip: config::default_egress_max_failed_per_ip(),
            failed_window: Duration::from_secs(60),
            max_unauth_handshakes: (max_connections / 4).clamp(4, 128),
            dc_media_overrides: default_media_override_map(),
        }
    }

    pub(crate) fn allows_ip(&self, ip: std::net::IpAddr) -> bool {
        self.allow_from.is_empty() || self.allow_from.iter().any(|cidr| cidr.contains(ip))
    }
}

pub(crate) struct IpFailureTracker {
    pub(crate) entries: HashMap<std::net::IpAddr, std::collections::VecDeque<Instant>>,
    pub(crate) window: Duration,
    pub(crate) max_failed: usize,
}

impl IpFailureTracker {
    pub(crate) fn new(window: Duration, max_failed: usize) -> Self {
        Self {
            entries: HashMap::new(),
            window,
            max_failed,
        }
    }

    pub(crate) fn prune(&mut self, now: Instant) {
        let window = self.window;
        self.entries.retain(|_, q| {
            while let Some(&front) = q.front() {
                if now.duration_since(front) >= window {
                    q.pop_front();
                } else {
                    break;
                }
            }
            !q.is_empty()
        });
    }

    pub(crate) fn is_rate_limited(&mut self, ip: std::net::IpAddr, now: Instant) -> bool {
        let window = self.window;
        if let Some(q) = self.entries.get_mut(&ip) {
            while let Some(&front) = q.front() {
                if now.duration_since(front) >= window {
                    q.pop_front();
                } else {
                    break;
                }
            }
            return q.len() >= self.max_failed;
        }
        false
    }

    pub(crate) fn record_failure(&mut self, ip: std::net::IpAddr, now: Instant) {
        if self.entries.len() >= 4096 {
            self.prune(now);
        }
        if self.entries.len() >= 4096 && !self.entries.contains_key(&ip) {
            return;
        }
        let window = self.window;
        let q = self.entries.entry(ip).or_default();
        while let Some(&front) = q.front() {
            if now.duration_since(front) >= window {
                q.pop_front();
            } else {
                break;
            }
        }
        if q.len() < self.max_failed.saturating_add(1) {
            q.push_back(now);
        }
    }
}

pub(crate) struct EgressRuntimeSecurity {
    pub(crate) cfg: EgressSecurityConfig,
    pub(crate) unauth_permits: Semaphore,
    pub(crate) nonce_replay: Mutex<ReplayCache>,
    pub(crate) failed_by_ip: std::sync::Mutex<IpFailureTracker>,
}

impl EgressRuntimeSecurity {
    pub(crate) fn new(cfg: EgressSecurityConfig) -> Self {
        let max_unauth = cfg.max_unauth_handshakes.max(1);
        let failed_tracker = IpFailureTracker::new(cfg.failed_window, cfg.max_failed_per_ip);
        Self {
            cfg,
            unauth_permits: Semaphore::new(max_unauth),
            nonce_replay: Mutex::new(ReplayCache::new(16384, Duration::from_secs(65))),
            failed_by_ip: std::sync::Mutex::new(failed_tracker),
        }
    }

    pub(crate) fn check_peer_allowed(&self, ip: std::net::IpAddr) -> Result<()> {
        ensure!(
            self.cfg.allows_ip(ip),
            "egress source IP not in egress_allow_from"
        );
        let mut tracker = self.failed_by_ip.lock().unwrap_or_else(|e| e.into_inner());
        ensure!(
            !tracker.is_rate_limited(ip, Instant::now()),
            "egress source IP rate-limited due to failed handshakes"
        );
        Ok(())
    }

    pub(crate) fn record_auth_failure(&self, ip: std::net::IpAddr) {
        let mut tracker = self.failed_by_ip.lock().unwrap_or_else(|e| e.into_inner());
        tracker.record_failure(ip, Instant::now());
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve_egress(
    listener: impl Acceptor,
    dcs: Arc<HashMap<i16, SocketAddr>>,
    egress_token: [u8; 16],
    max_connections: usize,
    handshake: Duration,
    idle: Duration,
    drain: Duration,
    counters: Arc<telemetry::Counters>,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    serve_egress_with_security(
        listener,
        dcs,
        egress_token,
        max_connections,
        handshake,
        idle,
        drain,
        counters,
        EgressSecurityConfig::default_for(max_connections),
        shutdown,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve_egress_with_security(
    mut listener: impl Acceptor,
    dcs: Arc<HashMap<i16, SocketAddr>>,
    egress_token: [u8; 16],
    max_connections: usize,
    handshake: Duration,
    idle: Duration,
    drain: Duration,
    counters: Arc<telemetry::Counters>,
    security: EgressSecurityConfig,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    let permits = Arc::new(Semaphore::new(max_connections));
    let runtime_sec = Arc::new(EgressRuntimeSecurity::new(security));
    let mut tasks = tokio::task::JoinSet::new();
    let mut accept_state = AcceptLoopState::default();
    tokio::pin!(shutdown);
    loop {
        while tasks.try_join_next().is_some() {}
        let permit = tokio::select! {
            permit = permits.clone().acquire_owned() => permit?,
            _ = &mut shutdown => break,
        };
        let accepted = tokio::select! {
            accepted = listener.accept_conn() => accepted,
            _ = &mut shutdown => break,
        };
        let (mut edge, peer_addr) = match accept_state
            .handle_result(accepted, &counters, &mut shutdown)
            .await?
        {
            AcceptDecision::Accepted(pair) => pair,
            AcceptDecision::Retry => continue,
            AcceptDecision::Shutdown => break,
        };
        let dcs = dcs.clone();
        let counters = counters.clone();
        let runtime_sec = runtime_sec.clone();
        tasks.spawn(async move {
            let _permit = permit;
            let mut session = telemetry::Session::new(&counters);
            let res = egress_connection(
                &mut edge,
                peer_addr.ip(),
                &dcs,
                &egress_token,
                handshake,
                idle,
                &counters,
                &runtime_sec,
            )
            .await;
            session.finish(&res);
        });
    }
    drop(listener);
    if timeout(drain, async { while tasks.join_next().await.is_some() {} })
        .await
        .is_err()
    {
        let remaining = tasks.len() as u64;
        if remaining > 0 {
            counters
                .forced_close
                .fetch_add(remaining, std::sync::atomic::Ordering::Relaxed);
        }
        tasks.shutdown().await;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn egress_connection(
    edge: &mut TcpStream,
    peer_ip: std::net::IpAddr,
    dcs: &HashMap<i16, SocketAddr>,
    expected_token: &[u8; 16],
    handshake: Duration,
    idle: Duration,
    counters: &telemetry::Counters,
    security: &EgressRuntimeSecurity,
) -> Result<()> {
    use std::sync::atomic::Ordering::Relaxed;
    security.check_peer_allowed(peer_ip)?;
    let Ok(unauth_permit) = security.unauth_permits.try_acquire() else {
        bail!("egress unauthenticated handshake limit reached");
    };
    configure_tcp_socket(edge)?;
    let mut magic = [0u8; 4];
    if let Err(err) = timeout(handshake, edge.read_exact(&mut magic))
        .await
        .context("egress_header_timeout")
        .and_then(|r| r.context("egress_header_eof"))
    {
        security.record_auth_failure(peer_ip);
        return Err(err);
    }
    counters
        .downstream_rx_bytes
        .fetch_add(magic.len() as u64, Relaxed);

    let (raw_dc_id, mtv3_dc_header) = if magic == wire::EGRESS_MAGIC_V3 {
        let mut rest = [0u8; wire::EGRESS_PREFACE_V3_LEN - 4];
        if let Err(err) = timeout(handshake, edge.read_exact(&mut rest))
            .await
            .context("egress_v3_header_timeout")
            .and_then(|r| r.context("egress_v3_header_eof"))
        {
            security.record_auth_failure(peer_ip);
            return Err(err);
        }
        counters
            .downstream_rx_bytes
            .fetch_add(rest.len() as u64, Relaxed);
        let mut full = [0u8; wire::EGRESS_PREFACE_V3_LEN];
        full[..4].copy_from_slice(&magic);
        full[4..].copy_from_slice(&rest);
        let now_secs = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let parsed = match wire::verify_egress_preface_v3(
            &full,
            expected_token,
            now_secs,
            wire::EGRESS_V3_MAX_SKEW_SECS,
        ) {
            Ok(p) => p,
            Err(err) => {
                security.record_auth_failure(peer_ip);
                return Err(err);
            }
        };
        let mut replay_key = [0u8; 32];
        replay_key[..8].copy_from_slice(&parsed.timestamp.to_le_bytes());
        replay_key[8..24].copy_from_slice(&parsed.nonce);
        replay_key[24..26].copy_from_slice(&parsed.dc.to_le_bytes());
        let decision = security
            .nonce_replay
            .lock()
            .await
            .check_and_insert(replay_key, Instant::now());
        if decision != Decision::Fresh {
            security.record_auth_failure(peer_ip);
            bail!("egress MTV3 nonce replay detected");
        }
        counters.egress_mtv3_connections.fetch_add(1, Relaxed);
        (parsed.dc, Some(parsed.dc_header))
    } else if magic == wire::EGRESS_MAGIC_V2 {
        if !security.cfg.accept_legacy {
            security.record_auth_failure(peer_ip);
            bail!("egress legacy MTV2 disabled");
        }
        let mut rest = [0u8; 20];
        if let Err(err) = timeout(handshake, edge.read_exact(&mut rest))
            .await
            .context("egress_v2_header_timeout")
            .and_then(|r| r.context("egress_v2_header_eof"))
        {
            security.record_auth_failure(peer_ip);
            return Err(err);
        }
        counters
            .downstream_rx_bytes
            .fetch_add(rest.len() as u64, Relaxed);
        let token: [u8; 16] = rest[4..20].try_into()?;
        if !ct_eq_16(&token, expected_token) {
            security.record_auth_failure(peer_ip);
            bail!("egress token mismatch");
        }
        let dc_id = i16::from_le_bytes([rest[0], rest[1]]);
        counters.egress_legacy_connections.fetch_add(1, Relaxed);
        (dc_id, None)
    } else {
        security.record_auth_failure(peer_ip);
        bail!("invalid egress magic");
    };
    drop(unauth_permit);

    if raw_dc_id == 0 {
        if mtv3_dc_header.is_none() {
            let mut tail = [0u8; 64];
            timeout(handshake, edge.read_exact(&mut tail))
                .await
                .context("egress_ping_tail_timeout")?
                .context("egress_ping_tail_eof")?;
            counters
                .downstream_rx_bytes
                .fetch_add(tail.len() as u64, Relaxed);
        }
        timeout(handshake, edge.write_all(&[EGRESS_ACK_OK])).await??;
        counters.downstream_tx_bytes.fetch_add(1, Relaxed);
        let _ = edge.shutdown().await;
        return Ok(());
    }
    let seq = counters.active.load(Relaxed) as usize;
    let candidates =
        lookup_dc_candidates_with_overrides(dcs, &security.cfg.dc_media_overrides, raw_dc_id, seq);
    if candidates.is_empty() {
        if edge.write_all(&[EGRESS_ACK_ERR]).await.is_ok() {
            counters.downstream_tx_bytes.fetch_add(1, Relaxed);
        }
        let _ = edge.shutdown().await;
        bail!("DC not configured on egress");
    }
    let mut dc = match connect_dc_candidates(&candidates, handshake).await {
        Ok(stream) => stream,
        Err(_) => {
            if edge.write_all(&[EGRESS_ACK_ERR]).await.is_ok() {
                counters.downstream_tx_bytes.fetch_add(1, Relaxed);
            }
            let _ = edge.shutdown().await;
            bail!("dc_connect_failed");
        }
    };
    if let Some(dc_hdr) = mtv3_dc_header {
        if timeout(handshake, dc.write_all(&dc_hdr))
            .await
            .map_err(anyhow::Error::from)
            .and_then(|r| r.map_err(anyhow::Error::from))
            .is_err()
        {
            if edge.write_all(&[EGRESS_ACK_ERR]).await.is_ok() {
                counters.downstream_tx_bytes.fetch_add(1, Relaxed);
            }
            let _ = edge.shutdown().await;
            bail!("dc_header_write_failed");
        }
        counters
            .upstream_tx_bytes
            .fetch_add(dc_hdr.len() as u64, Relaxed);
    }
    timeout(handshake, edge.write_all(&[EGRESS_ACK_OK])).await??;
    counters.downstream_tx_bytes.fetch_add(1, Relaxed);
    let edge_fd = stream_raw_fd(edge);
    let dc_fd = stream_raw_fd(&dc);
    let (er, ew) = edge.split();
    let (dr, dw) = dc.split();
    tokio::try_join!(
        counted_copy(
            er,
            dw,
            idle,
            &counters.downstream_rx_bytes,
            &counters.upstream_tx_bytes,
            dc_fd,
            &counters.upstream_retrans_segs,
        ),
        counted_copy(
            dr,
            ew,
            idle,
            &counters.upstream_rx_bytes,
            &counters.downstream_tx_bytes,
            edge_fd,
            &counters.downstream_retrans_segs,
        ),
    )?;
    Ok(())
}
