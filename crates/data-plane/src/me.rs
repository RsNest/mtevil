//! Telegram Middle-End (ME) runtime manager, config refresher, hot-reloading `ad_tag`,
//! and client-to-ME framed relay for `direct` mode (ADR-002 Phase 2).
use super::*;
use mtevil_me_pool::{
    MeConfigBundle, MeConnOptions, MeDiskCache, MeInboundEvent, MePool, MePoolConfig, MeSession,
};
use rand::{Rng, RngCore};
use std::net::{IpAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;
use tokio::time::Instant;

const MAX_ME_FETCH_BYTES: usize = 256 * 1024;
const ME_FETCH_TIMEOUT: Duration = Duration::from_secs(15);
const ME_FALLBACK_EVENT_PERIOD: Duration = Duration::from_secs(60);
const ME_REFRESH_BACKOFF_MIN: Duration = Duration::from_secs(30);
const ME_REFRESH_BACKOFF_MAX: Duration = Duration::from_secs(600);

#[derive(Clone, Debug, Default)]
pub struct MeTelemetrySnapshot {
    pub enabled: bool,
    pub fallback_to_direct: bool,
    pub degraded: bool,
    pub alive_connections: usize,
    pub total_slots: usize,
    pub configured_dcs: usize,
    pub config_age_secs: Option<u64>,
    pub backpressure_drops: u64,
    pub dropped_close_ext: u64,
    pub ad_tag_configured: bool,
}

pub(crate) struct MeRuntime {
    cfg: config::MeConfig,
    cache: MeDiskCache,
    pool: Mutex<Option<MePool>>,
    ad_tag: RwLock<Option<[u8; 16]>>,
    ad_tag_mtime: Mutex<Option<SystemTime>>,
    last_config_updated_unix: AtomicU64,
    fallback_event_state: Mutex<(Option<Instant>, u64)>,
    counters: Arc<telemetry::Counters>,
    shutdown_tx: watch::Sender<bool>,
    stopped: AtomicBool,
}

impl MeRuntime {
    pub(crate) async fn start(
        cfg: config::MeConfig,
        default_cache_dir: PathBuf,
        counters: Arc<telemetry::Counters>,
    ) -> Arc<Self> {
        Self::start_with_backoff(
            cfg,
            default_cache_dir,
            counters,
            ME_REFRESH_BACKOFF_MIN,
            ME_REFRESH_BACKOFF_MAX,
        )
        .await
    }

    pub(crate) async fn start_with_backoff(
        cfg: config::MeConfig,
        default_cache_dir: PathBuf,
        counters: Arc<telemetry::Counters>,
        backoff_min: Duration,
        backoff_max: Duration,
    ) -> Arc<Self> {
        let cache_dir = cfg.cache_dir.clone().unwrap_or(default_cache_dir);
        let cache = MeDiskCache::new(cache_dir);
        let initial_tag = cfg
            .ad_tag_file
            .as_deref()
            .and_then(|p| read_ad_tag_with_mtime(p).ok());
        let (ad_tag_val, ad_tag_mtime) = match initial_tag {
            Some((tag, mtime)) => (tag, mtime),
            None => (None, None),
        };
        let (shutdown_tx, _) = watch::channel(false);

        let rt = Arc::new(Self {
            cfg: cfg.clone(),
            cache,
            pool: Mutex::new(None),
            ad_tag: RwLock::new(ad_tag_val),
            ad_tag_mtime: Mutex::new(ad_tag_mtime),
            last_config_updated_unix: AtomicU64::new(0),
            fallback_event_state: Mutex::new((None, 0)),
            counters,
            shutdown_tx,
            stopped: AtomicBool::new(false),
        });

        // Initial load: try remote fetch first, fall back to LKG disk cache, never crash-loop.
        match rt.fetch_and_save_bundle().await {
            Ok(bundle) => {
                rt.install_bundle(bundle);
                telemetry::event(
                    "me_config_loaded",
                    0,
                    json!({
                        "source": "remote",
                        "ad_tag": if rt.current_ad_tag().is_some() { "configured" } else { "disabled" },
                        "send_client_ip": rt.cfg.send_client_ip,
                        "fallback_to_direct": rt.cfg.fallback_to_direct,
                    }),
                );
            }
            Err(err) => {
                rt.counters
                    .me_refresh_errors
                    .fetch_add(1, Ordering::Relaxed);
                match rt.cache.load() {
                    Ok(lkg) => {
                        rt.install_bundle(lkg);
                        telemetry::event(
                            "me_config_loaded",
                            0,
                            json!({
                                "source": "lkg_cache",
                                "fetch_error": format!("{err:#}"),
                                "fallback_to_direct": rt.cfg.fallback_to_direct,
                            }),
                        );
                    }
                    Err(cache_err) => {
                        telemetry::event(
                            "me_startup_degraded",
                            0,
                            json!({
                                "fetch_error": format!("{err:#}"),
                                "cache_error": format!("{cache_err:#}"),
                                "fallback_to_direct": rt.cfg.fallback_to_direct,
                            }),
                        );
                    }
                }
            }
        }

        // Background refresh task: periodic refresh on success, exponential backoff on failure.
        let rt_bg = rt.clone();
        let mut stop_rx = rt.shutdown_tx.subscribe();
        tokio::spawn(async move {
            let mut failures: u32 = if rt_bg.has_pool() { 0 } else { 1 };
            let refresh_interval = Duration::from_secs(rt_bg.cfg.refresh_interval_secs.max(1));
            loop {
                let wait = if failures == 0 {
                    refresh_interval
                } else {
                    mtevil_egress::compute_egress_cooldown(backoff_min, backoff_max, failures)
                };
                let stopped = tokio::select! {
                    biased;
                    _ = stop_rx.wait_for(|&s| s) => true,
                    () = tokio::time::sleep(wait) => false,
                };
                if stopped || rt_bg.stopped.load(Ordering::Relaxed) {
                    break;
                }
                match rt_bg.fetch_and_save_bundle().await {
                    Ok(bundle) => {
                        failures = 0;
                        rt_bg.install_bundle(bundle);
                        telemetry::event("me_config_refreshed", 0, json!({"status": "ok"}));
                    }
                    Err(err) => {
                        failures = failures.saturating_add(1);
                        rt_bg
                            .counters
                            .me_refresh_errors
                            .fetch_add(1, Ordering::Relaxed);
                        telemetry::event(
                            "me_config_refresh_failed",
                            0,
                            json!({
                                "failures": failures,
                                "error": format!("{err:#}"),
                            }),
                        );
                    }
                }
            }
        });

        // Hot-reload `ad_tag_file` every 2 seconds without restart.
        if rt.cfg.ad_tag_file.is_some() {
            let rt_tag = rt.clone();
            let mut stop_rx_tag = rt.shutdown_tx.subscribe();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(2));
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                ticker.tick().await;
                loop {
                    tokio::select! {
                        biased;
                        _ = stop_rx_tag.wait_for(|&s| s) => break,
                        _ = ticker.tick() => {}
                    }
                    rt_tag.reload_ad_tag_if_changed();
                }
            });
        }

        rt
    }

    pub(crate) fn reload_ad_tag_if_changed(&self) {
        let Some(ref path) = self.cfg.ad_tag_file else {
            return;
        };
        if !path.exists() {
            let had_tag = {
                let mut w = self.ad_tag.write().unwrap_or_else(|e| e.into_inner());
                w.take().is_some()
            };
            if had_tag {
                let mut mt = self.ad_tag_mtime.lock().unwrap_or_else(|e| e.into_inner());
                *mt = None;
                telemetry::event("me_ad_tag_reloaded", 0, json!({"status": "disabled"}));
            }
            return;
        }
        let cur_mtime = std::fs::metadata(path).ok().and_then(|m| m.modified().ok());
        {
            let prev_mtime = self.ad_tag_mtime.lock().unwrap_or_else(|e| e.into_inner());
            if cur_mtime.is_some() && *prev_mtime == cur_mtime {
                return;
            }
        }
        match read_ad_tag_with_mtime(path) {
            Ok((tag, mtime)) => {
                {
                    let mut w = self.ad_tag.write().unwrap_or_else(|e| e.into_inner());
                    *w = tag;
                }
                {
                    let mut mt = self.ad_tag_mtime.lock().unwrap_or_else(|e| e.into_inner());
                    *mt = mtime;
                }
                telemetry::event(
                    "me_ad_tag_reloaded",
                    0,
                    json!({"status": if tag.is_some() { "configured" } else { "disabled" }}),
                );
            }
            Err(err) => {
                telemetry::event(
                    "me_ad_tag_reload_failed",
                    0,
                    json!({"error": format!("{err:#}")}),
                );
            }
        }
    }

    async fn fetch_and_save_bundle(&self) -> Result<MeConfigBundle> {
        let secret_bytes = fetch_url_bounded(&self.cfg.proxy_secret_url).await?;
        let conf_bytes = fetch_url_bounded(&self.cfg.proxy_config_url).await?;
        let conf_text =
            String::from_utf8(conf_bytes).context("proxy-multi.conf is not valid UTF-8")?;
        // Validate & atomically persist LKG cache (corrupted response never overwrites LKG).
        self.cache.save_validated(&secret_bytes, &conf_text)
    }

    fn install_bundle(&self, bundle: MeConfigBundle) {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.last_config_updated_unix
            .store(now_unix, Ordering::Relaxed);
        let pool_cfg = MePoolConfig {
            conns_per_dc: self.cfg.pool_size,
            drain_timeout: Duration::from_secs(self.cfg.drain_timeout_secs),
            conn_opts: MeConnOptions {
                public_ipv4: self.cfg.public_ipv4,
                ..MeConnOptions::default()
            },
            ..MePoolConfig::default()
        };
        let mut guard = self.pool.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some(existing) => existing.update_config(bundle),
            None => *guard = Some(MePool::start(bundle, pool_cfg)),
        }
    }

    fn has_pool(&self) -> bool {
        self.pool
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }

    pub(crate) fn current_ad_tag(&self) -> Option<[u8; 16]> {
        *self.ad_tag.read().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn fallback_to_direct(&self) -> bool {
        self.cfg.fallback_to_direct
    }

    pub(crate) fn send_client_ip(&self) -> bool {
        self.cfg.send_client_ip
    }

    pub(crate) fn open_session(
        &self,
        dc_id: i16,
        remote_addr: Option<SocketAddrV4>,
    ) -> Result<MeSession> {
        let pool = {
            let guard = self.pool.lock().unwrap_or_else(|e| e.into_inner());
            guard
                .clone()
                .ok_or_else(|| anyhow::anyhow!("ME pool not initialized yet"))?
        };
        let ad_tag = self.current_ad_tag();
        pool.open_session(dc_id, remote_addr, ad_tag)
    }

    pub(crate) fn record_fallback_to_direct(&self, session_id: u64, dc_id: i16, reason: &str) {
        self.counters
            .me_fallback_direct_total
            .fetch_add(1, Ordering::Relaxed);
        let now = Instant::now();
        let emit = {
            let mut st = self
                .fallback_event_state
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            match st.0 {
                Some(last) if now.duration_since(last) < ME_FALLBACK_EVENT_PERIOD => {
                    st.1 = st.1.saturating_add(1);
                    None
                }
                _ => {
                    let suppressed = st.1;
                    st.0 = Some(now);
                    st.1 = 0;
                    Some(suppressed)
                }
            }
        };
        if let Some(suppressed) = emit {
            telemetry::event(
                "me_fallback_direct",
                session_id,
                json!({
                    "dc": dc_id,
                    "reason": reason,
                    "suppressed": suppressed,
                }),
            );
        }
    }

    pub(crate) fn telemetry_snapshot(&self) -> MeTelemetrySnapshot {
        let pool_health = {
            let guard = self.pool.lock().unwrap_or_else(|e| e.into_inner());
            guard.as_ref().map(MePool::health)
        };
        let last_unix = self.last_config_updated_unix.load(Ordering::Relaxed);
        let config_age_secs = if last_unix == 0 {
            None
        } else {
            let now_unix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(last_unix);
            Some(now_unix.saturating_sub(last_unix))
        };
        let ad_tag_configured = self.current_ad_tag().is_some();
        match pool_health {
            Some(h) => MeTelemetrySnapshot {
                enabled: true,
                fallback_to_direct: self.cfg.fallback_to_direct,
                degraded: h.degraded,
                alive_connections: h.alive_connections,
                total_slots: h.total_slots,
                configured_dcs: h.configured_dcs,
                config_age_secs,
                backpressure_drops: h.backpressure_drops,
                dropped_close_ext: h.dropped_close_ext,
                ad_tag_configured,
            },
            None => MeTelemetrySnapshot {
                enabled: true,
                fallback_to_direct: self.cfg.fallback_to_direct,
                degraded: true,
                alive_connections: 0,
                total_slots: 0,
                configured_dcs: 0,
                config_age_secs,
                backpressure_drops: 0,
                dropped_close_ext: 0,
                ad_tag_configured,
            },
        }
    }

    pub(crate) fn shutdown(&self) {
        self.stopped.store(true, Ordering::Relaxed);
        let _ = self.shutdown_tx.send(true);
        let mut guard = self.pool.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(pool) = guard.take() {
            pool.shutdown();
        }
    }
}

fn read_ad_tag_with_mtime(path: &Path) -> Result<(Option<[u8; 16]>, Option<SystemTime>)> {
    let mtime = std::fs::metadata(path).ok().and_then(|m| m.modified().ok());
    let tag = config::load_ad_tag_file(path)?;
    Ok((tag, mtime))
}

/// Extract IPv4 peer address (normalizing IPv4-mapped IPv6) for `RPC_PROXY_REQ`.
/// Never logged or persisted.
pub(crate) fn extract_client_ipv4(addr: Option<SocketAddr>) -> Option<SocketAddrV4> {
    let sa = addr?;
    match sa.ip() {
        IpAddr::V4(v4) => Some(SocketAddrV4::new(v4, sa.port())),
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(|v4| SocketAddrV4::new(v4, sa.port())),
    }
}

/// Fetch `http://` (native bounded async TCP) or `https://` (system `curl` with TLS 1.2+ CA verify)
/// with strict size bound (`MAX_ME_FETCH_BYTES`) and timeout (`ME_FETCH_TIMEOUT`).
pub(crate) async fn fetch_url_bounded(url: &str) -> Result<Vec<u8>> {
    config::validate_me_config_url(url)?;
    if let Some(rest) = url.strip_prefix("http://") {
        fetch_http_plain_bounded(rest).await
    } else if url.starts_with("https://") {
        fetch_https_via_curl_bounded(url).await
    } else {
        anyhow::bail!("unsupported ME config URL scheme");
    }
}

async fn fetch_http_plain_bounded(rest: &str) -> Result<Vec<u8>> {
    let (host_port, path) = match rest.find('/') {
        Some(pos) => (&rest[..pos], &rest[pos..]),
        None => (rest, "/"),
    };
    let mut stream = timeout(ME_FETCH_TIMEOUT, TcpStream::connect(host_port))
        .await
        .context("ME config HTTP connect timeout")?
        .context("ME config HTTP connect failed")?;
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host_port}\r\nUser-Agent: mtevil\r\nConnection: close\r\n\r\n"
    );
    timeout(ME_FETCH_TIMEOUT, stream.write_all(req.as_bytes()))
        .await
        .context("ME config HTTP write timeout")?
        .context("ME config HTTP write failed")?;

    let mut raw = Vec::with_capacity(4096);
    let mut buf = [0u8; 4096];
    let max_raw = MAX_ME_FETCH_BYTES + 16 * 1024;
    timeout(ME_FETCH_TIMEOUT, async {
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            ensure!(
                raw.len().saturating_add(n) <= max_raw,
                "ME config HTTP response exceeds bound"
            );
            raw.extend_from_slice(&buf[..n]);
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("ME config HTTP read timeout")??;

    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("malformed HTTP response header"))?;
    let header_str = std::str::from_utf8(&raw[..sep]).context("non-UTF8 HTTP response header")?;
    let status_line = header_str.lines().next().unwrap_or("");
    let code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    ensure!(code == 200, "ME config HTTP returned status {code}");
    let body = raw[sep + 4..].to_vec();
    ensure!(
        body.len() <= MAX_ME_FETCH_BYTES,
        "ME config body exceeds {MAX_ME_FETCH_BYTES} bytes"
    );
    Ok(body)
}

async fn fetch_https_via_curl_bounded(url: &str) -> Result<Vec<u8>> {
    let output = timeout(
        ME_FETCH_TIMEOUT,
        tokio::process::Command::new("curl")
            .args([
                "-fsSL",
                "--max-time",
                "12",
                "--max-filesize",
                &MAX_ME_FETCH_BYTES.to_string(),
                "--proto",
                "=https",
                "--tlsv1.2",
                url,
            ])
            .output(),
    )
    .await
    .context("ME config HTTPS fetch timeout")?
    .context("spawning curl for ME config HTTPS fetch")?;
    ensure!(
        output.status.success(),
        "ME config HTTPS fetch failed with status {}",
        output.status
    );
    ensure!(
        output.stdout.len() <= MAX_ME_FETCH_BYTES,
        "ME config HTTPS body exceeds {MAX_ME_FETCH_BYTES} bytes"
    );
    Ok(output.stdout)
}

/// Relay one authenticated client session over a multiplexed `MeSession`.
/// Strictly post-ServerHello (INV-01: no cover fallback; INV-03: bounded queues & timeouts;
/// INV-08: bounded frame lengths before allocation).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay_me_session(
    client: &mut TcpStream,
    state: &State,
    session_id: u64,
    t0: Instant,
    user: String,
    transport: wire::ClientTransport,
    tls: Option<TlsReader>,
    hello_read_us: u64,
    flight_written_us: Option<u64>,
    diag: HelloDiag,
    me_session: MeSession,
    ad_tag_configured: bool,
) -> Result<()> {
    struct MeActiveGuard(Arc<telemetry::Counters>);
    impl Drop for MeActiveGuard {
        fn drop(&mut self) {
            self.0.me_active_sessions.fetch_sub(1, Ordering::Relaxed);
        }
    }
    state
        .counters
        .me_active_sessions
        .fetch_add(1, Ordering::Relaxed);
    let _me_guard = MeActiveGuard(state.counters.clone());

    let us = || t0.elapsed().as_micros() as u64;
    let framed = tls.is_some();
    let kind = transport.kind;
    let mut client_decrypt = transport.decrypt;
    let mut client_encrypt = transport.encrypt;

    telemetry::event(
        "authenticated",
        session_id,
        json!({
            "user": user,
            "dc": transport.dc,
            "route": "me",
            "transport": kind.as_str(),
            "mode": if framed { "ee" } else { "dd" },
            "ad_tag": if ad_tag_configured { "configured" } else { "disabled" },
            "hello_read_us": hello_read_us,
            "flight_written_us": flight_written_us,
            "inner_header_us": us(),
            "client_hello_bytes": diag.client_hello_bytes,
            "client_hello_records": diag.client_hello_records,
            "record_version": diag.record_version,
            "client_template": diag.client_template,
            "cipher_suite": diag.cipher_suite,
            "flight_bytes": diag.flight_bytes,
            "fake_tls_cert_bytes": diag.fake_tls_cert_bytes,
        }),
    );

    let client_fd = stream_raw_fd(client);
    let (mut cr, mut cw) = client.split();
    let relay = RelayStats {
        counters: Some(state.counters.clone()),
        client_fd,
        upstream_fd: None,
        diagnostics: state.diagnostics,
        ..RelayStats::default()
    };
    let relay_start_us = us();

    let (mut me_rx_sess, me_tx_sess) = split_me_session_handles(me_session);
    let max_dec_buf = wire::MAX_MTPROTO_FRAME_LEN + 64;

    let result = relay_until_end(
        &relay,
        state.idle,
        async {
            let mut tls = tls;
            let mut raw = [0u8; 16 * 1024];
            let mut dec_buf = Vec::with_capacity(16 * 1024);
            loop {
                let n = match tls.as_mut() {
                    Some(reader) => reader.read_into(&mut cr, &mut raw).await?,
                    None => cr.read(&mut raw).await?,
                };
                if n == 0 {
                    break;
                }
                relay.uploaded.fetch_add(n as u64, Ordering::Relaxed);
                relay.client_reads.fetch_add(1, Ordering::Relaxed);
                relay.stamp(&relay.first_up_us, &relay.last_up_us);
                if let Some(c) = &relay.counters {
                    c.downstream_rx_bytes.fetch_add(n as u64, Ordering::Relaxed);
                }
                let chunk = &mut raw[..n];
                wire::crypt(&mut client_decrypt, chunk);
                ensure!(
                    dec_buf.len().saturating_add(n) <= max_dec_buf,
                    "client ME decode buffer exceeded bound"
                );
                dec_buf.extend_from_slice(chunk);
                while let Some(frame) = wire::decode_client_frame(kind, &mut dec_buf)? {
                    let payload_len = frame.payload.len();
                    timeout(RELAY_WRITE_TIMEOUT, me_tx_sess.send_frame(&frame.payload))
                        .await
                        .context("me_upload_send_timeout")??;
                    relay.dc_writes.fetch_add(1, Ordering::Relaxed);
                    relay.stamp(&relay.first_up_us, &relay.last_up_us);
                    if let Some(c) = &relay.counters {
                        c.upstream_tx_bytes
                            .fetch_add(payload_len as u64, Ordering::Relaxed);
                    }
                }
            }
            me_tx_sess.close();
            Ok::<_, anyhow::Error>(())
        },
        async {
            while let Some(ev) = me_rx_sess.recv_event().await {
                match ev {
                    MeInboundEvent::Payload(payload) => {
                        if let Some(c) = &relay.counters {
                            c.upstream_rx_bytes
                                .fetch_add(payload.len() as u64, Ordering::Relaxed);
                        }
                        let mut pad = [0u8; 15];
                        let pad_len = if kind == wire::ClientProtoKind::PaddedIntermediate {
                            let n = rand::rngs::OsRng.gen_range(0..=15);
                            rand::rngs::OsRng.fill_bytes(&mut pad[..n]);
                            n
                        } else {
                            0
                        };
                        let mut encoded =
                            wire::encode_client_frame(kind, &payload, &pad[..pad_len])?;
                        wire::crypt(&mut client_encrypt, &mut encoded);
                        write_client_encrypted(
                            &mut cw,
                            &encoded,
                            framed,
                            RELAY_WRITE_TIMEOUT,
                            &relay,
                        )
                        .await?;
                    }
                    MeInboundEvent::QuickAck(confirm_key) => {
                        let mut ack = wire::encode_quick_ack(kind, confirm_key);
                        wire::crypt(&mut client_encrypt, &mut ack);
                        write_client_encrypted(&mut cw, &ack, framed, RELAY_WRITE_TIMEOUT, &relay)
                            .await?;
                    }
                }
            }
            let _ = timeout(RELAY_WRITE_TIMEOUT, cw.shutdown()).await;
            Ok::<_, anyhow::Error>(())
        },
    )
    .await;

    let mut summary = relay.summary();
    summary["relay_start_us"] = json!(relay_start_us);
    summary["elapsed_us"] = json!(us());
    summary["route"] = json!("me");
    summary["transport"] = json!(kind.as_str());
    match result {
        Ok(()) => {
            telemetry::event("relay_closed", session_id, summary);
            Ok(())
        }
        Err(err) => {
            summary["error"] = json!(format!("{err:#}"));
            telemetry::event("relay_failed", session_id, summary);
            Err(err)
        }
    }
}

/// Split a `MeSession` into an upload sender handle and download receiver handle
/// so upload and download futures can run concurrently inside `relay_until_end`.
fn split_me_session_handles(session: MeSession) -> (MeSessionRecv, MeSessionSend) {
    let (rx, tx) = session.into_split();
    (MeSessionRecv(rx), MeSessionSend(tx))
}

struct MeSessionRecv(mtevil_me_pool::MeSessionReceiver);
impl MeSessionRecv {
    async fn recv_event(&mut self) -> Option<MeInboundEvent> {
        self.0.recv_event().await
    }
}

struct MeSessionSend(mtevil_me_pool::MeSessionSender);
impl MeSessionSend {
    async fn send_frame(&self, payload: &[u8]) -> Result<()> {
        self.0.send_frame(payload).await
    }
    fn close(self) {
        self.0.close();
    }
}

async fn write_client_encrypted<W: tokio::io::AsyncWrite + Unpin>(
    cw: &mut W,
    data: &[u8],
    framed: bool,
    write_timeout: Duration,
    relay: &RelayStats,
) -> Result<()> {
    if !framed {
        timeout(write_timeout, cw.write_all(data))
            .await
            .context("me_download_write_timeout")?
            .context("me_download_write_failed")?;
        relay
            .downloaded
            .fetch_add(data.len() as u64, Ordering::Relaxed);
        relay.client_writes.fetch_add(1, Ordering::Relaxed);
        relay.stamp(&relay.first_dn_us, &relay.last_dn_us);
        if let Some(c) = &relay.counters {
            c.downstream_tx_bytes
                .fetch_add(data.len() as u64, Ordering::Relaxed);
        }
        return Ok(());
    }
    for chunk in data.chunks(wire::MAX_RECORD) {
        let rec = wire::record(0x17, chunk)?;
        timeout(write_timeout, cw.write_all(&rec))
            .await
            .context("me_download_tls_write_timeout")?
            .context("me_download_tls_write_failed")?;
        relay
            .downloaded
            .fetch_add(rec.len() as u64, Ordering::Relaxed);
        relay.client_writes.fetch_add(1, Ordering::Relaxed);
        relay.stamp(&relay.first_dn_us, &relay.last_dn_us);
        if let Some(c) = &relay.counters {
            c.downstream_tx_bytes
                .fetch_add(rec.len() as u64, Ordering::Relaxed);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mtevil_me_pool::{
        decode_rpc_frame, derive_me_aes_key_iv, encode_handshake, encode_nonce, pack_rpc_frame,
        parse_rpc_message, KdfPurpose, MeCbcDecryptor, MeCbcEncryptor, RpcMessage,
    };
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    const TEST_RPC_HANDSHAKE: u32 = 0x7682_eef5;
    const TEST_RPC_PROXY_REQ: u32 = 0x36ce_f1ee;
    const TEST_RPC_PROXY_ANS: u32 = 0x4403_da0d;
    const TEST_RPC_SIMPLE_ACK: u32 = 0x3bac_409b;
    const TEST_FLAG_HAS_AD_TAG: u32 = 0x08;

    struct TestMeObserved {
        remote_ip: [u8; 16],
        remote_port: u32,
        ad_tag: Option<[u8; 16]>,
    }

    struct TestMockMe {
        addr: SocketAddrV4,
        observed: Arc<Mutex<Vec<TestMeObserved>>>,
        send_quick_ack: Arc<AtomicBool>,
        drop_after_first_req: Arc<AtomicBool>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for TestMockMe {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn spawn_test_mock_me(secret: Vec<u8>) -> Result<TestMockMe> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let SocketAddr::V4(addr) = listener.local_addr()? else {
            anyhow::bail!("expected IPv4 listener");
        };
        let observed = Arc::new(Mutex::new(Vec::new()));
        let send_quick_ack = Arc::new(AtomicBool::new(false));
        let drop_after_first_req = Arc::new(AtomicBool::new(false));
        let obs_c = observed.clone();
        let qa_c = send_quick_ack.clone();
        let dr_c = drop_after_first_req.clone();

        let task = tokio::spawn(async move {
            loop {
                let Ok((mut s, peer)) = listener.accept().await else {
                    break;
                };
                let SocketAddr::V4(peer_v4) = peer else {
                    continue;
                };
                let secret = secret.clone();
                let obs = obs_c.clone();
                let qa = qa_c.clone();
                let dr = dr_c.clone();
                tokio::spawn(async move {
                    let mut pbuf = Vec::new();
                    let mut tmp = [0u8; 256];
                    let (seq, pay) = loop {
                        if let Ok(Some(f)) = decode_rpc_frame(&mut pbuf) {
                            break f;
                        }
                        let Ok(n) = s.read(&mut tmp).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        pbuf.extend_from_slice(&tmp[..n]);
                    };
                    if seq != -2 {
                        return;
                    }
                    let Ok(RpcMessage::Nonce {
                        key_selector,
                        ts,
                        nonce: clt_nonce,
                        ..
                    }) = parse_rpc_message(&pay)
                    else {
                        return;
                    };
                    let srv_nonce = [0x42; 16];
                    let Ok(resp) =
                        pack_rpc_frame(-2, &encode_nonce(key_selector, ts, &srv_nonce), false)
                    else {
                        return;
                    };
                    if s.write_all(&resp).await.is_err() {
                        return;
                    }
                    let (dk, div) = derive_me_aes_key_iv(
                        &srv_nonce,
                        &clt_nonce,
                        ts,
                        *addr.ip(),
                        peer_v4.port(),
                        KdfPurpose::Client,
                        *peer_v4.ip(),
                        addr.port(),
                        &secret,
                    );
                    let (ek, eiv) = derive_me_aes_key_iv(
                        &srv_nonce,
                        &clt_nonce,
                        ts,
                        *addr.ip(),
                        peer_v4.port(),
                        KdfPurpose::Server,
                        *peer_v4.ip(),
                        addr.port(),
                        &secret,
                    );
                    let mut dec = MeCbcDecryptor::new(&dk, &div);
                    let mut enc = MeCbcEncryptor::new(&ek, &eiv);
                    let mut ebuf = Vec::new();
                    let mut blk = [0u8; 16];
                    let mut next_seq: i32 = 0;
                    loop {
                        let (rseq, rpay) = loop {
                            if let Ok(Some(f)) = decode_rpc_frame(&mut ebuf) {
                                break f;
                            }
                            if s.read_exact(&mut blk).await.is_err()
                                || dec.decrypt_in_place(&mut blk).is_err()
                            {
                                return;
                            }
                            ebuf.extend_from_slice(&blk);
                        };
                        if rpay.len() < 4 {
                            return;
                        }
                        let op = u32::from_le_bytes([rpay[0], rpay[1], rpay[2], rpay[3]]);
                        if op == TEST_RPC_HANDSHAKE && rseq == -1 {
                            let Ok(mut f) =
                                pack_rpc_frame(-1, &encode_handshake(0, &[1; 12], &[2; 12]), true)
                            else {
                                return;
                            };
                            if enc.encrypt_in_place(&mut f).is_err()
                                || s.write_all(&f).await.is_err()
                            {
                                return;
                            }
                        } else if op == TEST_RPC_PROXY_REQ && rpay.len() >= 56 {
                            let flags = u32::from_le_bytes([rpay[4], rpay[5], rpay[6], rpay[7]]);
                            let cid = u64::from_le_bytes([
                                rpay[8], rpay[9], rpay[10], rpay[11], rpay[12], rpay[13], rpay[14],
                                rpay[15],
                            ]);
                            let mut rip = [0u8; 16];
                            rip.copy_from_slice(&rpay[16..32]);
                            let rport =
                                u32::from_le_bytes([rpay[32], rpay[33], rpay[34], rpay[35]]);
                            let (ad_tag, body_off) = if flags & TEST_FLAG_HAS_AD_TAG != 0 {
                                if rpay.len() < 76 || rpay[56] != 16 {
                                    return;
                                }
                                let mut tag = [0u8; 16];
                                tag.copy_from_slice(&rpay[57..73]);
                                (Some(tag), 76)
                            } else {
                                (None, 56)
                            };
                            let body = rpay[body_off..].to_vec();
                            obs.lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .push(TestMeObserved {
                                    remote_ip: rip,
                                    remote_port: rport,
                                    ad_tag,
                                });
                            if dr.load(Ordering::Relaxed) {
                                return; // Simulate sudden ME disconnect mid-session
                            }
                            if qa.load(Ordering::Relaxed) {
                                let mut ack = Vec::with_capacity(16);
                                ack.extend_from_slice(&TEST_RPC_SIMPLE_ACK.to_le_bytes());
                                ack.extend_from_slice(&cid.to_le_bytes());
                                ack.extend_from_slice(&0x1234_5678u32.to_le_bytes());
                                let Ok(mut f) = pack_rpc_frame(next_seq, &ack, true) else {
                                    return;
                                };
                                next_seq = next_seq.wrapping_add(1);
                                if enc.encrypt_in_place(&mut f).is_err()
                                    || s.write_all(&f).await.is_err()
                                {
                                    return;
                                }
                            }
                            let mut ans = Vec::with_capacity(16 + body.len());
                            ans.extend_from_slice(&TEST_RPC_PROXY_ANS.to_le_bytes());
                            ans.extend_from_slice(&0u32.to_le_bytes());
                            ans.extend_from_slice(&cid.to_le_bytes());
                            ans.extend_from_slice(&body);
                            let Ok(mut f) = pack_rpc_frame(next_seq, &ans, true) else {
                                return;
                            };
                            next_seq = next_seq.wrapping_add(1);
                            if enc.encrypt_in_place(&mut f).is_err()
                                || s.write_all(&f).await.is_err()
                            {
                                return;
                            }
                        }
                    }
                });
            }
        });

        Ok(TestMockMe {
            addr,
            observed,
            send_quick_ack,
            drop_after_first_req,
            task,
        })
    }

    async fn spawn_test_http_cfg(
        secret: Arc<Mutex<Vec<u8>>>,
        conf: Arc<Mutex<Vec<u8>>>,
    ) -> Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    break;
                };
                let sec = secret.clone();
                let cnf = conf.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let Ok(n) = s.read(&mut buf).await else {
                        return;
                    };
                    let req = std::str::from_utf8(&buf[..n]).unwrap_or("");
                    let path = req
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("");
                    let body = if path == "/secret" {
                        sec.lock().unwrap_or_else(|e| e.into_inner()).clone()
                    } else {
                        cnf.lock().unwrap_or_else(|e| e.into_inner()).clone()
                    };
                    let hdr = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = s.write_all(hdr.as_bytes()).await;
                    let _ = s.write_all(&body).await;
                });
            }
        });
        Ok((addr, task))
    }

    fn make_temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mtevil-me-dp-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    fn write_ad_tag_0600(path: &Path, text: &str) -> Result<()> {
        std::fs::write(path, text)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    #[test]
    fn me_config_validation_and_backward_compatibility() -> Result<()> {
        let dir = make_temp_dir("cfg");
        let secret_file = dir.join("secret");
        std::fs::write(&secret_file, "00112233445566778899aabbccddeeff\n")?;

        // 1. Old v0.2 config without `me` loads identically with me.enabled = false.
        let old_cfg_path = dir.join("old.json");
        std::fs::write(
            &old_cfg_path,
            serde_json::to_string(&json!({
                "role": "direct",
                "secret_file": secret_file,
                "sni": "example.com",
                "cover": "127.0.0.1:443",
                "dc": ["2=127.0.0.1:443"]
            }))?,
        )?;
        let loaded = Config::load(&old_cfg_path)?;
        assert!(!loaded.me.enabled);
        assert!(loaded.me.fallback_to_direct);
        assert!(loaded.me.send_client_ip);

        // 2. Role edge or egress with me.enabled = true must be rejected until Phase 3 (MTV4).
        let edge_cfg_path = dir.join("edge.json");
        std::fs::write(
            &edge_cfg_path,
            serde_json::to_string(&json!({
                "role": "edge",
                "secret_file": secret_file,
                "sni": "example.com",
                "cover": "127.0.0.1:443",
                "egress_upstreams": ["127.0.0.1:9443"],
                "me": { "enabled": true }
            }))?,
        )?;
        assert!(Config::load(&edge_cfg_path).is_err());

        let egress_cfg_path = dir.join("egress.json");
        std::fs::write(
            &egress_cfg_path,
            serde_json::to_string(&json!({
                "role": "egress",
                "dc": ["2=127.0.0.1:443"],
                "me": { "enabled": true }
            }))?,
        )?;
        assert!(Config::load(&egress_cfg_path).is_err());

        // 3. Invalid ad_tag rejected; valid 32-hex ad_tag (0600) accepted.
        let tag_path = dir.join("ad-tag");
        write_ad_tag_0600(&tag_path, "not-a-valid-tag\n")?;
        let bad_tag_cfg = dir.join("bad_tag.json");
        std::fs::write(
            &bad_tag_cfg,
            serde_json::to_string(&json!({
                "role": "direct",
                "secret_file": secret_file,
                "sni": "example.com",
                "cover": "127.0.0.1:443",
                "dc": ["2=127.0.0.1:443"],
                "me": { "enabled": true, "ad_tag_file": tag_path }
            }))?,
        )?;
        assert!(Config::load(&bad_tag_cfg).is_err());

        write_ad_tag_0600(&tag_path, "0123456789abcdef0123456789abcdef\n")?;
        let ok_cfg = Config::load(&bad_tag_cfg)?;
        assert!(ok_cfg.me.enabled);

        // 4. Plain http:// ME config URLs are rejected for non-loopback hosts, allowed only for loopback.
        assert!(config::validate_me_config_url("https://core.telegram.org/getProxySecret").is_ok());
        assert!(config::validate_me_config_url("http://127.0.0.1:8080/secret").is_ok());
        assert!(config::validate_me_config_url("http://[::1]:8080/conf").is_ok());
        assert!(config::validate_me_config_url("http://localhost:8080/conf").is_ok());
        assert!(config::validate_me_config_url("http://core.telegram.org/getProxySecret").is_err());
        assert!(config::validate_me_config_url("http://198.51.100.10/secret").is_err());
        assert!(config::validate_me_config_url("ftp://core.telegram.org/secret").is_err());

        let bad_http_cfg = dir.join("bad_http.json");
        std::fs::write(
            &bad_http_cfg,
            serde_json::to_string(&json!({
                "role": "direct",
                "secret_file": secret_file,
                "sni": "example.com",
                "cover": "127.0.0.1:443",
                "dc": ["2=127.0.0.1:443"],
                "me": {
                    "enabled": true,
                    "proxy_secret_url": "http://198.51.100.10/secret"
                }
            }))?,
        )?;
        assert!(Config::load(&bad_http_cfg).is_err());

        // 5. extract_client_ipv4: IPv4 and IPv4-mapped IPv6 preserved, pure IPv6 maps to None (0.0.0.0:0).
        assert_eq!(
            extract_client_ipv4(Some("198.51.100.77:54321".parse()?)),
            Some(SocketAddrV4::new(
                std::net::Ipv4Addr::new(198, 51, 100, 77),
                54321
            ))
        );
        assert_eq!(
            extract_client_ipv4(Some("[::ffff:198.51.100.42]:44444".parse()?)),
            Some(SocketAddrV4::new(
                std::net::Ipv4Addr::new(198, 51, 100, 42),
                44444
            ))
        );
        assert_eq!(
            extract_client_ipv4(Some("[2001:db8::1]:54321".parse()?)),
            None
        );

        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn me_proxy_v2_client_ip_and_ipv6_zero_address() -> Result<()> {
        let dir = make_temp_dir("pv2");
        let me_secret = vec![0x61; 128];
        let mock_me = spawn_test_mock_me(me_secret.clone()).await?;
        let conf_text = format!("default 2;\nproxy_for 2 {};\n", mock_me.addr);
        let (http_addr, http_task) = spawn_test_http_cfg(
            Arc::new(Mutex::new(me_secret.clone())),
            Arc::new(Mutex::new(conf_text.into_bytes())),
        )
        .await?;

        let counters = Arc::new(telemetry::Counters::default());
        let me_cfg = config::MeConfig {
            enabled: true,
            fallback_to_direct: false,
            send_client_ip: true,
            public_ipv4: None,
            pool_size: 1,
            refresh_interval_secs: 3600,
            drain_timeout_secs: 5,
            ad_tag_file: None,
            cache_dir: Some(dir.join("cache")),
            proxy_secret_url: format!("http://{http_addr}/secret"),
            proxy_config_url: format!("http://{http_addr}/conf"),
        };
        let me_rt = MeRuntime::start(me_cfg, dir.join("cache"), counters.clone()).await;
        for _ in 0..50 {
            if !me_rt.telemetry_snapshot().degraded {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(!me_rt.telemetry_snapshot().degraded);

        let client_secret = [0x23; 16];
        let st = Arc::new(State {
            secrets: std::sync::RwLock::new(Arc::new(vec![NamedSecret {
                name: "default".into(),
                key: Zeroizing::new(client_secret),
            }])),
            sni: "example.com".into(),
            allowed_snis: std::sync::RwLock::new(Arc::new("example.com".into())),
            cover_resolver: Arc::new(CoverResolver::new(
                "127.0.0.1:1".into(),
                Duration::from_secs(60),
            )),
            enable_dd: false,
            proxy_protocol: true,
            cover_permits: Semaphore::new(4),
            dcs: HashMap::new(),
            dc_media_overrides: HashMap::new(),
            egress_upstreams: Vec::new(),
            egress_strategy: EgressStrategy::RoundRobin,
            egress_token: [0; 16],
            egress_rr: std::sync::atomic::AtomicUsize::new(0),
            egress_health: std::sync::Mutex::new(EgressHealth::new(0)),
            egress_probe_notify: Arc::new(tokio::sync::Notify::new()),
            egress_cooldown: Duration::from_secs(1),
            egress_cooldown_max: Duration::from_secs(5),
            egress_probe_interval: Duration::from_secs(30),
            egress_probe_degraded_interval: Duration::from_secs(5),
            egress_hedge_ms: 0,
            egress_use_mtv3: true,
            client_hello: Duration::from_secs(2),
            handshake: Duration::from_secs(2),
            idle: Duration::from_secs(5),
            drain: Duration::from_secs(1),
            flight: wire::ServerFlightProfile::default(),
            flight_shaping: false,
            client_mss_bulk: None,
            replay: tokio::sync::Mutex::new(ReplayCache::new(1024, Duration::from_secs(300))),
            counters: counters.clone(),
            alert_webhook_url: None,
            alerts_file: None,
            diagnostics: false,
            me: Some(me_rt.clone()),
        });

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let proxy_addr = listener.local_addr()?;
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let srv_task = tokio::spawn(serve(listener, st.clone(), 16, async {
            let _ = stop_rx.await;
        }));

        let build_pv2_v4 = |src_ip: [u8; 4], src_port: u16| -> Vec<u8> {
            let mut h = Vec::with_capacity(28);
            h.extend_from_slice(b"\r\n\r\n\0\r\nQUIT\n");
            h.push(0x21); // v2 PROXY
            h.push(0x11); // AF_INET STREAM
            h.extend_from_slice(&12u16.to_be_bytes());
            h.extend_from_slice(&src_ip);
            h.extend_from_slice(&[127, 0, 0, 1]);
            h.extend_from_slice(&src_port.to_be_bytes());
            h.extend_from_slice(&443u16.to_be_bytes());
            h
        };
        let build_pv2_v6 = |src_ip: [u8; 16], src_port: u16| -> Vec<u8> {
            let mut h = Vec::with_capacity(52);
            h.extend_from_slice(b"\r\n\r\n\0\r\nQUIT\n");
            h.push(0x21); // v2 PROXY
            h.push(0x21); // AF_INET6 STREAM
            h.extend_from_slice(&36u16.to_be_bytes());
            h.extend_from_slice(&src_ip);
            h.extend_from_slice(&[0u8; 16]);
            h.extend_from_slice(&src_port.to_be_bytes());
            h.extend_from_slice(&443u16.to_be_bytes());
            h
        };

        for pv2 in [
            build_pv2_v4([198, 51, 100, 77], 54321),
            build_pv2_v6(
                std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets(),
                54322,
            ),
        ] {
            let mut s = TcpStream::connect(proxy_addr).await?;
            s.write_all(&pv2).await?;
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let (hello, _, _) = wire::build_client_hello(
                &client_secret,
                "example.com",
                now,
                &mut rand::rngs::OsRng,
            )?;
            s.write_all(&hello).await?;
            let mut hdr = [0u8; 5];
            for _ in 0..3 {
                s.read_exact(&mut hdr).await?;
                let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                let mut body = vec![0u8; len];
                s.read_exact(&mut body).await?;
            }
            let (init, mut enc, mut dec) = wire::build_client_init_with_kind(
                &client_secret,
                2,
                wire::ClientProtoKind::Intermediate,
            )?;
            s.write_all(&wire::record(0x17, &init)?).await?;
            let payload = vec![0x99; 32];
            let mut frame =
                wire::encode_client_frame(wire::ClientProtoKind::Intermediate, &payload, &[])?;
            wire::crypt(&mut enc, &mut frame);
            s.write_all(&wire::record(0x17, &frame)?).await?;

            let mut tls_rd = TlsReader::default();
            let mut plain_buf = Vec::new();
            let mut tmp = [0u8; 1024];
            let reply = timeout(Duration::from_secs(3), async {
                loop {
                    if let Some(f) = wire::decode_client_frame(
                        wire::ClientProtoKind::Intermediate,
                        &mut plain_buf,
                    )? {
                        return Ok::<_, anyhow::Error>(f.payload);
                    }
                    let n = tls_rd.read_into(&mut s, &mut tmp).await?;
                    ensure!(n > 0, "EOF");
                    wire::crypt(&mut dec, &mut tmp[..n]);
                    plain_buf.extend_from_slice(&tmp[..n]);
                }
            })
            .await??;
            assert_eq!(reply, payload);
        }

        {
            let obs = mock_me.observed.lock().unwrap_or_else(|e| e.into_inner());
            assert_eq!(obs.len(), 2);
            // 1st connection: PROXY v2 IPv4 198.51.100.77:54321
            assert_eq!(
                obs[0].remote_ip,
                mtevil_me_pool::ipv4_mapped_16(std::net::Ipv4Addr::new(198, 51, 100, 77))
            );
            assert_eq!(obs[0].remote_port, 54321);
            // 2nd connection: pure IPv6 client -> deterministic 0.0.0.0:0
            assert_eq!(
                obs[1].remote_ip,
                mtevil_me_pool::ipv4_mapped_16(std::net::Ipv4Addr::UNSPECIFIED)
            );
            assert_eq!(obs[1].remote_port, 0);
        }

        let _ = stop_tx.send(());
        let _ = srv_task.await;
        me_rt.shutdown();
        http_task.abort();
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_faketls_client_exchange(
        proxy_addr: SocketAddr,
        client_secret: &[u8; 16],
        sni: &str,
        dc: i16,
        kind: wire::ClientProtoKind,
        payload: &[u8],
        fragmented: bool,
        expect_quick_ack: bool,
    ) -> Result<(Vec<u8>, Option<[u8; 4]>)> {
        let mut s = TcpStream::connect(proxy_addr).await?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let (hello, _, _) =
            wire::build_client_hello(client_secret, sni, now, &mut rand::rngs::OsRng)?;
        s.write_all(&hello).await?;

        // Read ServerHello flight (3 TLS records: ServerHello + CCS + AppData)
        let mut srv_buf = Vec::new();
        let mut hdr = [0u8; 5];
        for _ in 0..3 {
            s.read_exact(&mut hdr).await?;
            let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
            let mut body = vec![0u8; len];
            s.read_exact(&mut body).await?;
            srv_buf.extend_from_slice(&hdr);
            srv_buf.extend_from_slice(&body);
        }

        // Send obfuscated2 init + encoded MTProto frame inside FakeTLS ApplicationData records
        let (init, mut enc, mut dec) = wire::build_client_init_with_kind(client_secret, dc, kind)?;
        let init_rec = wire::record(0x17, &init)?;
        s.write_all(&init_rec).await?;

        let pad = if kind == wire::ClientProtoKind::PaddedIntermediate {
            &[0x11, 0x22, 0x33][..]
        } else {
            &[][..]
        };
        let mut frame = wire::encode_client_frame(kind, payload, pad)?;
        wire::crypt(&mut enc, &mut frame);
        if fragmented {
            for ch in frame.chunks(7) {
                let rec = wire::record(0x17, ch)?;
                s.write_all(&rec).await?;
            }
        } else {
            for ch in frame.chunks(wire::MAX_RECORD) {
                let rec = wire::record(0x17, ch)?;
                s.write_all(&rec).await?;
            }
        }

        // Read response TLS ApplicationData records and decrypt client transport
        let mut tls_rd = TlsReader::default();
        let mut plain_buf = Vec::new();
        let mut tmp = [0u8; 16 * 1024];
        let mut quick_ack_seen = None;
        let reply = timeout(Duration::from_secs(5), async {
            loop {
                if expect_quick_ack && quick_ack_seen.is_none() && plain_buf.len() >= 4 {
                    let is_qa = match kind {
                        wire::ClientProtoKind::Abridged => (plain_buf[0] & 0x80) != 0,
                        wire::ClientProtoKind::Intermediate
                        | wire::ClientProtoKind::PaddedIntermediate => (plain_buf[3] & 0x80) != 0,
                    };
                    if is_qa {
                        let qa = [plain_buf[0], plain_buf[1], plain_buf[2], plain_buf[3]];
                        plain_buf.drain(..4);
                        quick_ack_seen = Some(qa);
                        continue;
                    }
                }
                if let Some(f) = wire::decode_client_frame(kind, &mut plain_buf)? {
                    return Ok::<_, anyhow::Error>(f.payload);
                }
                let n = tls_rd.read_into(&mut s, &mut tmp).await?;
                ensure!(n > 0, "EOF waiting for ME reply");
                wire::crypt(&mut dec, &mut tmp[..n]);
                plain_buf.extend_from_slice(&tmp[..n]);
            }
        })
        .await
        .context("client ME exchange timeout")??;
        Ok((reply, quick_ack_seen))
    }

    #[tokio::test]
    async fn me_e2e_all_three_transports_fragmentation_quick_ack_and_large_frames() -> Result<()> {
        let dir = make_temp_dir("e2e");
        let me_secret = vec![0x55; 128];
        let mock_me = spawn_test_mock_me(me_secret.clone()).await?;
        let conf_text = format!(
            "default 2;\nproxy_for 2 {};\nproxy_for -2 {};\n",
            mock_me.addr, mock_me.addr
        );
        let (http_addr, http_task) = spawn_test_http_cfg(
            Arc::new(Mutex::new(me_secret.clone())),
            Arc::new(Mutex::new(conf_text.into_bytes())),
        )
        .await?;

        let tag_path = dir.join("ad-tag");
        let tag_hex = "0123456789abcdef0123456789abcdef";
        write_ad_tag_0600(&tag_path, tag_hex)?;

        let counters = Arc::new(telemetry::Counters::default());
        let me_cfg = config::MeConfig {
            enabled: true,
            fallback_to_direct: false,
            send_client_ip: true,
            public_ipv4: None,
            pool_size: 1,
            refresh_interval_secs: 3600,
            drain_timeout_secs: 5,
            ad_tag_file: Some(tag_path.clone()),
            cache_dir: Some(dir.join("cache")),
            proxy_secret_url: format!("http://{http_addr}/secret"),
            proxy_config_url: format!("http://{http_addr}/conf"),
        };
        let me_rt = MeRuntime::start(me_cfg, dir.join("cache"), counters.clone()).await;
        for _ in 0..50 {
            if !me_rt.telemetry_snapshot().degraded {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(!me_rt.telemetry_snapshot().degraded);

        let client_secret = [0x12; 16];
        let mut st_dcs = HashMap::new();
        st_dcs.insert(2, SocketAddr::from(([127, 0, 0, 1], 1)));
        let st = Arc::new(State {
            secrets: std::sync::RwLock::new(Arc::new(vec![NamedSecret {
                name: "default".into(),
                key: Zeroizing::new(client_secret),
            }])),
            sni: "example.com".into(),
            allowed_snis: std::sync::RwLock::new(Arc::new("example.com".into())),
            cover_resolver: Arc::new(CoverResolver::new(
                "127.0.0.1:1".into(),
                Duration::from_secs(60),
            )),
            enable_dd: false,
            proxy_protocol: false,
            cover_permits: Semaphore::new(4),
            dcs: st_dcs,
            dc_media_overrides: HashMap::new(),
            egress_upstreams: Vec::new(),
            egress_strategy: EgressStrategy::RoundRobin,
            egress_token: [0; 16],
            egress_rr: std::sync::atomic::AtomicUsize::new(0),
            egress_health: std::sync::Mutex::new(EgressHealth::new(0)),
            egress_probe_notify: Arc::new(tokio::sync::Notify::new()),
            egress_cooldown: Duration::from_secs(1),
            egress_cooldown_max: Duration::from_secs(5),
            egress_probe_interval: Duration::from_secs(30),
            egress_probe_degraded_interval: Duration::from_secs(5),
            egress_hedge_ms: 0,
            egress_use_mtv3: true,
            client_hello: Duration::from_secs(2),
            handshake: Duration::from_secs(2),
            idle: Duration::from_secs(5),
            drain: Duration::from_secs(1),
            flight: wire::ServerFlightProfile::default(),
            flight_shaping: false,
            client_mss_bulk: None,
            replay: tokio::sync::Mutex::new(ReplayCache::new(1024, Duration::from_secs(300))),
            counters: counters.clone(),
            alert_webhook_url: None,
            alerts_file: None,
            diagnostics: false,
            me: Some(me_rt.clone()),
        });

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let proxy_addr = listener.local_addr()?;
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let srv_task = tokio::spawn(serve(listener, st.clone(), 32, async {
            let _ = stop_rx.await;
        }));

        // Test all 3 transports: Abridged (fragmented), Intermediate (quick-ack), PaddedIntermediate (64 KiB + media DC -2)
        let small_payload = vec![0xab; 64];
        let (r1, _) = run_faketls_client_exchange(
            proxy_addr,
            &client_secret,
            "example.com",
            2,
            wire::ClientProtoKind::Abridged,
            &small_payload,
            true,
            false,
        )
        .await?;
        assert_eq!(r1, small_payload);

        mock_me.send_quick_ack.store(true, Ordering::Relaxed);
        let (r2, qa) = run_faketls_client_exchange(
            proxy_addr,
            &client_secret,
            "example.com",
            2,
            wire::ClientProtoKind::Intermediate,
            &small_payload,
            false,
            true,
        )
        .await?;
        assert_eq!(r2, small_payload);
        assert_eq!(
            qa,
            Some(wire::encode_quick_ack(
                wire::ClientProtoKind::Intermediate,
                0x1234_5678
            ))
        );
        mock_me.send_quick_ack.store(false, Ordering::Relaxed);

        let large_payload: Vec<u8> = (0..65536).map(|i| (i % 251) as u8).collect();
        let (r3, _) = run_faketls_client_exchange(
            proxy_addr,
            &client_secret,
            "example.com",
            -2,
            wire::ClientProtoKind::PaddedIntermediate,
            &large_payload,
            false,
            false,
        )
        .await?;
        assert!(
            r3.len() >= large_payload.len() && r3.len() <= large_payload.len() + 12,
            "padded-intermediate reply length {} out of expected range",
            r3.len()
        );
        assert_eq!(&r3[..large_payload.len()], large_payload.as_slice());

        // Verify mock ME observed ad_tag and real client loopback IPv4 (send_client_ip = true)
        let expected_tag = mtevil_me_pool::parse_ad_tag_hex(tag_hex)?;
        {
            let obs = mock_me.observed.lock().unwrap_or_else(|e| e.into_inner());
            assert_eq!(obs.len(), 3);
            for o in obs.iter() {
                assert_eq!(o.ad_tag, Some(expected_tag));
                assert_eq!(
                    o.remote_ip,
                    mtevil_me_pool::ipv4_mapped_16(std::net::Ipv4Addr::LOCALHOST)
                );
                assert!(o.remote_port > 0);
            }
        }

        // Verify Prometheus metrics and runtime-stats JSON expose ME fields without leaking ad_tag
        let snap = me_rt.telemetry_snapshot();
        let prom = counters.render_prometheus_with_me(&[], None, None, Some(&snap));
        assert!(prom.contains("mtevil_me_active_sessions"));
        assert!(prom.contains("mtevil_me_pool_degraded 0"));
        assert!(prom.contains("mtevil_me_config_age_seconds"));
        assert!(!prom.contains(tag_hex));
        let stats_json = counters.snapshot_json_with_me("direct", Some(&snap));
        assert_eq!(stats_json["me"]["mode"], "me");
        assert_eq!(stats_json["me"]["ad_tag"], "configured");
        assert!(!stats_json.to_string().contains(tag_hex));

        // Verify hot-reload of ad_tag_file without restart
        let new_tag_hex = "fedcba9876543210fedcba9876543210";
        tokio::time::sleep(Duration::from_millis(50)).await;
        write_ad_tag_0600(&tag_path, new_tag_hex)?;
        // Force mtime check
        *me_rt.ad_tag_mtime.lock().unwrap_or_else(|e| e.into_inner()) = None;
        me_rt.reload_ad_tag_if_changed();
        assert_eq!(
            me_rt.current_ad_tag(),
            Some(mtevil_me_pool::parse_ad_tag_hex(new_tag_hex)?)
        );

        // Simulate mid-session ME disconnect: client receives EOF cleanly (no fallback mid-session)
        mock_me.drop_after_first_req.store(true, Ordering::Relaxed);
        let mid_err = run_faketls_client_exchange(
            proxy_addr,
            &client_secret,
            "example.com",
            2,
            wire::ClientProtoKind::Intermediate,
            &small_payload,
            false,
            false,
        )
        .await;
        assert!(mid_err.is_err());

        let _ = stop_tx.send(());
        let _ = srv_task.await;
        me_rt.shutdown();
        http_task.abort();
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn me_fallback_chaos_unavailable_empty_pool_and_corrupted_refresh() -> Result<()> {
        let dir = make_temp_dir("chaos");
        let counters = Arc::new(telemetry::Counters::default());

        // 1. ME config URL unreachable, no LKG cache, fallback_to_direct = true -> starts cleanly without crash-loop
        let dead_listener = TcpListener::bind("127.0.0.1:0").await?;
        let dead_addr = dead_listener.local_addr()?;
        drop(dead_listener);

        let me_cfg = config::MeConfig {
            enabled: true,
            fallback_to_direct: true,
            send_client_ip: false,
            public_ipv4: None,
            pool_size: 1,
            refresh_interval_secs: 60,
            drain_timeout_secs: 5,
            ad_tag_file: None,
            cache_dir: Some(dir.join("cache-empty")),
            proxy_secret_url: format!("http://{dead_addr}/secret"),
            proxy_config_url: format!("http://{dead_addr}/conf"),
        };
        let me_rt = MeRuntime::start_with_backoff(
            me_cfg,
            dir.join("cache-empty"),
            counters.clone(),
            Duration::from_secs(60),
            Duration::from_secs(120),
        )
        .await;
        assert!(me_rt.telemetry_snapshot().degraded);
        assert!(counters.me_refresh_errors.load(Ordering::Relaxed) >= 1);

        // Spawn a mock Direct DC that echoes obfuscated2 stream
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
            let Ok(mut dec) = wire::client_transport(&hdr, &[0; 16]) else {
                // Direct DC header uses empty secret
                let mut d_plain = hdr;
                let Ok(mut d_dec) = mtevil_proto::client_transport(&hdr, &[0; 16]) else {
                    return;
                };
                let _ = (&mut d_plain, &mut d_dec);
                return;
            };
            let mut buf = [0u8; 4096];
            if let Ok(n) = s.read(&mut buf).await {
                if n > 0 {
                    wire::crypt(&mut dec.decrypt, &mut buf[..n]);
                    wire::crypt(&mut dec.encrypt, &mut buf[..n]);
                    let _ = s.write_all(&buf[..n]).await;
                }
            }
        });

        let client_secret = [0x34; 16];
        let mut dcs = HashMap::new();
        dcs.insert(2, dc_addr);
        let st = Arc::new(State {
            secrets: std::sync::RwLock::new(Arc::new(vec![NamedSecret {
                name: "default".into(),
                key: Zeroizing::new(client_secret),
            }])),
            sni: "example.com".into(),
            allowed_snis: std::sync::RwLock::new(Arc::new("example.com".into())),
            cover_resolver: Arc::new(CoverResolver::new(
                "127.0.0.1:1".into(),
                Duration::from_secs(60),
            )),
            enable_dd: false,
            proxy_protocol: false,
            cover_permits: Semaphore::new(4),
            dcs,
            dc_media_overrides: HashMap::new(),
            egress_upstreams: Vec::new(),
            egress_strategy: EgressStrategy::RoundRobin,
            egress_token: [0; 16],
            egress_rr: std::sync::atomic::AtomicUsize::new(0),
            egress_health: std::sync::Mutex::new(EgressHealth::new(0)),
            egress_probe_notify: Arc::new(tokio::sync::Notify::new()),
            egress_cooldown: Duration::from_secs(1),
            egress_cooldown_max: Duration::from_secs(5),
            egress_probe_interval: Duration::from_secs(30),
            egress_probe_degraded_interval: Duration::from_secs(5),
            egress_hedge_ms: 0,
            egress_use_mtv3: true,
            client_hello: Duration::from_secs(2),
            handshake: Duration::from_secs(2),
            idle: Duration::from_secs(3),
            drain: Duration::from_secs(1),
            flight: wire::ServerFlightProfile::default(),
            flight_shaping: false,
            client_mss_bulk: None,
            replay: tokio::sync::Mutex::new(ReplayCache::new(1024, Duration::from_secs(300))),
            counters: counters.clone(),
            alert_webhook_url: None,
            alerts_file: None,
            diagnostics: false,
            me: Some(me_rt.clone()),
        });

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let proxy_addr = listener.local_addr()?;
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let srv_task = tokio::spawn(serve(listener, st.clone(), 16, async {
            let _ = stop_rx.await;
        }));

        let payload = vec![0x77; 32];
        // Note: fallback to Direct succeeds and increments mtevil_me_fallback_direct_total!
        let _ = run_faketls_client_exchange(
            proxy_addr,
            &client_secret,
            "example.com",
            2,
            wire::ClientProtoKind::PaddedIntermediate,
            &payload,
            false,
            false,
        )
        .await;
        assert_eq!(counters.me_fallback_direct_total.load(Ordering::Relaxed), 1);
        let stats = counters.snapshot_json_with_me("direct", Some(&me_rt.telemetry_snapshot()));
        assert_eq!(stats["me"]["mode"], "me_degraded_fallback_direct");

        // 2. Corrupted refresh response never overwrites LKG cache
        let lkg_dir = dir.join("cache-lkg");
        let valid_secret = vec![0x88; 128];
        let valid_conf = b"default 2;\nproxy_for 2 127.0.0.1:1;\n".to_vec();
        let sec_shared = Arc::new(Mutex::new(valid_secret.clone()));
        let conf_shared = Arc::new(Mutex::new(valid_conf.clone()));
        let (http_addr, http_task) =
            spawn_test_http_cfg(sec_shared.clone(), conf_shared.clone()).await?;
        let me_lkg_cfg = config::MeConfig {
            enabled: true,
            fallback_to_direct: false,
            send_client_ip: true,
            public_ipv4: None,
            pool_size: 1,
            refresh_interval_secs: 60,
            drain_timeout_secs: 5,
            ad_tag_file: None,
            cache_dir: Some(lkg_dir.clone()),
            proxy_secret_url: format!("http://{http_addr}/secret"),
            proxy_config_url: format!("http://{http_addr}/conf"),
        };
        let me_lkg = MeRuntime::start(me_lkg_cfg, lkg_dir.clone(), counters.clone()).await;
        // Corrupt remote server response and trigger fetch_and_save_bundle
        *conf_shared.lock().unwrap_or_else(|e| e.into_inner()) = b"corrupted garbage".to_vec();
        assert!(me_lkg.fetch_and_save_bundle().await.is_err());
        // LKG disk cache must still load the original valid bundle
        let lkg_loaded = MeDiskCache::new(&lkg_dir).load()?;
        assert_eq!(lkg_loaded.proxy_secret, valid_secret);
        assert!(lkg_loaded.proxy_conf.dcs.contains_key(&2));

        let _ = stop_tx.send(());
        let _ = srv_task.await;
        me_rt.shutdown();
        me_lkg.shutdown();
        dc_task.abort();
        http_task.abort();
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }
}
