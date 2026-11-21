use anyhow::{bail, ensure, Context, Result};
use clap::{Parser, Subcommand};
use mtevil_proto::{self as wire, AesCtr};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, Semaphore},
    time::{timeout, Instant},
};
use zeroize::Zeroizing;
mod replay;
use replay::{Decision, ReplayCache};

mod config;
use config::{Config, EgressStrategy, NamedSecret, Role};
mod telemetry;
use serde_json::json;

const BUILD_VERSION: &str = match option_env!("MTEVIL_BUILD_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

#[derive(Parser)]
#[command(name = "mtevil", version = BUILD_VERSION, about = "Experimental MTProto Direct proxy")]
struct Args {
    #[command(subcommand)]
    command: Option<Action>,
    #[arg(long, conflicts_with_all=["listen","secret_file","users_file","replay_file","sni","cover","dc","egress_upstreams","egress_strategy","egress_token_file","role","enable_dd","proxy_protocol","max_connections","client_hello_timeout_secs","handshake_timeout_secs","idle_timeout_secs","drain_timeout_secs","fake_tls_cert_bytes","fake_tls_cert_jitter","flight_shaping","client_mss","client_mss_bulk","egress_cooldown_base_ms","egress_cooldown_max_ms","egress_probe_interval_secs","egress_probe_degraded_interval_secs","egress_hedge_ms","egress_accept_legacy","egress_use_mtv3","egress_allow_from","egress_max_failed_per_ip","dc_media_override","dc_probe_interval_secs","cover_dns_ttl_secs","diagnostics","metrics_listen"])]
    config: Option<PathBuf>,
    #[arg(long)]
    check_config: bool,
    #[arg(long)]
    role: Option<Role>,
    #[arg(long)]
    listen: Option<SocketAddr>,
    #[arg(long)]
    secret_file: Option<PathBuf>,
    #[arg(long)]
    users_file: Option<PathBuf>,
    #[arg(long)]
    replay_file: Option<PathBuf>,
    #[arg(long)]
    sni: Option<String>,
    #[arg(long)]
    cover: Option<String>,
    #[arg(long)]
    dc: Vec<String>,
    #[arg(long)]
    egress_upstreams: Vec<SocketAddr>,
    #[arg(long)]
    egress_strategy: Option<EgressStrategy>,
    #[arg(long)]
    egress_token_file: Option<PathBuf>,
    #[arg(long)]
    enable_dd: bool,
    #[arg(long)]
    proxy_protocol: bool,
    #[arg(long)]
    max_connections: Option<usize>,
    #[arg(long)]
    client_hello_timeout_secs: Option<u64>,
    #[arg(long)]
    handshake_timeout_secs: Option<u64>,
    #[arg(long)]
    idle_timeout_secs: Option<u64>,
    #[arg(long)]
    drain_timeout_secs: Option<u64>,
    /// Size of the fake TLS certificate record in the ServerHello flight.
    #[arg(long)]
    fake_tls_cert_bytes: Option<usize>,
    /// Symmetric spread applied to the fake TLS certificate size.
    #[arg(long)]
    fake_tls_cert_jitter: Option<usize>,
    /// Unevenly fragment the outgoing ServerHello flight with small jittered delays.
    #[arg(long)]
    flight_shaping: bool,
    /// Client-facing TCP MSS (TCP_MAXSEG) set on the listener before listen(2).
    #[arg(long)]
    client_mss: Option<u16>,
    /// Bulk-phase TCP MSS applied to the client socket after handshake.
    #[arg(long)]
    client_mss_bulk: Option<u16>,
    /// Base cooldown in milliseconds for an egress upstream or DC after a failure.
    #[arg(long)]
    egress_cooldown_base_ms: Option<u64>,
    /// Maximum exponential backoff cooldown in milliseconds for an egress upstream or DC.
    #[arg(long)]
    egress_cooldown_max_ms: Option<u64>,
    /// Background egress probe interval in seconds when all egress nodes are healthy.
    #[arg(long)]
    egress_probe_interval_secs: Option<u64>,
    /// Background egress probe interval in seconds while at least one egress node is unavailable.
    #[arg(long)]
    egress_probe_degraded_interval_secs: Option<u64>,
    /// Hedged connect delay in milliseconds for ordered egress strategy (0 = disabled).
    #[arg(long)]
    egress_hedge_ms: Option<u64>,
    /// Whether egress accepts legacy MTV2 prefaces alongside MTV3.
    #[arg(long)]
    egress_accept_legacy: Option<bool>,
    /// Whether edge uses MTV3 when dialing egress.
    #[arg(long)]
    egress_use_mtv3: Option<bool>,
    /// Optional CIDR source allowlist on egress.
    #[arg(long)]
    egress_allow_from: Vec<String>,
    /// Maximum failed authentication attempts per source IP within a 60s sliding window on egress.
    #[arg(long)]
    egress_max_failed_per_ip: Option<usize>,
    /// Configurable media/alternate DC candidate overrides (`ID=IP:PORT`).
    #[arg(long)]
    dc_media_override: Vec<String>,
    /// Background DC self-check interval in seconds on direct/egress (0 = disabled).
    #[arg(long)]
    dc_probe_interval_secs: Option<u64>,
    /// Background cover DNS cache TTL / refresh interval in seconds.
    #[arg(long)]
    cover_dns_ttl_secs: Option<u64>,
    /// Enable per-chunk timeline diagnostic marks on relay paths.
    #[arg(long)]
    diagnostics: bool,
    /// Optional localhost-only Prometheus `/metrics` HTTP listener (disabled by default).
    #[arg(long)]
    metrics_listen: Option<SocketAddr>,
}

#[derive(Subcommand)]
enum Action {
    /// Create a random secret once; never overwrite an existing secret.
    Secret {
        #[arg(long)]
        output: PathBuf,
    },
    /// Add a named user secret to a JSON users file (never overwrites an existing user).
    UserAdd {
        #[arg(long)]
        users_file: PathBuf,
        #[arg(long)]
        name: String,
    },
    /// Remove a named user secret from a JSON users file.
    UserDel {
        #[arg(long)]
        users_file: PathBuf,
        #[arg(long)]
        name: String,
    },
    /// List user names from a JSON users file (one name per line, never prints secrets).
    UserList {
        #[arg(long)]
        users_file: PathBuf,
    },
    /// Explicitly print a Telegram proxy link. Treat the output as a credential.
    Link {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        server: String,
        #[arg(long, default_value_t = 443)]
        port: u16,
        #[arg(long)]
        dd: bool,
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        all: bool,
        #[arg(long)]
        sni: Option<String>,
    },
    /// TCP listener check only. Does not verify Telegram DC connectivity.
    Health {
        #[arg(long, default_value = "127.0.0.1:24443")]
        address: SocketAddr,
    },
    /// Check configured egress endpoints via MTV2 handshake from the edge network context.
    CheckEgress {
        #[arg(long)]
        config: PathBuf,
        #[arg(long, default_value_t = 2)]
        dc: i16,
    },
    /// Print runtime traffic and session counters from the state volume as JSON.
    Stats {
        #[arg(long, default_value = RUNTIME_STATS_DEFAULT_PATH)]
        stats_file: PathBuf,
    },
    /// End-to-end Telegram probe through the local proxy (FakeTLS/MTV2 handshake + req_pq_multi -> resPQ).
    ProbeTelegram {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        address: Option<SocketAddr>,
        #[arg(long, default_value_t = 2)]
        dc: i16,
        #[arg(long, default_value_t = 8)]
        timeout_secs: u64,
    },
}

impl Args {
    fn runtime_config(self) -> Result<Config> {
        if let Some(path) = self.config {
            return Config::load(&path);
        }
        let role = self.role.unwrap_or(Role::Direct);
        let config = Config {
            role,
            listen: self
                .listen
                .unwrap_or(SocketAddr::from(([127, 0, 0, 1], 24443))),
            secret_file: self.secret_file,
            users_file: self.users_file,
            replay_file: self.replay_file,
            sni: self.sni.unwrap_or_default(),
            cover: self.cover.unwrap_or_default(),
            enable_dd: self.enable_dd,
            proxy_protocol: self.proxy_protocol,
            dc: self.dc,
            egress_upstreams: self.egress_upstreams,
            egress_strategy: self.egress_strategy.unwrap_or(EgressStrategy::RoundRobin),
            egress_token_file: self.egress_token_file,
            max_connections: self.max_connections.unwrap_or(128),
            client_hello_timeout_secs: self.client_hello_timeout_secs.unwrap_or(5),
            handshake_timeout_secs: self.handshake_timeout_secs.unwrap_or(10),
            idle_timeout_secs: self.idle_timeout_secs.unwrap_or(300),
            drain_timeout_secs: self.drain_timeout_secs.unwrap_or(5),
            fake_tls_cert_bytes: self.fake_tls_cert_bytes.unwrap_or(wire::DEFAULT_CERT_BYTES),
            fake_tls_cert_jitter: self.fake_tls_cert_jitter.unwrap_or(0),
            flight_shaping: self.flight_shaping,
            client_mss: self.client_mss,
            client_mss_bulk: self.client_mss_bulk,
            alert_webhook_url: None,
            egress_cooldown_base_ms: self
                .egress_cooldown_base_ms
                .unwrap_or_else(config::default_egress_cooldown_base_ms),
            egress_cooldown_max_ms: self
                .egress_cooldown_max_ms
                .unwrap_or_else(config::default_egress_cooldown_max_ms),
            egress_probe_interval_secs: self
                .egress_probe_interval_secs
                .unwrap_or_else(config::default_egress_probe_interval_secs),
            egress_probe_degraded_interval_secs: self
                .egress_probe_degraded_interval_secs
                .unwrap_or_else(config::default_egress_probe_degraded_interval_secs),
            egress_hedge_ms: self
                .egress_hedge_ms
                .unwrap_or_else(config::default_egress_hedge_ms),
            egress_accept_legacy: self
                .egress_accept_legacy
                .unwrap_or_else(config::default_egress_accept_legacy),
            egress_use_mtv3: self
                .egress_use_mtv3
                .unwrap_or_else(config::default_egress_use_mtv3),
            egress_allow_from: self.egress_allow_from,
            egress_max_failed_per_ip: self
                .egress_max_failed_per_ip
                .unwrap_or_else(config::default_egress_max_failed_per_ip),
            dc_media_override: if self.dc_media_override.is_empty() {
                config::default_dc_media_override()
            } else {
                self.dc_media_override
            },
            dc_probe_interval_secs: self
                .dc_probe_interval_secs
                .unwrap_or_else(config::default_dc_probe_interval_secs),
            cover_dns_ttl_secs: self
                .cover_dns_ttl_secs
                .unwrap_or_else(config::default_cover_dns_ttl_secs),
            diagnostics: self.diagnostics,
            metrics_listen: self.metrics_listen,
        };
        config.validate()?;
        Ok(config)
    }
}

#[derive(Default, Clone, Copy)]
struct CooldownSlot {
    until: Option<Instant>,
    probing: bool,
    failures: u32,
}

fn compute_egress_cooldown_unclamped_ms(base_ms: u64, max_ms: u64, failures: u32) -> u64 {
    let shift = failures.saturating_sub(1).min(20);
    let scaled = base_ms.saturating_mul(1u64 << shift);
    scaled.min(max_ms.max(base_ms))
}

fn apply_cooldown_jitter_ms(clamped_ms: u64, sample_permille: i64) -> u64 {
    let factor = (1000 + sample_permille.clamp(-200, 200)) as u128;
    let out = (u128::from(clamped_ms) * factor) / 1000;
    (out as u64).max(1)
}

fn compute_egress_cooldown(base: Duration, max: Duration, failures: u32) -> Duration {
    use rand::Rng;
    let base_ms = base.as_millis().min(u128::from(u64::MAX)) as u64;
    let max_ms = max.as_millis().min(u128::from(u64::MAX)) as u64;
    let clamped_ms = compute_egress_cooldown_unclamped_ms(base_ms, max_ms, failures);
    let sample = rand::rngs::OsRng.gen_range(-200..=200);
    Duration::from_millis(apply_cooldown_jitter_ms(clamped_ms, sample))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
enum EdgeRouteState {
    #[default]
    PrimaryOk,
    FailoverBackup(usize),
    Degraded {
        healthy: usize,
        total: usize,
    },
    AllDown,
}

impl EdgeRouteState {
    fn as_str(&self) -> &'static str {
        match self {
            EdgeRouteState::PrimaryOk => "primary_ok",
            EdgeRouteState::FailoverBackup(_) => "failover_backup",
            EdgeRouteState::Degraded { .. } => "degraded",
            EdgeRouteState::AllDown => "all_down",
        }
    }
}

#[derive(Default)]
struct EgressHealth {
    nodes: Vec<CooldownSlot>,
    node_failed: Vec<bool>,
    dc_slots: HashMap<(usize, i16), CooldownSlot>,
    route_state: EdgeRouteState,
}

struct EdgeAlertEvent {
    prev: EdgeRouteState,
    next: EdgeRouteState,
    primary: SocketAddr,
    active: Option<SocketAddr>,
    reason: String,
    strategy: EgressStrategy,
}

impl EgressHealth {
    fn new(node_count: usize) -> Self {
        Self {
            nodes: vec![CooldownSlot::default(); node_count],
            node_failed: vec![false; node_count],
            dc_slots: HashMap::new(),
            route_state: EdgeRouteState::PrimaryOk,
        }
    }

    fn set_node_availability(
        health: &std::sync::Mutex<EgressHealth>,
        idx: usize,
        available: bool,
    ) -> (usize, usize) {
        let mut h = health.lock().unwrap_or_else(|e| e.into_inner());
        while h.node_failed.len() <= idx {
            h.node_failed.push(false);
        }
        h.node_failed[idx] = !available;
        let total = h.node_failed.len();
        let healthy = h.node_failed.iter().filter(|failed| !**failed).count();
        (healthy, total)
    }

    fn snapshot_breaker_states(
        health: &std::sync::Mutex<EgressHealth>,
        upstreams: &[SocketAddr],
    ) -> Vec<(String, u8)> {
        let now = Instant::now();
        let h = health.lock().unwrap_or_else(|e| e.into_inner());
        upstreams
            .iter()
            .enumerate()
            .map(|(idx, addr)| {
                let code = match h.nodes.get(idx) {
                    Some(slot) if slot.probing => 2,
                    Some(slot) if slot.until.is_some_and(|u| now < u) => 1,
                    _ => 0,
                };
                (addr.to_string(), code)
            })
            .collect()
    }

    fn apply_background_probe(
        health: &std::sync::Mutex<EgressHealth>,
        idx: usize,
        dc_abs: i16,
        available: bool,
        base: Duration,
        max: Duration,
    ) {
        let mut h = health.lock().unwrap_or_else(|e| e.into_inner());
        while h.nodes.len() <= idx {
            h.nodes.push(CooldownSlot::default());
        }
        while h.node_failed.len() <= idx {
            h.node_failed.push(false);
        }
        if available {
            let slot = &mut h.nodes[idx];
            slot.until = None;
            slot.probing = false;
            slot.failures = 0;
            if let Some(dc_slot) = h.dc_slots.get_mut(&(idx, dc_abs)) {
                dc_slot.until = None;
                dc_slot.probing = false;
                dc_slot.failures = 0;
            }
            h.node_failed[idx] = false;
        } else {
            let slot = &mut h.nodes[idx];
            slot.failures = slot.failures.saturating_add(1);
            let cooldown = compute_egress_cooldown(base, max, slot.failures);
            slot.until = Some(Instant::now() + cooldown);
            slot.probing = false;
            h.node_failed[idx] = true;
        }
    }

    fn transition_route_state(
        health: &std::sync::Mutex<EgressHealth>,
        next: EdgeRouteState,
        upstreams: &[SocketAddr],
        reason: String,
        strategy: EgressStrategy,
        active_override: Option<SocketAddr>,
    ) -> Option<EdgeAlertEvent> {
        let primary = *upstreams.first()?;
        let mut h = health.lock().unwrap_or_else(|e| e.into_inner());
        if h.route_state == next {
            return None;
        }
        let prev = h.route_state;
        h.route_state = next;
        let active = active_override.or(match next {
            EdgeRouteState::PrimaryOk => Some(primary),
            EdgeRouteState::FailoverBackup(idx) => upstreams.get(idx).copied(),
            EdgeRouteState::Degraded { .. } => None,
            EdgeRouteState::AllDown => None,
        });
        Some(EdgeAlertEvent {
            prev,
            next,
            primary,
            active,
            reason,
            strategy,
        })
    }
}

struct EgressAttemptClaim<'a> {
    health: &'a std::sync::Mutex<EgressHealth>,
    idx: usize,
    dc: i16,
    node_probe: bool,
    dc_probe: bool,
    completed: bool,
}

impl<'a> Drop for EgressAttemptClaim<'a> {
    fn drop(&mut self) {
        if !self.completed && (self.node_probe || self.dc_probe) {
            if let Ok(mut h) = self.health.lock() {
                if self.node_probe {
                    if let Some(slot) = h.nodes.get_mut(self.idx) {
                        slot.probing = false;
                    }
                }
                if self.dc_probe {
                    if let Some(slot) = h.dc_slots.get_mut(&(self.idx, self.dc)) {
                        slot.probing = false;
                    }
                }
            }
        }
    }
}

impl EgressHealth {
    fn try_claim<'a>(
        health: &'a std::sync::Mutex<EgressHealth>,
        idx: usize,
        dc: i16,
        now: Instant,
    ) -> Option<EgressAttemptClaim<'a>> {
        let mut h = health.lock().unwrap_or_else(|e| e.into_inner());
        while h.nodes.len() <= idx {
            h.nodes.push(CooldownSlot::default());
        }
        let mut node_probe = false;
        let node_slot = &mut h.nodes[idx];
        if let Some(until) = node_slot.until {
            if now < until || node_slot.probing {
                return None;
            }
            node_slot.probing = true;
            node_probe = true;
        }
        let mut dc_probe = false;
        if let Some(dc_slot) = h.dc_slots.get_mut(&(idx, dc)) {
            if let Some(until) = dc_slot.until {
                if now < until || dc_slot.probing {
                    if node_probe {
                        h.nodes[idx].probing = false;
                    }
                    return None;
                }
                dc_slot.probing = true;
                dc_probe = true;
            }
        }
        Some(EgressAttemptClaim {
            health,
            idx,
            dc,
            node_probe,
            dc_probe,
            completed: false,
        })
    }

    fn try_claim_forced_soonest<'a>(
        health: &'a std::sync::Mutex<EgressHealth>,
        node_count: usize,
        dc: i16,
    ) -> Option<(usize, EgressAttemptClaim<'a>)> {
        let mut h = health.lock().unwrap_or_else(|e| e.into_inner());
        while h.nodes.len() < node_count {
            h.nodes.push(CooldownSlot::default());
        }
        let mut best: Option<(usize, Option<Instant>)> = None;
        for idx in 0..node_count {
            let node_slot = &h.nodes[idx];
            if node_slot.probing {
                continue;
            }
            let dc_slot = h.dc_slots.get(&(idx, dc));
            if dc_slot.is_some_and(|s| s.probing) {
                continue;
            }
            let eff_until = match (node_slot.until, dc_slot.and_then(|s| s.until)) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            };
            let is_better = match (&best, eff_until) {
                (None, _) => true,
                (Some((_, Some(_))), None) => true,
                (Some((_, Some(cur_min))), Some(cand)) => cand < *cur_min,
                (Some((_, None)), _) => false,
            };
            if is_better {
                best = Some((idx, eff_until));
            }
        }
        let (idx, _) = best?;
        let mut node_probe = false;
        if h.nodes[idx].until.is_some() {
            h.nodes[idx].probing = true;
            node_probe = true;
        }
        let mut dc_probe = false;
        if let Some(dc_slot) = h.dc_slots.get_mut(&(idx, dc)) {
            if dc_slot.until.is_some() {
                dc_slot.probing = true;
                dc_probe = true;
            }
        }
        if !node_probe && !dc_probe {
            h.nodes[idx].probing = true;
            node_probe = true;
        }
        Some((
            idx,
            EgressAttemptClaim {
                health,
                idx,
                dc,
                node_probe,
                dc_probe,
                completed: false,
            },
        ))
    }
}

impl<'a> EgressAttemptClaim<'a> {
    fn record_success(mut self) {
        self.completed = true;
        let mut h = self.health.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(slot) = h.nodes.get_mut(self.idx) {
            slot.until = None;
            slot.probing = false;
            slot.failures = 0;
        }
        if let Some(slot) = h.dc_slots.get_mut(&(self.idx, self.dc)) {
            slot.until = None;
            slot.probing = false;
            slot.failures = 0;
        }
    }

    fn record_node_failure(mut self, base: Duration, max: Duration) {
        self.completed = true;
        let mut h = self.health.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(slot) = h.nodes.get_mut(self.idx) {
            slot.failures = slot.failures.saturating_add(1);
            let cooldown = compute_egress_cooldown(base, max, slot.failures);
            slot.until = Some(Instant::now() + cooldown);
            slot.probing = false;
        }
        if self.dc_probe {
            if let Some(slot) = h.dc_slots.get_mut(&(self.idx, self.dc)) {
                slot.probing = false;
            }
        }
    }

    fn record_dc_failure(mut self, base: Duration, max: Duration) {
        self.completed = true;
        let mut h = self.health.lock().unwrap_or_else(|e| e.into_inner());
        if self.node_probe {
            if let Some(slot) = h.nodes.get_mut(self.idx) {
                slot.until = None;
                slot.probing = false;
                slot.failures = 0;
            }
        }
        let dc_slot = h.dc_slots.entry((self.idx, self.dc)).or_default();
        dc_slot.failures = dc_slot.failures.saturating_add(1);
        let cooldown = compute_egress_cooldown(base, max, dc_slot.failures);
        dc_slot.until = Some(Instant::now() + cooldown);
        dc_slot.probing = false;
    }
}

struct CoverResolver {
    target: String,
    ttl: Duration,
    cached: std::sync::RwLock<Option<(Vec<SocketAddr>, Instant)>>,
    rr: std::sync::atomic::AtomicUsize,
}

impl CoverResolver {
    fn new(target: String, ttl: Duration) -> Self {
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

    fn is_static_ip(&self) -> bool {
        self.target.parse::<SocketAddr>().is_ok()
    }

    fn update_addrs(&self, addrs: Vec<SocketAddr>) {
        if !addrs.is_empty() {
            *self.cached.write().unwrap_or_else(|e| e.into_inner()) = Some((addrs, Instant::now()));
        }
    }

    fn has_cached(&self) -> bool {
        self.cached
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .is_some_and(|(v, _)| !v.is_empty())
    }

    fn next_addr(&self) -> Option<SocketAddr> {
        let guard = self.cached.read().unwrap_or_else(|e| e.into_inner());
        let (addrs, _) = guard.as_ref()?;
        if addrs.is_empty() {
            return None;
        }
        let idx = self.rr.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % addrs.len();
        Some(addrs[idx])
    }

    async fn refresh_with<F, Fut>(
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

    async fn refresh_once(&self, dns_timeout: Duration, counters: &telemetry::Counters) -> bool {
        self.refresh_with(dns_timeout, counters, |target| async move {
            let iter = tokio::net::lookup_host(target).await?;
            Ok(iter.collect::<Vec<_>>())
        })
        .await
    }
}

fn spawn_cover_resolver(
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

struct State {
    secrets: std::sync::RwLock<Arc<Vec<NamedSecret>>>,
    sni: String,
    allowed_snis: std::sync::RwLock<Arc<String>>,
    cover_resolver: Arc<CoverResolver>,
    enable_dd: bool,
    proxy_protocol: bool,
    cover_permits: Semaphore,
    dcs: HashMap<i16, SocketAddr>,
    dc_media_overrides: HashMap<i16, Vec<SocketAddr>>,
    egress_upstreams: Vec<SocketAddr>,
    egress_strategy: EgressStrategy,
    egress_token: [u8; 16],
    egress_rr: std::sync::atomic::AtomicUsize,
    egress_health: std::sync::Mutex<EgressHealth>,
    egress_cooldown: Duration,
    egress_cooldown_max: Duration,
    egress_probe_interval: Duration,
    egress_probe_degraded_interval: Duration,
    egress_hedge_ms: u64,
    egress_use_mtv3: bool,
    client_hello: Duration,
    handshake: Duration,
    idle: Duration,
    drain: Duration,
    flight: wire::ServerFlightProfile,
    flight_shaping: bool,
    client_mss_bulk: Option<u16>,
    replay: Mutex<ReplayCache>,
    counters: Arc<telemetry::Counters>,
    alert_webhook_url: Option<String>,
    alerts_file: Option<PathBuf>,
    diagnostics: bool,
}

fn format_edge_alert_message(ev: &EdgeAlertEvent) -> String {
    if ev.reason == "background_egress_probe_dc2" {
        return match ev.next {
            EdgeRouteState::PrimaryOk => {
                "Фоновая проверка DC2: доступность egress восстановилась.".into()
            }
            EdgeRouteState::FailoverBackup(_) => format!(
                "Фоновая проверка DC2: основной egress ({}) недоступен, резервный отвечает.",
                ev.primary
            ),
            EdgeRouteState::Degraded { healthy, total } => {
                format!("Фоновая проверка DC2: доступно egress {healthy} из {total}.")
            }
            EdgeRouteState::AllDown => "Фоновая проверка DC2: все egress недоступны.".into(),
        };
    }
    match ev.next {
        EdgeRouteState::FailoverBackup(_) => format!(
            "Основной egress ({}) недоступен — трафик переключён на резервный egress ({}).",
            ev.primary,
            ev.active.map(|a| a.to_string()).unwrap_or_else(|| "unknown".into())
        ),
        EdgeRouteState::Degraded { healthy, total } => format!(
            "Часть узлов egress недоступна в режиме round-robin: доступно {} из {} (последний успешный: {}). Причина: {}",
            healthy,
            total,
            ev.active.map(|a| a.to_string()).unwrap_or_else(|| "нет".into()),
            ev.reason
        ),
        EdgeRouteState::AllDown => format!(
            "Все узлы egress недоступны (основной: {}). Причина: {}",
            ev.primary, ev.reason
        ),
        EdgeRouteState::PrimaryOk => match ev.strategy {
            EgressStrategy::Ordered => format!(
                "Основной egress ({}) восстановился — трафик вернулся на основной выход.",
                ev.primary
            ),
            EgressStrategy::RoundRobin => {
                "Все узлы egress снова доступны в режиме round-robin.".to_string()
            }
        },
    }
}

fn send_http_alert_webhook(url: &str, payload: &str) -> std::io::Result<()> {
    use std::{
        io::{BufRead, BufReader, Write},
        net::ToSocketAddrs,
    };
    // Minimal stdlib-only HTTP POST for http://host[:port]/path webhooks (no extra crate deps).
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| std::io::Error::other("expected an HTTP webhook URL"))?;
    let (host_port, path) = match rest.find('/') {
        Some(pos) => (&rest[..pos], &rest[pos..]),
        None => (rest, "/"),
    };
    let addr = if host_port.contains(':') {
        host_port.to_string()
    } else {
        format!("{host_port}:80")
    };
    let body = payload.as_bytes();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host_port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let endpoint = addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::other("webhook address did not resolve"))?;
    let limit = Duration::from_secs(3);
    let mut stream = std::net::TcpStream::connect_timeout(&endpoint, limit)?;
    stream.set_write_timeout(Some(limit))?;
    stream.set_read_timeout(Some(limit))?;
    stream.write_all(req.as_bytes())?;
    stream.write_all(body)?;
    let mut status = String::new();
    use std::io::Read;
    BufReader::new(stream).take(256).read_line(&mut status)?;
    match status
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
    {
        Some(200..=299) => Ok(()),
        _ => Err(std::io::Error::other("webhook did not return HTTP 2xx")),
    }
}

fn emit_edge_route_alert(state: &State, ev: EdgeAlertEvent) {
    let ts_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let message = format_edge_alert_message(&ev);
    let payload = json!({
        "ts_unix_ms": ts_unix_ms,
        "event": "edge_route_alert",
        "prev_state": ev.prev.as_str(),
        "state": ev.next.as_str(),
        "primary": ev.primary.to_string(),
        "active": ev.active.map(|a| a.to_string()),
        "reason": ev.reason,
        "message": message,
    });
    telemetry::event("edge_route_alert", 0, payload.clone());

    if let Some(alerts_path) = &state.alerts_file {
        if let Some(parent) = alerts_path.parent() {
            if parent.exists() {
                let line = format!("{payload}\n");
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(alerts_path)
                {
                    use std::io::Write;
                    let _ = f.write_all(line.as_bytes());
                }
            }
        }
    }

    if let Some(url) = state.alert_webhook_url.clone() {
        let body = payload.to_string();
        std::thread::spawn(move || {
            for delay in [0, 2, 8] {
                std::thread::sleep(Duration::from_secs(delay));
                if send_http_alert_webhook(&url, &body).is_ok() {
                    return;
                }
            }
            telemetry::event("edge_alert_webhook_failed", 0, json!({"attempts": 3}));
        });
    }
}

const BACKGROUND_PROBE_DCS: [i16; 4] = [2, 4, -2, -4];

async fn monitor_edge_egress(state: Arc<State>, period: Duration) {
    let mut previous = None;
    let mut confirmed = None;
    let mut dc_rot: usize = 0;
    let mut first = true;
    let mut next_wait = period;
    loop {
        if !first {
            tokio::time::sleep(next_wait).await;
        }
        first = false;
        let probe_dc = BACKGROUND_PROBE_DCS[dc_rot % BACKGROUND_PROBE_DCS.len()];
        dc_rot = dc_rot.wrapping_add(1);
        let mut probes = tokio::task::JoinSet::new();
        for (idx, &address) in state.egress_upstreams.iter().enumerate() {
            let token = state.egress_token;
            let use_mtv3 = state.egress_use_mtv3;
            probes.spawn(async move {
                let limit = Duration::from_secs(4);
                let available = timeout(
                    limit,
                    probe_egress_endpoint_proto(address, probe_dc, &token, limit, use_mtv3),
                )
                .await
                .is_ok_and(|probe| probe.dc_reachable);
                (idx, available)
            });
        }
        let mut available = vec![false; state.egress_upstreams.len()];
        while let Some(result) = probes.join_next().await {
            if let Ok((idx, ok)) = result {
                available[idx] = ok;
                EgressHealth::apply_background_probe(
                    &state.egress_health,
                    idx,
                    probe_dc.abs(),
                    ok,
                    state.egress_cooldown,
                    state.egress_cooldown_max,
                );
            }
        }
        let any_down = available.iter().any(|ok| !*ok);
        next_wait = if any_down {
            state.egress_probe_degraded_interval.min(period)
        } else {
            period
        };
        let route = match available.iter().position(|ok| *ok) {
            None => EdgeRouteState::AllDown,
            Some(0) if state.egress_strategy == EgressStrategy::Ordered => {
                EdgeRouteState::PrimaryOk
            }
            Some(idx) if state.egress_strategy == EgressStrategy::Ordered => {
                EdgeRouteState::FailoverBackup(idx)
            }
            Some(_) => {
                let healthy = available.iter().filter(|ok| **ok).count();
                let total = available.len();
                if healthy == total {
                    EdgeRouteState::PrimaryOk
                } else {
                    EdgeRouteState::Degraded { healthy, total }
                }
            }
        };
        // A single transient probe should not trigger an alert; require two consecutive matching observations.
        if previous == Some(route) && confirmed != Some(route) {
            confirmed = Some(route);
            if let Some(event) = EgressHealth::transition_route_state(
                &state.egress_health,
                route,
                &state.egress_upstreams,
                "background_egress_probe_dc2".to_string(),
                state.egress_strategy,
                None,
            ) {
                emit_edge_route_alert(&state, event);
            }
        }
        previous = Some(route);
    }
}

impl State {
    fn current_secrets(&self) -> Arc<Vec<NamedSecret>> {
        self.secrets
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn current_allowed_snis(&self) -> Arc<String> {
        let cur = self
            .allowed_snis
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if cur.is_empty() {
            Arc::new(self.sni.clone())
        } else {
            cur
        }
    }

    fn reload_secrets(&self, config: &Config) {
        if config.users_file.is_some() {
            match config.load_secrets_allow_empty() {
                Ok(new_secrets) => {
                    let cur = self.current_secrets();
                    let same = cur.len() == new_secrets.len()
                        && cur
                            .iter()
                            .zip(new_secrets.iter())
                            .all(|(a, b)| a.name == b.name && a.key == b.key);
                    if !same {
                        let count = new_secrets.len();
                        *self.secrets.write().unwrap_or_else(|e| e.into_inner()) =
                            Arc::new(new_secrets);
                        telemetry::event("users_reloaded", 0, json!({"users": count}));
                    }
                }
                Err(err) => {
                    telemetry::event(
                        "users_reload_failed",
                        0,
                        json!({"error": format!("{err:#}")}),
                    );
                }
            }
        }
        let next_snis = config.allowed_snis();
        let cur_snis = self.current_allowed_snis();
        if *cur_snis != next_snis {
            let count = next_snis.split(',').filter(|s| !s.is_empty()).count();
            *self.allowed_snis.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(next_snis);
            telemetry::event("allowed_sni_reloaded", 0, json!({"sni_count": count}));
        }
    }
}

fn spawn_users_reloader(
    state: Arc<State>,
    cfg: Config,
    period: Duration,
    mut stop_rx: tokio::sync::oneshot::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(period);
        interval.tick().await;
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = &mut stop_rx => break,
            }
            state.reload_secrets(&cfg);
        }
    })
}

const RUNTIME_STATS_DEFAULT_PATH: &str = "/var/lib/mtevil/runtime-stats.json";

fn parse_proc_self_limits_nofile(text: &str) -> Option<usize> {
    for line in text.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("Max open files") {
            let first = rest.split_whitespace().next()?;
            if first.eq_ignore_ascii_case("unlimited") {
                return Some(usize::MAX);
            }
            return first.parse::<usize>().ok();
        }
    }
    None
}

fn detect_rlimit_nofile() -> Option<usize> {
    let text = std::fs::read_to_string("/proc/self/limits").ok()?;
    parse_proc_self_limits_nofile(&text)
}

fn detect_fd_used() -> Option<usize> {
    std::fs::read_dir("/proc/self/fd").ok().map(|rd| rd.count())
}

fn spawn_metrics_server(
    listener: TcpListener,
    counters: Arc<telemetry::Counters>,
    breaker_source: Option<Arc<State>>,
    fd_limit: Option<usize>,
    mut stop_rx: tokio::sync::oneshot::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                res = listener.accept() => res,
                _ = &mut stop_rx => break,
            };
            let Ok((mut stream, _)) = accepted else {
                continue;
            };
            let counters = counters.clone();
            let breaker_source = breaker_source.clone();
            tokio::spawn(async move {
                let mut req_buf = [0u8; 1024];
                let Ok(Ok(n)) = timeout(Duration::from_secs(2), stream.read(&mut req_buf)).await
                else {
                    return;
                };
                if n == 0 {
                    return;
                }
                let first_line = std::str::from_utf8(&req_buf[..n])
                    .unwrap_or("")
                    .lines()
                    .next()
                    .unwrap_or("");
                let mut parts = first_line.split_whitespace();
                let method = parts.next().unwrap_or("");
                let path = parts.next().unwrap_or("");
                let resp = if method == "GET"
                    && (path == "/metrics" || path.starts_with("/metrics?"))
                {
                    let breaker_states = breaker_source
                        .as_ref()
                        .map(|st| {
                            EgressHealth::snapshot_breaker_states(
                                &st.egress_health,
                                &st.egress_upstreams,
                            )
                        })
                        .unwrap_or_default();
                    let body =
                        counters.render_prometheus(&breaker_states, detect_fd_used(), fd_limit);
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                } else {
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_string()
                };
                let _ = timeout(Duration::from_secs(2), stream.write_all(resp.as_bytes())).await;
                let _ = stream.shutdown().await;
            });
        }
    })
}

fn compute_effective_max_connections(
    configured_max: usize,
    rlimit_nofile: Option<usize>,
) -> Result<usize> {
    let effective = match rlimit_nofile {
        Some(nofile) => configured_max.min(nofile.saturating_sub(128) / 2),
        None => configured_max,
    };
    ensure!(
        effective >= 16,
        "effective max_connections ({effective}) is below minimum 16 (configured max_connections={configured_max}, rlimit_nofile={rlimit_nofile:?})"
    );
    Ok(effective)
}

// Query TCP_INFO on Linux to measure TCP retransmissions on mtevil's own sockets only,
// excluding unrelated VPS traffic even when running with network_mode: host.
#[cfg(unix)]
#[allow(unsafe_code)]
fn sample_fd_retrans(
    fd: Option<std::os::fd::RawFd>,
    prev: &mut u32,
    acc: &std::sync::atomic::AtomicU64,
) {
    #[cfg(target_os = "linux")]
    {
        let Some(raw_fd) = fd else {
            return;
        };
        #[repr(C)]
        #[derive(Default)]
        struct LinuxTcpInfoPrefix {
            tcpi_state: u8,
            tcpi_ca_state: u8,
            tcpi_retransmits: u8,
            tcpi_probes: u8,
            tcpi_backoff: u8,
            tcpi_options: u8,
            tcpi_snd_rcv_wscale: u8,
            tcpi_delivery_rate_app_limited: u8,
            tcpi_rto: u32,
            tcpi_ato: u32,
            tcpi_snd_mss: u32,
            tcpi_rcv_mss: u32,
            tcpi_unacked: u32,
            tcpi_sacked: u32,
            tcpi_lost: u32,
            tcpi_retrans: u32,
            tcpi_fackets: u32,
            tcpi_last_data_sent: u32,
            tcpi_last_ack_sent: u32,
            tcpi_last_data_recv: u32,
            tcpi_last_ack_recv: u32,
            tcpi_pmtu: u32,
            tcpi_rcv_ssthresh: u32,
            tcpi_rtt: u32,
            tcpi_rttvar: u32,
            tcpi_snd_ssthresh: u32,
            tcpi_snd_cwnd: u32,
            tcpi_advmss: u32,
            tcpi_reordering: u32,
            tcpi_rcv_rtt: u32,
            tcpi_rcv_space: u32,
            tcpi_total_retrans: u32,
        }
        extern "C" {
            fn getsockopt(
                sockfd: i32,
                level: i32,
                optname: i32,
                optval: *mut std::ffi::c_void,
                optlen: *mut u32,
            ) -> i32;
        }
        const IPPROTO_TCP: i32 = 6;
        const TCP_INFO: i32 = 11;
        let mut info = LinuxTcpInfoPrefix::default();
        let mut len = std::mem::size_of::<LinuxTcpInfoPrefix>() as u32;
        let rc = unsafe {
            getsockopt(
                raw_fd,
                IPPROTO_TCP,
                TCP_INFO,
                (&mut info as *mut LinuxTcpInfoPrefix).cast::<std::ffi::c_void>(),
                &mut len,
            )
        };
        if rc == 0 && (len as usize) >= std::mem::size_of::<LinuxTcpInfoPrefix>() {
            let cur = info.tcpi_total_retrans;
            if cur >= *prev {
                let delta = cur - *prev;
                if delta > 0 {
                    acc.fetch_add(u64::from(delta), std::sync::atomic::Ordering::Relaxed);
                }
                *prev = cur;
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (fd, prev, acc);
    }
}

#[cfg(not(unix))]
fn sample_fd_retrans(_fd: Option<i32>, _prev: &mut u32, _acc: &std::sync::atomic::AtomicU64) {}

#[cfg(unix)]
fn stream_raw_fd(stream: &TcpStream) -> Option<std::os::fd::RawFd> {
    use std::os::fd::{AsFd, AsRawFd};
    Some(stream.as_fd().as_raw_fd())
}

#[cfg(not(unix))]
fn stream_raw_fd(_stream: &TcpStream) -> Option<i32> {
    None
}

fn write_runtime_stats_atomic(
    path: &std::path::Path,
    counters: &telemetry::Counters,
    role: &str,
) -> Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            return Ok(());
        }
    }
    let val = counters.snapshot_json(role);
    let encoded = serde_json::to_string(&val)?;
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp)?;
    f.write_all(encoded.as_bytes())?;
    f.write_all(b"\n")?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn spawn_stats_writer(
    counters: Arc<telemetry::Counters>,
    role: &'static str,
    path: PathBuf,
    period: Duration,
    mut stop_rx: tokio::sync::oneshot::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    counters.ensure_started();
    let _ = write_runtime_stats_atomic(&path, &counters, role);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(period);
        interval.tick().await;
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = &mut stop_rx => break,
            }
            let _ = write_runtime_stats_atomic(&path, &counters, role);
        }
        let _ = write_runtime_stats_atomic(&path, &counters, role);
    })
}

// OS-level exclusive advisory file lock (flock on Unix, LockFileEx on Windows) so the
// kernel automatically releases the lock if a CLI user-add/user-del process crashes.
#[allow(unsafe_code)]
fn lock_users_file(users_file: &std::path::Path) -> Result<std::fs::File> {
    if let Some(parent) = users_file.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let lock_path = users_file.with_extension("lock");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .with_context(|| format!("opening lock file {}", lock_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        extern "C" {
            fn flock(fd: i32, operation: i32) -> i32;
        }
        const LOCK_EX: i32 = 2;
        let rc = unsafe { flock(file.as_raw_fd(), LOCK_EX) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("locking {}", lock_path.display()));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        #[repr(C)]
        struct Overlapped {
            internal: usize,
            internal_high: usize,
            offset: u32,
            offset_high: u32,
            h_event: isize,
        }
        extern "system" {
            fn LockFileEx(
                h_file: isize,
                dw_flags: u32,
                dw_reserved: u32,
                n_number_of_bytes_to_lock_low: u32,
                n_number_of_bytes_to_lock_high: u32,
                lp_overlapped: *mut Overlapped,
            ) -> i32;
        }
        const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x0000_0002;
        let mut overlapped = Overlapped {
            internal: 0,
            internal_high: 0,
            offset: 0,
            offset_high: 0,
            h_event: 0,
        };
        let ok = unsafe {
            LockFileEx(
                file.as_raw_handle() as isize,
                LOCKFILE_EXCLUSIVE_LOCK,
                0,
                1,
                0,
                &mut overlapped,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("locking {}", lock_path.display()));
        }
    }
    Ok(file)
}

fn write_users_map_atomic(
    users_file: &std::path::Path,
    map: &std::collections::BTreeMap<String, String>,
) -> Result<()> {
    use std::io::Write;
    let encoded = Zeroizing::new(serde_json::to_string_pretty(map)?);
    let tmp = users_file.with_extension(format!("tmp.{}", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    {
        let mut f = options.open(&tmp)?;
        f.write_all(encoded.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, users_file)?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = Args::parse();
    if let Some(action) = args.command.take() {
        match action {
            Action::Secret { output } => {
                use rand::RngCore;
                use std::io::Write;
                let mut bytes = Zeroizing::new([0u8; 16]);
                rand::rngs::OsRng.fill_bytes(&mut bytes[..]);
                let encoded = Zeroizing::new(hex::encode(&bytes[..]));
                let mut options = std::fs::OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                let mut file = options
                    .open(output)
                    .context("creating secret (existing files are never overwritten)")?;
                file.write_all(encoded.as_bytes())?;
                file.sync_all()?;
                println!("secret created");
                return Ok(());
            }
            Action::UserAdd { users_file, name } => {
                use rand::RngCore;
                ensure!(
                    !name.is_empty()
                        && name.len() <= 32
                        && name
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
                    "invalid user name"
                );
                let _lock = lock_users_file(&users_file)?;
                let mut map: std::collections::BTreeMap<String, String> = if users_file.exists() {
                    let text = Zeroizing::new(std::fs::read_to_string(&users_file)?);
                    serde_json::from_str(&text).context("invalid users file JSON")?
                } else {
                    std::collections::BTreeMap::new()
                };
                ensure!(
                    !map.contains_key(&name),
                    "user '{name}' already exists (refusing to overwrite)"
                );
                let mut bytes = Zeroizing::new([0u8; 16]);
                rand::rngs::OsRng.fill_bytes(&mut bytes[..]);
                map.insert(name.clone(), hex::encode(&bytes[..]));
                write_users_map_atomic(&users_file, &map)?;
                println!("user '{name}' added");
                return Ok(());
            }
            Action::UserDel { users_file, name } => {
                let _lock = lock_users_file(&users_file)?;
                ensure!(users_file.exists(), "users file does not exist");
                let text = Zeroizing::new(std::fs::read_to_string(&users_file)?);
                let mut map: std::collections::BTreeMap<String, String> =
                    serde_json::from_str(&text).context("invalid users file JSON")?;
                ensure!(
                    map.remove(&name).is_some(),
                    "user '{name}' not found in users file"
                );
                write_users_map_atomic(&users_file, &map)?;
                println!("user '{name}' deleted");
                return Ok(());
            }
            Action::UserList { users_file } => {
                if !users_file.exists() {
                    return Ok(());
                }
                let text = Zeroizing::new(std::fs::read_to_string(&users_file)?);
                let map: std::collections::BTreeMap<String, String> =
                    serde_json::from_str(&text).context("invalid users file JSON")?;
                for name in map.keys() {
                    println!("{name}");
                }
                return Ok(());
            }
            Action::Link {
                config,
                server,
                port,
                dd,
                user,
                all,
                sni,
            } => {
                ensure!(
                    !server.is_empty()
                        && server.len() <= 253
                        && port > 0
                        && server
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b".:-[]".contains(&b)),
                    "invalid server or port"
                );
                let config = Config::load(&config)?;
                let target_sni = match sni.as_deref() {
                    Some(custom) => {
                        ensure!(
                            config::is_valid_sni_hostname(custom),
                            "invalid SNI hostname"
                        );
                        custom
                    }
                    None => config.sni.as_str(),
                };
                let secrets = config.secrets()?;
                let server = server
                    .replace(':', "%3A")
                    .replace('[', "%5B")
                    .replace(']', "%5D");
                let selected: Vec<&NamedSecret> = if all {
                    secrets.iter().collect()
                } else if let Some(target) = user.as_deref() {
                    let found = secrets
                        .iter()
                        .find(|s| s.name == target)
                        .with_context(|| format!("user '{target}' not found"))?;
                    vec![found]
                } else {
                    vec![&secrets[0]]
                };
                for secret in selected {
                    let key = hex::encode(&secret.key[..]);
                    let encoded = if dd {
                        ensure!(config.enable_dd, "dd mode is disabled in this config");
                        format!("dd{key}")
                    } else {
                        format!("ee{key}{}", hex::encode(target_sni.as_bytes()))
                    };
                    if all || user.is_some() {
                        println!(
                            "{}: https://t.me/proxy?server={server}&port={port}&secret={encoded}",
                            secret.name
                        );
                    } else {
                        println!("https://t.me/proxy?server={server}&port={port}&secret={encoded}");
                    }
                }
                return Ok(());
            }
            Action::Health { address } => {
                timeout(Duration::from_secs(2), TcpStream::connect(address)).await??;
                println!("listener reachable; DC connectivity not checked");
                return Ok(());
            }
            Action::CheckEgress { config, dc } => {
                ensure!((1..=5).contains(&dc), "DC id must be 1..5");
                let config = Config::load(&config)?;
                ensure!(
                    !config.egress_upstreams.is_empty(),
                    "egress_upstreams is empty in config"
                );
                let token = config.egress_token()?;
                let per_try = Duration::from_secs(config.handshake_timeout_secs.clamp(1, 5));
                let mut results = Vec::with_capacity(config.egress_upstreams.len());
                let mut all_ok = true;
                for addr in &config.egress_upstreams {
                    let probe = probe_egress_endpoint_proto(
                        *addr,
                        dc,
                        &token,
                        per_try,
                        config.egress_use_mtv3,
                    )
                    .await;
                    if !probe.dc_reachable {
                        all_ok = false;
                    }
                    results.push(json!({
                        "address": addr.to_string(),
                        "dc_tested": dc,
                        "tcp_reachable": probe.tcp_reachable,
                        "token_status": probe.token_status,
                        "dc_reachable": probe.dc_reachable,
                        "status": if probe.dc_reachable { "ok" } else { "fail" },
                        "detail": probe.detail,
                    }));
                }
                println!("{}", serde_json::to_string_pretty(&results)?);
                ensure!(all_ok, "one or more egress checks failed");
                return Ok(());
            }
            Action::Stats { stats_file } => {
                let text = std::fs::read_to_string(&stats_file).with_context(|| {
                    format!("reading runtime stats file {}", stats_file.display())
                })?;
                let val: serde_json::Value = serde_json::from_str(&text).with_context(|| {
                    format!("parsing runtime stats file {}", stats_file.display())
                })?;
                println!("{}", serde_json::to_string_pretty(&val)?);
                return Ok(());
            }
            Action::ProbeTelegram {
                config,
                address,
                dc,
                timeout_secs,
            } => {
                ensure!((1..=5).contains(&dc), "DC id must be 1..5");
                let cfg = Config::load(&config)?;
                let target_addr = address.unwrap_or_else(|| {
                    let ip = if cfg.listen.ip().is_unspecified() {
                        if cfg.listen.is_ipv6() {
                            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
                        } else {
                            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                        }
                    } else {
                        cfg.listen.ip()
                    };
                    SocketAddr::new(ip, cfg.listen.port())
                });
                let limit = Duration::from_secs(timeout_secs.clamp(1, 30));
                let rtt_ms = probe_telegram_e2e(&cfg, target_addr, dc, limit).await?;
                println!(
                    "{}",
                    json!({
                        "status": "ok",
                        "role": match cfg.role {
                            Role::Direct => if cfg.egress_upstreams.is_empty() { "direct" } else { "edge" },
                            Role::Edge => "edge",
                            Role::Egress => "egress",
                        },
                        "address": target_addr.to_string(),
                        "dc": dc,
                        "rtt_ms": rtt_ms,
                    })
                );
                return Ok(());
            }
        }
    }
    let check_config = args.check_config;
    let config = args.runtime_config()?;
    let dcs = config.datacenters().unwrap_or_default();
    let dc_media_overrides = config.dc_media_overrides().unwrap_or_default();
    let egress_token = config.egress_token()?;
    let stats_path = std::env::var_os("MTEVIL_STATS_FILE")
        .map(PathBuf::from)
        .or_else(|| {
            config
                .replay_file
                .as_ref()
                .or(config.secret_file.as_ref())
                .or(config.egress_token_file.as_ref())
                .and_then(|p| p.parent().map(|dir| dir.join("runtime-stats.json")))
        })
        .unwrap_or_else(|| PathBuf::from(RUNTIME_STATS_DEFAULT_PATH));
    if config.role == Role::Egress {
        if check_config {
            println!("configuration valid");
            return Ok(());
        }
        let rlimit_nofile = detect_rlimit_nofile();
        let effective_max =
            compute_effective_max_connections(config.max_connections, rlimit_nofile)?;
        let allow_from = config.parsed_egress_allow_from()?;
        let listener = bind_listener(config.listen, None)?;
        let local_addr = listener.local_addr()?;
        if !config::is_loopback_or_private_ip(local_addr.ip()) {
            telemetry::event(
                "egress_public_listen_warning",
                0,
                json!({
                    "listen": local_addr.to_string(),
                    "allowlist_empty": allow_from.is_empty(),
                    "warning": "egress listener is bound to a non-private/non-loopback address"
                }),
            );
        }
        telemetry::event(
            "startup",
            0,
            json!({
                "version":BUILD_VERSION,
                "role":"egress",
                "listen":local_addr.to_string(),
                "max_connections":config.max_connections,
                "effective_max_connections":effective_max,
                "rlimit_nofile":rlimit_nofile,
                "authenticated":config.egress_token_file.is_some(),
                "accept_legacy_mtv2":config.egress_accept_legacy,
                "allow_from_cidrs":allow_from.len(),
                "test_only":true
            }),
        );
        let counters = Arc::new(telemetry::Counters::default());
        counters.ensure_started();
        let (stats_stop_tx, stats_stop_rx) = tokio::sync::oneshot::channel::<()>();
        let stats_task = spawn_stats_writer(
            counters.clone(),
            "egress",
            stats_path,
            Duration::from_millis(500),
            stats_stop_rx,
        );
        let (metrics_stop_tx, metrics_stop_rx) = tokio::sync::oneshot::channel::<()>();
        let metrics_task = match config.metrics_listen {
            Some(addr) => {
                let m_listener = TcpListener::bind(addr)
                    .await
                    .with_context(|| format!("binding metrics listener on {addr}"))?;
                Some(spawn_metrics_server(
                    m_listener,
                    counters.clone(),
                    None,
                    rlimit_nofile,
                    metrics_stop_rx,
                ))
            }
            None => None,
        };
        let security = EgressSecurityConfig {
            accept_legacy: config.egress_accept_legacy,
            allow_from,
            max_failed_per_ip: config.egress_max_failed_per_ip,
            failed_window: Duration::from_secs(60),
            max_unauth_handshakes: (effective_max / 4).clamp(4, 128),
            dc_media_overrides: dc_media_overrides.clone(),
        };
        let dcs_arc = Arc::new(dcs);
        let dc_monitor = (config.dc_probe_interval_secs > 0).then(|| {
            tokio::spawn(monitor_dc_reachability(
                dcs_arc.clone(),
                Arc::new(dc_media_overrides),
                counters.clone(),
                Duration::from_secs(config.dc_probe_interval_secs),
            ))
        });
        #[cfg(unix)]
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let res = serve_egress_with_security(
            listener,
            dcs_arc,
            egress_token,
            effective_max,
            Duration::from_secs(config.handshake_timeout_secs),
            Duration::from_secs(config.idle_timeout_secs),
            Duration::from_secs(config.drain_timeout_secs),
            counters,
            security,
            async {
                #[cfg(unix)]
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {},
                    _ = terminate.recv() => {},
                }
                #[cfg(not(unix))]
                let _ = tokio::signal::ctrl_c().await;
            },
        )
        .await;
        if let Some(task) = dc_monitor {
            task.abort();
            let _ = task.await;
        }
        let _ = metrics_stop_tx.send(());
        if let Some(task) = metrics_task {
            let _ = task.await;
        }
        let _ = stats_stop_tx.send(());
        let _ = stats_task.await;
        return res;
    }
    let secrets = config.secrets()?;
    if check_config {
        println!("configuration valid");
        return Ok(());
    }
    let rlimit_nofile = detect_rlimit_nofile();
    let effective_max = compute_effective_max_connections(config.max_connections, rlimit_nofile)?;
    let replay_ttl = Duration::from_secs(300);
    let (replay, replay_load_status) = match &config.replay_file {
        Some(path) => ReplayCache::load_with_status(path.clone(), 65536, replay_ttl),
        None => (
            ReplayCache::new(65536, replay_ttl),
            replay::ReplayLoadStatus::Disabled,
        ),
    };
    if replay_load_status == replay::ReplayLoadStatus::CorruptedReinitialized {
        telemetry::event(
            "replay_table_reinitialized",
            0,
            json!({"reason": "corrupted_or_unreadable_replay_file"}),
        );
    }
    let max_cover_connections = (effective_max / 4).max(1);
    let user_count = secrets.len();
    let persistent_replay = config.replay_file.is_some();
    let reload_config = (config.users_file.is_some() || config.allowed_sni_file().is_some())
        .then(|| config.clone());
    let allowed_snis = config.allowed_snis();
    let egress_count = config.egress_upstreams.len();
    let counters = Arc::new(telemetry::Counters::default());
    counters.ensure_started();
    let alerts_file = std::env::var_os("MTEVIL_ALERTS_FILE")
        .map(PathBuf::from)
        .or_else(|| stats_path.parent().map(|dir| dir.join("edge-alerts.jsonl")));
    let cover_resolver = Arc::new(CoverResolver::new(
        config.cover,
        Duration::from_secs(config.cover_dns_ttl_secs),
    ));
    let handshake_dur = Duration::from_secs(config.handshake_timeout_secs);
    let _ = cover_resolver.refresh_once(handshake_dur, &counters).await;
    let state = Arc::new(State {
        secrets: std::sync::RwLock::new(Arc::new(secrets)),
        sni: config.sni,
        allowed_snis: std::sync::RwLock::new(Arc::new(allowed_snis)),
        cover_resolver: cover_resolver.clone(),
        enable_dd: config.enable_dd,
        proxy_protocol: config.proxy_protocol,
        cover_permits: Semaphore::new(max_cover_connections),
        dcs,
        dc_media_overrides,
        egress_upstreams: config.egress_upstreams,
        egress_strategy: config.egress_strategy,
        egress_token,
        egress_rr: std::sync::atomic::AtomicUsize::new(0),
        egress_health: std::sync::Mutex::new(EgressHealth::new(egress_count)),
        egress_cooldown: Duration::from_millis(config.egress_cooldown_base_ms),
        egress_cooldown_max: Duration::from_millis(config.egress_cooldown_max_ms),
        egress_probe_interval: Duration::from_secs(config.egress_probe_interval_secs),
        egress_probe_degraded_interval: Duration::from_secs(
            config.egress_probe_degraded_interval_secs,
        ),
        egress_hedge_ms: config.egress_hedge_ms,
        egress_use_mtv3: config.egress_use_mtv3,
        client_hello: Duration::from_secs(config.client_hello_timeout_secs),
        handshake: Duration::from_secs(config.handshake_timeout_secs),
        idle: Duration::from_secs(config.idle_timeout_secs),
        drain: Duration::from_secs(config.drain_timeout_secs),
        flight: wire::ServerFlightProfile {
            cert_bytes: config.fake_tls_cert_bytes,
            jitter: config.fake_tls_cert_jitter,
        },
        flight_shaping: config.flight_shaping,
        client_mss_bulk: config.client_mss_bulk,
        replay: Mutex::new(replay),
        counters,
        alert_webhook_url: config.alert_webhook_url,
        alerts_file,
        diagnostics: config.diagnostics,
    });
    let role_str: &'static str = if state.egress_upstreams.is_empty() {
        "direct"
    } else {
        "edge"
    };
    let (stats_stop_tx, stats_stop_rx) = tokio::sync::oneshot::channel::<()>();
    let stats_task = spawn_stats_writer(
        state.counters.clone(),
        role_str,
        stats_path,
        Duration::from_millis(500),
        stats_stop_rx,
    );
    let (metrics_stop_tx, metrics_stop_rx) = tokio::sync::oneshot::channel::<()>();
    let metrics_task = match config.metrics_listen {
        Some(addr) => {
            let m_listener = TcpListener::bind(addr)
                .await
                .with_context(|| format!("binding metrics listener on {addr}"))?;
            Some(spawn_metrics_server(
                m_listener,
                state.counters.clone(),
                Some(state.clone()),
                rlimit_nofile,
                metrics_stop_rx,
            ))
        }
        None => None,
    };
    let listener = bind_listener(config.listen, config.client_mss)?;
    telemetry::event(
        "startup",
        0,
        json!({
            "version":BUILD_VERSION,
            "role": role_str,
            "listen":listener.local_addr()?.to_string(),
            "max_connections":config.max_connections,
            "effective_max_connections":effective_max,
            "rlimit_nofile":rlimit_nofile,
            "max_cover_connections":max_cover_connections,
            "users":user_count,
            "persistent_replay":persistent_replay,
            "replay_load_status":replay_load_status.as_str(),
            "replay_loaded_entries":replay_load_status.loaded_entries(),
            "fake_tls_cert_bytes":config.fake_tls_cert_bytes,
            "fake_tls_cert_jitter":config.fake_tls_cert_jitter,
            "flight_shaping":state.flight_shaping,
            "client_mss":config.client_mss,
            "client_mss_bulk":config.client_mss_bulk,
            "egress_upstreams":state.egress_upstreams.len(),
            "egress_strategy":match state.egress_strategy {
                EgressStrategy::RoundRobin => "round-robin",
                EgressStrategy::Ordered => "ordered",
            },
            "test_only":true
        }),
    );
    let (flush_stop_tx, mut flush_stop_rx) = tokio::sync::oneshot::channel::<()>();
    let flush_task = persistent_replay.then(|| {
        let state = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = interval.tick() => {}
                    _ = &mut flush_stop_rx => break,
                }
                let dirty = state.replay.lock().await.dirty_snapshot();
                if let Some((path, gen, items)) = dirty {
                    match tokio::task::spawn_blocking(move || {
                        replay::write_snapshot_items(&path, &items)
                    })
                    .await
                    {
                        Ok(Ok(())) => state.replay.lock().await.mark_flushed(gen),
                        Ok(Err(err)) => {
                            state
                                .counters
                                .replay_flush_failed
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            telemetry::event(
                                "replay_flush_failed",
                                0,
                                json!({"error": format!("{err:#}")}),
                            );
                        }
                        Err(err) => {
                            state
                                .counters
                                .replay_flush_failed
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            telemetry::event(
                                "replay_flush_failed",
                                0,
                                json!({"error": format!("{err:#}")}),
                            );
                        }
                    }
                }
            }
        })
    });
    let egress_monitor = (!state.egress_upstreams.is_empty()).then(|| {
        let interval = state.egress_probe_interval;
        tokio::spawn(monitor_edge_egress(state.clone(), interval))
    });
    let dc_monitor =
        (state.egress_upstreams.is_empty() && config.dc_probe_interval_secs > 0).then(|| {
            tokio::spawn(monitor_dc_reachability(
                Arc::new(state.dcs.clone()),
                Arc::new(state.dc_media_overrides.clone()),
                state.counters.clone(),
                Duration::from_secs(config.dc_probe_interval_secs),
            ))
        });
    let (cover_stop_tx, cover_stop_rx) = tokio::sync::oneshot::channel::<()>();
    let cover_dns_task = (!cover_resolver.is_static_ip()).then(|| {
        spawn_cover_resolver(
            cover_resolver,
            state.counters.clone(),
            handshake_dur,
            cover_stop_rx,
        )
    });
    let (users_stop_tx, users_stop_rx) = tokio::sync::oneshot::channel::<()>();
    let users_task = reload_config
        .map(|cfg| spawn_users_reloader(state.clone(), cfg, Duration::from_secs(1), users_stop_rx));
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let res = serve(listener, state.clone(), effective_max, async {
        #[cfg(unix)]
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
        #[cfg(not(unix))]
        let _ = tokio::signal::ctrl_c().await;
    })
    .await;
    let _ = stats_stop_tx.send(());
    let _ = stats_task.await;
    let _ = metrics_stop_tx.send(());
    if let Some(task) = metrics_task {
        let _ = task.await;
    }
    if let Some(task) = egress_monitor {
        task.abort();
        let _ = task.await;
    }
    if let Some(task) = dc_monitor {
        task.abort();
        let _ = task.await;
    }
    let _ = cover_stop_tx.send(());
    if let Some(task) = cover_dns_task {
        let _ = task.await;
    }
    let _ = users_stop_tx.send(());
    if let Some(task) = users_task {
        let _ = task.await;
    }
    let _ = flush_stop_tx.send(());
    if let Some(task) = flush_task {
        let _ = task.await;
    }
    if let Err(err) = state.replay.lock().await.flush_snapshot() {
        state
            .counters
            .replay_flush_failed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        telemetry::event(
            "replay_flush_failed",
            0,
            json!({"error": format!("{err:#}")}),
        );
    }
    res
}

trait Acceptor {
    async fn accept_conn(&mut self) -> std::io::Result<(TcpStream, SocketAddr)>;
}

impl Acceptor for TcpListener {
    async fn accept_conn(&mut self) -> std::io::Result<(TcpStream, SocketAddr)> {
        TcpListener::accept(self).await
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AcceptErrorAction {
    RetryImmediate(&'static str),
    Backoff(&'static str),
    Fatal(&'static str),
}

fn classify_accept_error(err: &std::io::Error) -> AcceptErrorAction {
    use std::io::ErrorKind;
    match err.kind() {
        ErrorKind::ConnectionAborted => {
            return AcceptErrorAction::RetryImmediate("connection_aborted")
        }
        ErrorKind::ConnectionReset => return AcceptErrorAction::RetryImmediate("connection_reset"),
        ErrorKind::Interrupted => return AcceptErrorAction::RetryImmediate("interrupted"),
        ErrorKind::WouldBlock => return AcceptErrorAction::RetryImmediate("would_block"),
        ErrorKind::OutOfMemory => return AcceptErrorAction::Backoff("enomem"),
        ErrorKind::InvalidInput => return AcceptErrorAction::Fatal("fatal"),
        _ => {}
    }
    match err.raw_os_error() {
        // EMFILE (POSIX 24, Winsock WSAEMFILE 10024)
        Some(24 | 10024) => AcceptErrorAction::Backoff("emfile"),
        // ENFILE (POSIX 23)
        Some(23) => AcceptErrorAction::Backoff("enfile"),
        // ENOBUFS (Linux 105, BSD/macOS 55, Winsock WSAENOBUFS 10055)
        Some(105 | 55 | 10055) => AcceptErrorAction::Backoff("enobufs"),
        // ENOMEM (POSIX 12)
        Some(12) => AcceptErrorAction::Backoff("enomem"),
        // ECONNABORTED / ECONNRESET / EINTR / EAGAIN / EPROTO / ENOPROTOOPT / EHOSTUNREACH / ENETUNREACH / ETIMEDOUT
        Some(103 | 10053) => AcceptErrorAction::RetryImmediate("connection_aborted"),
        Some(104 | 10054) => AcceptErrorAction::RetryImmediate("connection_reset"),
        Some(4 | 10004) => AcceptErrorAction::RetryImmediate("interrupted"),
        Some(11 | 10035) => AcceptErrorAction::RetryImmediate("would_block"),
        Some(71 | 92 | 101 | 110 | 112 | 113 | 64) => {
            AcceptErrorAction::RetryImmediate("connection_aborted")
        }
        // EBADF (9 / 10009), EINVAL (22 / 10022), ENOTSOCK (88 / 10038), EOPNOTSUPP (95 / 10045)
        Some(9 | 10009 | 22 | 10022 | 88 | 10038 | 95 | 10045) => AcceptErrorAction::Fatal("fatal"),
        _ => AcceptErrorAction::Backoff("other"),
    }
}

enum AcceptDecision {
    Accepted((TcpStream, SocketAddr)),
    Retry,
    Shutdown,
}

struct AcceptLoopState {
    backoff: Duration,
    last_log: HashMap<&'static str, (Instant, u64)>,
}

impl Default for AcceptLoopState {
    fn default() -> Self {
        Self {
            backoff: Duration::from_millis(10),
            last_log: HashMap::new(),
        }
    }
}

impl AcceptLoopState {
    const MIN_BACKOFF: Duration = Duration::from_millis(10);
    const MAX_BACKOFF: Duration = Duration::from_secs(1);
    const LOG_WINDOW: Duration = Duration::from_secs(1);

    fn log_rate_limited(
        &mut self,
        kind: &'static str,
        action: &'static str,
        backoff_ms: u64,
        err: &std::io::Error,
    ) {
        let now = Instant::now();
        match self.last_log.get_mut(kind) {
            Some((last_at, suppressed)) if now.duration_since(*last_at) < Self::LOG_WINDOW => {
                *suppressed += 1;
            }
            Some((last_at, suppressed)) => {
                let skipped = *suppressed;
                *last_at = now;
                *suppressed = 0;
                telemetry::event(
                    "accept_error",
                    0,
                    json!({
                        "kind": kind,
                        "action": action,
                        "backoff_ms": backoff_ms,
                        "suppressed": skipped,
                        "error": err.to_string(),
                    }),
                );
            }
            None => {
                self.last_log.insert(kind, (now, 0));
                telemetry::event(
                    "accept_error",
                    0,
                    json!({
                        "kind": kind,
                        "action": action,
                        "backoff_ms": backoff_ms,
                        "suppressed": 0,
                        "error": err.to_string(),
                    }),
                );
            }
        }
    }

    async fn handle_result<F: std::future::Future<Output = ()> + Unpin>(
        &mut self,
        accepted: std::io::Result<(TcpStream, SocketAddr)>,
        counters: &telemetry::Counters,
        shutdown: &mut F,
    ) -> Result<AcceptDecision> {
        match accepted {
            Ok(pair) => {
                self.backoff = Self::MIN_BACKOFF;
                Ok(AcceptDecision::Accepted(pair))
            }
            Err(err) => match classify_accept_error(&err) {
                AcceptErrorAction::RetryImmediate(kind) => {
                    counters.accept_errors.record(kind);
                    self.log_rate_limited(kind, "retry_immediate", 0, &err);
                    Ok(AcceptDecision::Retry)
                }
                AcceptErrorAction::Backoff(kind) => {
                    counters.accept_errors.record(kind);
                    let sleep_dur = self.backoff;
                    self.backoff = (self.backoff.saturating_mul(2)).min(Self::MAX_BACKOFF);
                    self.log_rate_limited(kind, "backoff", sleep_dur.as_millis() as u64, &err);
                    tokio::select! {
                        () = tokio::time::sleep(sleep_dur) => Ok(AcceptDecision::Retry),
                        _ = shutdown => Ok(AcceptDecision::Shutdown),
                    }
                }
                AcceptErrorAction::Fatal(kind) => {
                    counters.accept_errors.record(kind);
                    self.log_rate_limited(kind, "fatal", 0, &err);
                    Err(err.into())
                }
            },
        }
    }
}

async fn serve(
    mut listener: impl Acceptor,
    state: Arc<State>,
    max_connections: usize,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    let permits = Arc::new(Semaphore::new(max_connections));
    let mut tasks = tokio::task::JoinSet::new();
    let mut accept_state = AcceptLoopState::default();
    tokio::pin!(shutdown);
    loop {
        // Reap completed tasks before admitting another. A semaphore only bounds
        // live sessions; without reaping, completed JoinSet entries can accumulate.
        while tasks.try_join_next().is_some() {}
        // Acquire before accept: bounded tasks/FDs; overload remains in the kernel backlog.
        let permit = tokio::select! {
            permit = permits.clone().acquire_owned() => permit?,
            _ = &mut shutdown => break,
        };
        let accepted = tokio::select! {
            accepted = listener.accept_conn() => accepted,
            _ = &mut shutdown => break,
        };
        let socket = match accept_state
            .handle_result(accepted, &state.counters, &mut shutdown)
            .await?
        {
            AcceptDecision::Accepted((socket, _)) => socket,
            AcceptDecision::Retry => continue,
            AcceptDecision::Shutdown => break,
        };
        let state = state.clone();
        tasks.spawn(async move {
            let _permit = permit;
            // Deliberately do not log client addresses, secrets or payload bytes.
            let _ = connection(socket, state).await;
        });
    }
    // Stop admission immediately. Drain has its own deadline, independent of a stalled handshake.
    drop(listener);
    telemetry::event(
        "drain_started",
        0,
        json!({"active":state.counters.active.load(std::sync::atomic::Ordering::Relaxed)}),
    );
    if timeout(state.drain, async {
        while tasks.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        let remaining = tasks.len() as u64;
        if remaining > 0 {
            state
                .counters
                .forced_close
                .fetch_add(remaining, std::sync::atomic::Ordering::Relaxed);
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    telemetry::event(
        "shutdown",
        0,
        json!({"active":state.counters.active.load(std::sync::atomic::Ordering::Relaxed)}),
    );
    Ok(())
}

async fn saved_read<R: AsyncRead + Unpin>(r: &mut R, raw: &mut Vec<u8>, end: usize) -> Result<()> {
    while raw.len() < end {
        let mut buf = [0u8; 4096];
        let n = (end - raw.len()).min(buf.len());
        let got = r.read(&mut buf[..n]).await?;
        ensure!(got != 0, "EOF during ClientHello");
        raw.extend_from_slice(&buf[..got]);
    }
    Ok(())
}

async fn read_hello<R: AsyncRead + Unpin>(r: &mut R, raw: &mut Vec<u8>) -> Result<Vec<u8>> {
    let mut handshake = Vec::new();
    let mut offset = 0;
    for _ in 0..16 {
        saved_read(r, raw, offset + 1).await?;
        ensure!(raw[offset] == 0x16, "not a handshake record");
        saved_read(r, raw, offset + 5).await?;
        ensure!(
            raw[offset + 1] == 3 && (1..=3).contains(&raw[offset + 2]),
            "TLS version"
        );
        let n = usize::from(u16::from_be_bytes([raw[offset + 3], raw[offset + 4]]));
        ensure!(
            n > 0 && handshake.len() + n <= wire::MAX_HELLO + 4,
            "hello bound"
        );
        let start = offset + 5;
        offset = start + n;
        saved_read(r, raw, offset).await?;
        handshake.extend_from_slice(&raw[start..offset]);
        if handshake.len() >= 4 {
            let expected = wire::handshake_length(&handshake)?;
            ensure!(
                handshake.len() <= expected,
                "coalesced trailing handshake unsupported"
            );
            if handshake.len() == expected {
                return Ok(handshake);
            }
        }
    }
    bail!("too many ClientHello fragments")
}

/// Number of TLS records the ClientHello occupied on the wire.
fn hello_record_count(raw: &[u8]) -> usize {
    let mut offset = 0;
    let mut count = 0;
    while offset + 5 <= raw.len() && raw[offset] == 0x16 {
        let n = usize::from(u16::from_be_bytes([raw[offset + 3], raw[offset + 4]]));
        let next = offset + 5 + n;
        if next > raw.len() {
            break;
        }
        offset = next;
        count += 1;
    }
    count
}

async fn connection(mut client: TcpStream, state: Arc<State>) -> Result<()> {
    let mut session = telemetry::Session::new(&state.counters);
    let result = connection_inner(&mut client, &state, session.id).await;
    session.finish(&result);
    result
}

fn bind_listener(addr: SocketAddr, client_mss: Option<u16>) -> Result<TcpListener> {
    let domain = socket2::Domain::for_address(addr);
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    #[cfg(target_os = "linux")]
    if let Some(mss) = client_mss {
        socket
            .set_tcp_mss(u32::from(mss))
            .context("set listener TCP_MAXSEG")?;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = client_mss;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    let std_listener: std::net::TcpListener = socket.into();
    Ok(TcpListener::from_std(std_listener)?)
}

fn apply_bulk_mss(stream: &TcpStream, bulk_mss: Option<u16>) {
    #[cfg(target_os = "linux")]
    if let Some(mss) = bulk_mss {
        let _ = socket2::SockRef::from(stream).set_tcp_mss(u32::from(mss));
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (stream, bulk_mss);
}

fn configure_tcp_socket(stream: &TcpStream) -> Result<()> {
    stream.set_nodelay(true)?;
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(60))
        .with_interval(Duration::from_secs(15));
    #[cfg(unix)]
    let keepalive = keepalive.with_retries(3);
    socket2::SockRef::from(stream).set_tcp_keepalive(&keepalive)?;
    Ok(())
}

enum ProxyV2Outcome {
    Header,
    EmptyEof,
}

async fn read_proxy_v2<R: AsyncRead + Unpin>(r: &mut R, limit: Duration) -> Result<ProxyV2Outcome> {
    timeout(limit, async {
        let mut hdr = [0u8; wire::PROXY_V2_HEADER_LEN];
        let n = r.read(&mut hdr[..1]).await.context("proxy_v2_eof")?;
        if n == 0 {
            return Ok(ProxyV2Outcome::EmptyEof);
        }
        r.read_exact(&mut hdr[1..]).await.context("proxy_v2_eof")?;
        let parsed = wire::parse_proxy_v2_header(&hdr)?;
        let mut payload = vec![0u8; parsed.payload_len];
        if !payload.is_empty() {
            r.read_exact(&mut payload)
                .await
                .context("proxy_v2_payload_eof")?;
        }
        wire::parse_proxy_v2_payload(&parsed, &payload)?;
        Ok(ProxyV2Outcome::Header)
    })
    .await
    .context("proxy_v2_timeout")?
}

async fn connection_inner(client: &mut TcpStream, state: &State, session_id: u64) -> Result<()> {
    configure_tcp_socket(client)?;
    let t0 = Instant::now();
    let us = || t0.elapsed().as_micros() as u64;
    if state.proxy_protocol {
        match read_proxy_v2(client, state.client_hello).await {
            Ok(ProxyV2Outcome::Header) => {}
            Ok(ProxyV2Outcome::EmptyEof) => {
                telemetry::event(
                    "empty_connection_closed",
                    session_id,
                    json!({"timeout":false,"proxy_protocol":true}),
                );
                return Ok(());
            }
            Err(error) => {
                telemetry::event(
                    "proxy_protocol_failed",
                    session_id,
                    json!({"error": format!("{error:#}")}),
                );
                return Err(error);
            }
        }
    }
    let mut raw = Vec::with_capacity(wire::MAX_HELLO + 84);
    let received = timeout(state.client_hello, async {
        if state.enable_dd {
            saved_read(client, &mut raw, 3).await?;
            if !matches!(raw.as_slice(), [0x16, 3, 1..=3]) {
                saved_read(client, &mut raw, 64).await?;
                return Ok(None);
            }
        }
        read_hello(client, &mut raw).await.map(Some)
    })
    .await;
    if !raw.is_empty() {
        state
            .counters
            .downstream_rx_bytes
            .fetch_add(raw.len() as u64, std::sync::atomic::Ordering::Relaxed);
    }
    if raw.is_empty() {
        telemetry::event(
            "empty_connection_closed",
            session_id,
            json!({"timeout":received.is_err()}),
        );
        return Ok(());
    }
    let hello_read_us = us();
    let hello_records = hello_record_count(&raw);
    let record_version = raw.get(2).copied();
    let indicated_record_bytes = match raw.get(..5) {
        Some([0x16, 3, 1..=3, high, low]) => {
            Some(5 + usize::from(u16::from_be_bytes([*high, *low])))
        }
        _ => None,
    };
    if received.is_err() && indicated_record_bytes.is_some_and(|size| raw.len() < size) {
        // The input deadline has expired with an incomplete first record.
        // Starting another upstream exchange would consume another full budget.
        telemetry::event(
            "client_hello_incomplete",
            session_id,
            json!({
                "received_bytes":raw.len(),
                "first_tls_record_bytes":indicated_record_bytes,
            }),
        );
        let _ = timeout(DC_EOF_SHUTDOWN_TIMEOUT, async {
            client.shutdown().await?;
            tokio::io::copy(client, &mut tokio::io::sink()).await
        })
        .await;
        return Ok(());
    }
    if matches!(received, Ok(Ok(None))) {
        let secrets = state.current_secrets();
        let frame: &[u8; 64] = raw.as_slice().try_into()?;
        if let Some((user, transport)) = secrets.iter().find_map(|s| {
            wire::client_transport(frame, &s.key)
                .ok()
                .map(|t| (s.name.clone(), t))
        }) {
            // The first eight bytes do not affect the cipher. Key replays on the
            // wire key/IV so that changing those bytes does not reset the cache.
            let key = Sha256::digest(&frame[8..56]).into();
            let decision = state
                .replay
                .lock()
                .await
                .check_and_insert(key, Instant::now());
            if decision != Decision::Fresh {
                if decision == Decision::Full {
                    state
                        .counters
                        .replay_full
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                telemetry::event(
                    "dd_rejected",
                    session_id,
                    json!({"reason":"replay_or_cache_full"}),
                );
                return Ok(());
            }
            return relay_client(
                client,
                state,
                session_id,
                t0,
                ClientSession {
                    user,
                    transport,
                    tls: None,
                    hello_read_us,
                    flight_written_us: None,
                    diag: HelloDiag {
                        client_hello_bytes: raw.len(),
                        client_hello_records: hello_records,
                        record_version,
                        ..HelloDiag::default()
                    },
                },
            )
            .await;
        }
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let record_minor = if let Ok(Ok(Some(ref bytes))) = received {
        if raw.len() == bytes.len() + 5 {
            raw[2]
        } else {
            1
        }
    } else {
        1
    };
    let secrets = state.current_secrets();
    let allowed_snis = state.current_allowed_snis();
    let (auth, failure) = match received {
        Ok(Ok(Some(bytes))) => {
            let mut matched = None;
            let mut last_err = String::new();
            for s in secrets.iter() {
                match wire::authenticate_with_record_version(
                    &bytes,
                    record_minor,
                    &s.key,
                    &allowed_snis,
                    now,
                ) {
                    Ok(hello) => {
                        matched = Some((s, hello));
                        break;
                    }
                    Err(error) => last_err = error.to_string(),
                }
            }
            match matched {
                Some((s, hello)) => (Some((s, hello)), String::new()),
                None => (None, last_err),
            }
        }
        Ok(Ok(None)) => (None, "dd_authentication_failed".to_string()),
        Ok(Err(error)) => (None, error.to_string()),
        Err(_) => (None, "client_hello_timeout".to_string()),
    };
    let Some((matched_secret, hello)) = auth else {
        telemetry::event(
            "cover_selected",
            session_id,
            json!({
                "reason":"unverified_hello",
                "stage_error":failure,
                "received_bytes":raw.len(),
                "first_tls_record_bytes":indicated_record_bytes,
                "client_hello_records":hello_records,
                "record_version":record_version,
            }),
        );
        return bounded_cover(client, raw, state, session_id).await;
    };
    let decision = {
        let mut cache = state.replay.lock().await;
        cache.check_and_insert(hello.replay_key, Instant::now())
    };
    if decision != Decision::Fresh {
        if decision == Decision::Full {
            state
                .counters
                .replay_full
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        telemetry::event(
            "cover_selected",
            session_id,
            json!({"reason":"replay_or_cache_full"}),
        );
        return bounded_cover(client, raw, state, session_id).await;
    }
    let flight = wire::server_flight(
        &matched_secret.key,
        &hello,
        &state.flight,
        &mut rand::rngs::OsRng,
    )?;
    // INV-01: from the first write onwards every error only closes this path.
    // No cover call exists below this boundary, including partial-write failures.
    write_server_flight(client, &flight, state.flight_shaping, state.handshake).await?;
    state
        .counters
        .downstream_tx_bytes
        .fetch_add(flight.len() as u64, std::sync::atomic::Ordering::Relaxed);
    let flight_written_us = us();
    let mut tls = TlsReader::default();
    let mut frame = [0u8; 64];
    let inner = timeout(state.handshake, async {
        let mut off = 0;
        while off < frame.len() {
            let n = tls.read_into(client, &mut frame[off..]).await?;
            ensure!(n > 0, "EOF before inner header");
            off += n;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await;
    state
        .counters
        .downstream_rx_bytes
        .fetch_add(tls.consumed, std::sync::atomic::Ordering::Relaxed);
    let failure = match &inner {
        Ok(Ok(())) => None,
        Ok(Err(error)) => Some(format!("{error:#}")),
        Err(_) => Some("deadline".to_string()),
    };
    if let Some(reason) = failure {
        telemetry::event(
            "inner_header_incomplete",
            session_id,
            json!({
                "reason":reason,
                "flight_bytes":flight.len(),
                "fake_tls_cert_bytes":state.flight.cert_bytes,
                "client_bytes_after_flight":tls.consumed,
                "client_hello_bytes":raw.len(),
                "client_hello_records":hello_records,
                "record_version":record_version,
                "client_template":hello.template,
                "cipher_suite":hello.cipher_suite,
                "flight_written_us":flight_written_us,
            }),
        );
    }
    inner
        .context("inner_header_timeout")?
        .context("inner_header_invalid")?;
    let transport =
        wire::client_transport(&frame, &matched_secret.key).context("inner_transport_invalid")?;
    relay_client(
        client,
        state,
        session_id,
        t0,
        ClientSession {
            user: matched_secret.name.clone(),
            transport,
            tls: Some(tls),
            hello_read_us,
            flight_written_us: Some(flight_written_us),
            diag: HelloDiag {
                client_hello_bytes: raw.len(),
                client_hello_records: hello_records,
                record_version,
                client_template: hello.template.clone(),
                cipher_suite: hello.cipher_suite,
                flight_bytes: flight.len(),
                fake_tls_cert_bytes: state.flight.cert_bytes,
            },
        },
    )
    .await
}

struct ClientSession {
    user: String,
    transport: wire::ClientTransport,
    tls: Option<TlsReader>,
    hello_read_us: u64,
    flight_written_us: Option<u64>,
    diag: HelloDiag,
}

/// Shape of the accepted ClientHello and of the flight we answered with.
/// It identifies the client template without exposing key material.
#[derive(Default, Clone)]
struct HelloDiag {
    client_hello_bytes: usize,
    client_hello_records: usize,
    record_version: Option<u8>,
    client_template: String,
    cipher_suite: u16,
    flight_bytes: usize,
    fake_tls_cert_bytes: usize,
}

async fn relay_client(
    client: &mut TcpStream,
    state: &State,
    session_id: u64,
    t0: Instant,
    session: ClientSession,
) -> Result<()> {
    let ClientSession {
        user,
        transport,
        tls,
        hello_read_us,
        flight_written_us,
        diag,
    } = session;
    apply_bulk_mss(client, state.client_mss_bulk);
    let us = || t0.elapsed().as_micros() as u64;
    let framed = tls.is_some();
    let inner_header_us = us();
    let dc = wire::dc_transport()?;
    let (upstream, route) = connect_upstream(state, transport.dc, &dc.header).await?;
    let dc_connected_us = us();
    telemetry::event(
        "authenticated",
        session_id,
        json!({
            "user":user,
            "dc":transport.dc,
            "route":route,
            "transport":"padded-intermediate",
            "mode": if framed { "ee" } else { "dd" },
            "hello_read_us":hello_read_us,
            "flight_written_us":flight_written_us,
            "inner_header_us":inner_header_us,
            "dc_connected_us":dc_connected_us,
            "dc_header_written_us":us(),
            "client_hello_bytes":diag.client_hello_bytes,
            "client_hello_records":diag.client_hello_records,
            "record_version":diag.record_version,
            "client_template":diag.client_template,
            "cipher_suite":diag.cipher_suite,
            "flight_bytes":diag.flight_bytes,
            "fake_tls_cert_bytes":diag.fake_tls_cert_bytes,
        }),
    );
    let client_fd = stream_raw_fd(client);
    let upstream_fd = stream_raw_fd(&upstream);
    let (cr, cw) = client.split();
    let (ur, uw) = upstream.into_split();
    let relay = RelayStats {
        counters: Some(state.counters.clone()),
        client_fd,
        upstream_fd,
        diagnostics: state.diagnostics,
        ..RelayStats::default()
    };
    let relay_start_us = us();
    let result = relay_until_end(
        &relay,
        state.idle,
        async {
            upload(
                cr,
                uw,
                tls,
                transport.decrypt,
                dc.encrypt,
                RELAY_WRITE_TIMEOUT,
                &relay,
            )
            .await
            .context("client_to_dc_relay_failed")
        },
        async {
            download(
                ur,
                cw,
                dc.decrypt,
                transport.encrypt,
                framed,
                RELAY_WRITE_TIMEOUT,
                &relay,
            )
            .await
            .context("dc_to_client_relay_failed")
        },
    )
    .await;
    let dc_close_reason = if result.is_ok() {
        // Download already sent FIN. Give the peer a short window to close
        // its write half and consume late bytes without forwarding them.
        Some(
            match timeout(
                DC_EOF_SHUTDOWN_TIMEOUT,
                tokio::io::copy(client, &mut tokio::io::sink()),
            )
            .await
            {
                Ok(Ok(_)) => "dc_eof",
                Ok(Err(_)) => "client_drain_read_error",
                Err(_) => "client_drain_timeout",
            },
        )
    } else {
        None
    };
    let mut summary = relay.summary();
    if let Some(reason) = dc_close_reason {
        summary["final_reason"] = json!(reason);
    }
    summary["relay_start_us"] = json!(relay_start_us);
    telemetry::event("relay_summary", session_id, summary);
    result?;
    Ok(())
}

const NONE_US: u64 = u64::MAX;
const RELAY_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const DC_EOF_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);
const CLIENT_EOF_REPLY_TIMEOUT: Duration = Duration::from_secs(5);

async fn relay_until_end(
    stats: &RelayStats,
    idle: Duration,
    upload: impl std::future::Future<Output = Result<()>>,
    download: impl std::future::Future<Output = Result<()>>,
) -> Result<()> {
    tokio::pin!(upload, download);
    let transfer = async {
        tokio::select! {
            // Download completes only after the last reply has been written
            // and the client's write half has been shut down.
            biased;
            result = &mut download => result,
            result = &mut upload => {
                result?;
                // A client FIN still allows the DC to finish its reply.
                match timeout(CLIENT_EOF_REPLY_TIMEOUT, download).await {
                    Ok(result) => result,
                    Err(error) => stats.failed("dc_reply_drain_timeout", error.into()),
                }
            }
        }
    };
    tokio::select! {
        biased;
        result = transfer => result,
        () = stats.wait_for_idle(idle) => {
            stats.timeline.close("session_idle", "timed_out");
            bail!("session idle timeout")
        }
    }
}

/// Counters here measure bytes handed to a socket or read from it. A
/// successful write does not prove the peer received the data.
struct RelayStats {
    uploaded: std::sync::atomic::AtomicU64,
    downloaded: std::sync::atomic::AtomicU64,
    first_eof: std::sync::atomic::AtomicU64,
    transport_error: std::sync::atomic::AtomicI32,
    client_reads: std::sync::atomic::AtomicU64,
    dc_writes: std::sync::atomic::AtomicU64,
    dc_reads: std::sync::atomic::AtomicU64,
    client_writes: std::sync::atomic::AtomicU64,
    first_up_us: std::sync::atomic::AtomicU64,
    last_up_us: std::sync::atomic::AtomicU64,
    first_dn_us: std::sync::atomic::AtomicU64,
    last_dn_us: std::sync::atomic::AtomicU64,
    last_activity_us: std::sync::atomic::AtomicU64,
    timeline: telemetry::Timeline,
    first_up_kind: std::sync::atomic::AtomicU64,
    first_dn_kind: std::sync::atomic::AtomicU64,
    first_up_frame_len: std::sync::atomic::AtomicU64,
    first_dn_frame_len: std::sync::atomic::AtomicU64,
    counters: Option<Arc<telemetry::Counters>>,
    client_fd: Option<i32>,
    upstream_fd: Option<i32>,
    diagnostics: bool,
}

impl Default for RelayStats {
    fn default() -> Self {
        use std::sync::atomic::{AtomicI32, AtomicU64};
        Self {
            uploaded: AtomicU64::new(0),
            downloaded: AtomicU64::new(0),
            first_eof: AtomicU64::new(0),
            transport_error: AtomicI32::new(0),
            client_reads: AtomicU64::new(0),
            dc_writes: AtomicU64::new(0),
            dc_reads: AtomicU64::new(0),
            client_writes: AtomicU64::new(0),
            first_up_us: AtomicU64::new(NONE_US),
            last_up_us: AtomicU64::new(NONE_US),
            first_dn_us: AtomicU64::new(NONE_US),
            last_dn_us: AtomicU64::new(NONE_US),
            last_activity_us: AtomicU64::new(0),
            timeline: telemetry::Timeline::new(),
            first_up_kind: AtomicU64::new(0),
            first_dn_kind: AtomicU64::new(0),
            first_up_frame_len: AtomicU64::new(0),
            first_dn_frame_len: AtomicU64::new(0),
            counters: None,
            client_fd: None,
            upstream_fd: None,
            diagnostics: false,
        }
    }
}

fn io_kind(error: &anyhow::Error) -> &'static str {
    use std::io::ErrorKind::*;
    match error.downcast_ref::<std::io::Error>().map(|e| e.kind()) {
        None => "protocol",
        Some(ConnectionReset) => "reset",
        Some(BrokenPipe) => "broken_pipe",
        Some(UnexpectedEof) => "unexpected_eof",
        Some(TimedOut) => "timed_out",
        Some(ConnectionAborted) => "aborted",
        Some(_) => "other",
    }
}

impl RelayStats {
    async fn wait_for_idle(&self, idle: Duration) {
        use std::sync::atomic::Ordering::Relaxed;
        let mut wait = idle;
        loop {
            tokio::time::sleep(wait).await;
            let last_activity = self.last_activity_us.load(Relaxed);
            let elapsed =
                Duration::from_micros(self.timeline.now_us().saturating_sub(last_activity));
            wait = idle.saturating_sub(elapsed);
            if wait.is_zero() {
                return;
            }
        }
    }

    fn record_activity(&self) {
        self.last_activity_us
            .store(self.timeline.now_us(), std::sync::atomic::Ordering::Relaxed);
    }

    fn observe_prefix(&self, prefix: &[u8], upload: bool) {
        use std::sync::atomic::Ordering::Relaxed;
        let (kind, length) = if upload {
            (&self.first_up_kind, &self.first_up_frame_len)
        } else {
            (&self.first_dn_kind, &self.first_dn_frame_len)
        };
        if prefix.len() < 4 {
            return;
        }
        let frame_length =
            u32::from_le_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]) & 0x7fff_ffff;
        if !(8..=16 * 1024 * 1024).contains(&frame_length) {
            return;
        }
        length.store(u64::from(frame_length), Relaxed);
        if prefix.len() < 12 {
            return;
        }
        if prefix[4..12] != [0; 8] {
            kind.store(1, Relaxed);
            return;
        }
        kind.store(2, Relaxed);
        if prefix.len() >= 28 {
            let expected = if upload {
                [0xf1, 0x8e, 0x7e, 0xbe]
            } else {
                [0x63, 0x24, 0x16, 0x05]
            };
            if prefix[24..28] == expected {
                kind.store(3, Relaxed);
            }
        }
    }

    fn stamp(&self, first: &std::sync::atomic::AtomicU64, last: &std::sync::atomic::AtomicU64) {
        use std::sync::atomic::Ordering::Relaxed;
        let now = self.timeline.now_us();
        let _ = first.compare_exchange(NONE_US, now, Relaxed, Relaxed);
        last.store(now, Relaxed);
        self.last_activity_us.store(now, Relaxed);
    }

    fn failed<T>(&self, tag: &'static str, error: anyhow::Error) -> Result<T> {
        let detail = if error.is::<tokio::time::error::Elapsed>() {
            "timed_out"
        } else {
            io_kind(&error)
        };
        self.timeline.close(tag, detail);
        Err(error)
    }

    fn summary(&self) -> serde_json::Value {
        use std::sync::atomic::Ordering::Relaxed;
        let end = self.timeline.now_us();
        let opt = |v: u64| if v == NONE_US { None } else { Some(v) };
        let (first_up, last_up) = (
            opt(self.first_up_us.load(Relaxed)),
            opt(self.last_up_us.load(Relaxed)),
        );
        let (first_dn, last_dn) = (
            opt(self.first_dn_us.load(Relaxed)),
            opt(self.last_dn_us.load(Relaxed)),
        );
        let reply_seen = self.downloaded.load(Relaxed) > 0;
        let closer = self.timeline.closer();
        let class = match closer.map(|c| c.1) {
            Some("client_eof") | Some("client_eof_mid_record") if reply_seen => {
                "client_closed_after_dc_reply"
            }
            Some("client_eof") | Some("client_eof_mid_record") => {
                "client_closed_before_any_dc_reply"
            }
            Some("dc_eof") if reply_seen => "dc_closed_after_reply",
            Some("dc_eof") => "dc_closed_without_reply",
            Some(t) if t.ends_with("_idle") => "idle_timeout",
            Some(t) if t.starts_with("client_") => "client_socket_error",
            Some(t) if t.starts_with("dc_") => "dc_socket_error",
            Some(_) => "other",
            None => "none",
        };
        let error_code = self.transport_error.load(Relaxed);
        json!({
            "uploaded_bytes":self.uploaded.load(Relaxed),
            "downloaded_bytes":self.downloaded.load(Relaxed),
            "client_reads":self.client_reads.load(Relaxed),
            "dc_writes":self.dc_writes.load(Relaxed),
            "dc_reads":self.dc_reads.load(Relaxed),
            "client_writes":self.client_writes.load(Relaxed),
            "first_up_us":first_up,
            "last_up_us":last_up,
            "first_dn_us":first_dn,
            "last_dn_us":last_dn,
            "end_us":end,
            "final_reason":self.timeline.final_reason(),
            "final_at_us":end,
            "idle_since_last_up_us":last_up.map(|t| end.saturating_sub(t)),
            "idle_since_last_dn_us":last_dn.map(|t| end.saturating_sub(t)),
            "first_eof":match self.first_eof.load(Relaxed) {1=>"client",2=>"dc",_=>"none"},
            "initiator":closer.map(|c| c.1),
            "initiator_detail":closer.map(|c| c.2),
            "initiator_at_us":closer.map(|c| c.0),
            "class":class,
            "dc_transport_error":if error_code==0 {None}else{Some(error_code)},
            "first_up_frame_len":self.first_up_frame_len.load(Relaxed),
            "first_dn_frame_len":self.first_dn_frame_len.load(Relaxed),
            "first_up_kind":match self.first_up_kind.load(Relaxed) {1=>"encrypted",2=>"unencrypted_other",3=>"unencrypted_req_pq_multi",_=>"unknown"},
            "first_dn_kind":match self.first_dn_kind.load(Relaxed) {1=>"encrypted",2=>"unencrypted_other",3=>"unencrypted_res_pq",_=>"unknown"},
            "timeline":self.timeline.snapshot(),
        })
    }
}

// Telegram iOS emits FakeTLS application records with up to 16,408 payload bytes.
const MAX_CLIENT_RECORD: usize = 16_408;
const TLS_READER_CHUNK: usize = 5 + MAX_CLIENT_RECORD;

#[derive(Default)]
struct TlsReader {
    pending: Vec<u8>,
    offset: usize,
    raw: Vec<u8>,
    raw_offset: usize,
    /// Wire bytes read from the socket, including TLS headers and partial records.
    consumed: u64,
}
impl TlsReader {
    async fn read_wire_some<R: AsyncRead + Unpin>(
        &mut self,
        r: &mut R,
        dst: &mut [u8],
    ) -> std::io::Result<usize> {
        if self.raw_offset < self.raw.len() {
            let avail = self.raw.len() - self.raw_offset;
            let n = dst.len().min(avail);
            dst[..n].copy_from_slice(&self.raw[self.raw_offset..self.raw_offset + n]);
            self.raw_offset += n;
            if self.raw_offset == self.raw.len() {
                self.raw.clear();
                self.raw_offset = 0;
            }
            return Ok(n);
        }
        if self.raw.capacity() == 0 {
            self.raw.reserve_exact(TLS_READER_CHUNK);
        }
        self.raw.resize(TLS_READER_CHUNK, 0);
        let got = r.read(&mut self.raw).await?;
        self.raw.truncate(got);
        self.raw_offset = 0;
        if got == 0 {
            return Ok(0);
        }
        self.consumed += got as u64;
        let n = dst.len().min(got);
        dst[..n].copy_from_slice(&self.raw[..n]);
        self.raw_offset = n;
        if self.raw_offset == self.raw.len() {
            self.raw.clear();
            self.raw_offset = 0;
        }
        Ok(n)
    }

    async fn read_wire_exact<R: AsyncRead + Unpin>(
        &mut self,
        r: &mut R,
        mut bytes: &mut [u8],
    ) -> std::io::Result<()> {
        while !bytes.is_empty() {
            let n = self.read_wire_some(r, bytes).await?;
            if n == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            bytes = &mut bytes[n..];
        }
        Ok(())
    }

    async fn read_into<R: AsyncRead + Unpin>(
        &mut self,
        r: &mut R,
        out: &mut [u8],
    ) -> Result<usize> {
        if self.offset == self.pending.len() {
            self.pending.clear();
            self.offset = 0;
            // Permit only one CCS before an application record. No unbounded empty-record loop.
            for _ in 0..2 {
                let mut h = [0u8; 5];
                let first = self.read_wire_some(r, &mut h).await?;
                if first == 0 {
                    return Ok(0);
                }
                if first < 5 {
                    self.read_wire_exact(r, &mut h[first..]).await?;
                }
                ensure!(h[1..3] == [3, 3], "TLS record version");
                let n = usize::from(u16::from_be_bytes([h[3], h[4]]));
                let limit = if h[0] == 0x17 {
                    MAX_CLIENT_RECORD
                } else {
                    wire::MAX_RECORD
                };
                ensure!(n > 0 && n <= limit, "TLS record limit");
                let mut pending = std::mem::take(&mut self.pending);
                pending.resize(n, 0);
                let read_res = self.read_wire_exact(r, &mut pending).await;
                self.pending = pending;
                read_res?;
                if h[0] == 0x14 {
                    ensure!(self.pending == [1], "invalid CCS");
                    self.pending.clear();
                    continue;
                }
                ensure!(h[0] == 0x17, "unexpected post-commit record");
                break;
            }
            ensure!(!self.pending.is_empty(), "repeated CCS");
        }
        let n = out.len().min(self.pending.len() - self.offset);
        out[..n].copy_from_slice(&self.pending[self.offset..self.offset + n]);
        self.offset += n;
        Ok(n)
    }
}

async fn upload<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut r: R,
    mut w: W,
    mut tls: Option<TlsReader>,
    mut decrypt: AesCtr,
    mut encrypt: AesCtr,
    write_timeout: Duration,
    stats: &RelayStats,
) -> Result<()> {
    use std::sync::atomic::Ordering::Relaxed;
    const RETRANS_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
    let mut buf = [0u8; wire::MAX_RECORD];
    let mut prefix = [0u8; 28];
    let mut prefix_len = 0;
    let mut prev_retrans = 0u32;
    let mut last_retrans_sample = Instant::now();
    loop {
        let prev_consumed = tls.as_ref().map(|t| t.consumed).unwrap_or(0);
        let read = match &mut tls {
            Some(reader) => reader.read_into(&mut r, &mut buf).await,
            None => r.read(&mut buf).await.map_err(Into::into),
        };
        if let (Some(reader), Some(counters)) = (&tls, &stats.counters) {
            let delta = reader.consumed.saturating_sub(prev_consumed);
            if delta > 0 {
                counters.downstream_rx_bytes.fetch_add(delta, Relaxed);
            }
        }
        let n = match read {
            Ok(n) => n,
            Err(error) => {
                let tag = if io_kind(&error) == "unexpected_eof" {
                    "client_eof_mid_record"
                } else {
                    "client_read_error"
                };
                return stats.failed(tag, error);
            }
        };
        if tls.is_none() && n > 0 {
            if let Some(counters) = &stats.counters {
                counters.downstream_rx_bytes.fetch_add(n as u64, Relaxed);
            }
        }
        if n == 0 {
            let _ = stats.first_eof.compare_exchange(0, 1, Relaxed, Relaxed);
            stats.timeline.close("client_eof", "fin");
            let res = match timeout(write_timeout, w.shutdown()).await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) => stats.failed("dc_write_error", error.into()),
                Err(error) => stats.failed("dc_write_idle", error.into()),
            };
            if let Some(counters) = &stats.counters {
                sample_fd_retrans(
                    stats.upstream_fd,
                    &mut prev_retrans,
                    &counters.upstream_retrans_segs,
                );
            }
            return res;
        }
        stats.client_reads.fetch_add(1, Relaxed);
        stats.record_activity();
        if stats.diagnostics {
            stats.timeline.mark("client_read", n as u64);
        }
        wire::crypt(&mut decrypt, &mut buf[..n]);
        let take = n.min(prefix.len() - prefix_len);
        prefix[prefix_len..prefix_len + take].copy_from_slice(&buf[..take]);
        prefix_len += take;
        stats.observe_prefix(&prefix[..prefix_len], true);
        wire::crypt(&mut encrypt, &mut buf[..n]);
        match timeout(write_timeout, w.write_all(&buf[..n])).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                if let Some(counters) = &stats.counters {
                    sample_fd_retrans(
                        stats.upstream_fd,
                        &mut prev_retrans,
                        &counters.upstream_retrans_segs,
                    );
                }
                return stats.failed("dc_write_error", error.into());
            }
            Err(error) => {
                if let Some(counters) = &stats.counters {
                    sample_fd_retrans(
                        stats.upstream_fd,
                        &mut prev_retrans,
                        &counters.upstream_retrans_segs,
                    );
                }
                return stats.failed("dc_write_idle", error.into());
            }
        }
        if let Some(counters) = &stats.counters {
            counters.upstream_tx_bytes.fetch_add(n as u64, Relaxed);
            if last_retrans_sample.elapsed() >= RETRANS_SAMPLE_INTERVAL {
                sample_fd_retrans(
                    stats.upstream_fd,
                    &mut prev_retrans,
                    &counters.upstream_retrans_segs,
                );
                last_retrans_sample = Instant::now();
            }
        }
        stats.uploaded.fetch_add(n as u64, Relaxed);
        stats.dc_writes.fetch_add(1, Relaxed);
        if stats.diagnostics {
            stats.timeline.mark("dc_write", n as u64);
        }
        stats.stamp(&stats.first_up_us, &stats.last_up_us);
    }
}
async fn download<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut r: R,
    mut w: W,
    mut decrypt: AesCtr,
    mut encrypt: AesCtr,
    framed: bool,
    write_timeout: Duration,
    stats: &RelayStats,
) -> Result<()> {
    use std::sync::atomic::Ordering::Relaxed;
    const RETRANS_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
    let mut frame_buf = vec![0u8; 5 + wire::MAX_RECORD];
    frame_buf[0] = 0x17;
    frame_buf[1] = 3;
    frame_buf[2] = 3;
    let mut prefix = [0u8; 28];
    let mut prefix_len = 0;
    let mut prev_retrans = 0u32;
    let mut last_retrans_sample = Instant::now();
    loop {
        let n = match r.read(&mut frame_buf[5..]).await {
            Ok(n) => n,
            Err(error) => return stats.failed("dc_read_error", error.into()),
        };
        if n == 0 {
            let _ = stats.first_eof.compare_exchange(0, 2, Relaxed, Relaxed);
            stats.timeline.close("dc_eof", "fin");
            let res = match timeout(write_timeout.min(DC_EOF_SHUTDOWN_TIMEOUT), w.shutdown()).await
            {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) => stats.failed("client_write_error", error.into()),
                Err(error) => stats.failed("client_write_idle", error.into()),
            };
            if let Some(counters) = &stats.counters {
                sample_fd_retrans(
                    stats.client_fd,
                    &mut prev_retrans,
                    &counters.downstream_retrans_segs,
                );
            }
            return res;
        }
        if let Some(counters) = &stats.counters {
            counters.upstream_rx_bytes.fetch_add(n as u64, Relaxed);
        }
        stats.dc_reads.fetch_add(1, Relaxed);
        stats.record_activity();
        if stats.diagnostics {
            stats.timeline.mark("dc_read", n as u64);
        }
        {
            let buf = &mut frame_buf[5..5 + n];
            wire::crypt(&mut decrypt, buf);
            // Transient prefix only: recognize public unencrypted handshake types
            // and transport errors; never emit prefix bytes, key IDs or payload.
            let take = n.min(prefix.len() - prefix_len);
            prefix[prefix_len..prefix_len + take].copy_from_slice(&buf[..take]);
            prefix_len += take;
            stats.observe_prefix(&prefix[..prefix_len], false);
            if prefix_len >= 4 {
                let word = i32::from_le_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]);
                let code = if word == 4 && prefix_len >= 8 {
                    i32::from_le_bytes([prefix[4], prefix[5], prefix[6], prefix[7]])
                } else {
                    word
                };
                if [-404, -429, -444, -500].contains(&code) {
                    stats.transport_error.store(code, Relaxed);
                }
            }
            wire::crypt(&mut encrypt, buf);
        }
        let bytes = if framed {
            let len_bytes = (n as u16).to_be_bytes();
            frame_buf[3] = len_bytes[0];
            frame_buf[4] = len_bytes[1];
            &frame_buf[..5 + n]
        } else {
            &frame_buf[5..5 + n]
        };
        match timeout(write_timeout, w.write_all(bytes)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                if let Some(counters) = &stats.counters {
                    sample_fd_retrans(
                        stats.client_fd,
                        &mut prev_retrans,
                        &counters.downstream_retrans_segs,
                    );
                }
                return stats.failed("client_write_error", error.into());
            }
            Err(error) => {
                if let Some(counters) = &stats.counters {
                    sample_fd_retrans(
                        stats.client_fd,
                        &mut prev_retrans,
                        &counters.downstream_retrans_segs,
                    );
                }
                return stats.failed("client_write_idle", error.into());
            }
        }
        if let Some(counters) = &stats.counters {
            counters
                .downstream_tx_bytes
                .fetch_add(bytes.len() as u64, Relaxed);
            if last_retrans_sample.elapsed() >= RETRANS_SAMPLE_INTERVAL {
                sample_fd_retrans(
                    stats.client_fd,
                    &mut prev_retrans,
                    &counters.downstream_retrans_segs,
                );
                last_retrans_sample = Instant::now();
            }
        }
        stats.downloaded.fetch_add(n as u64, Relaxed);
        stats.client_writes.fetch_add(1, Relaxed);
        if stats.diagnostics {
            stats.timeline.mark("client_write", n as u64);
        }
        stats.stamp(&stats.first_dn_us, &stats.last_dn_us);
    }
}
async fn plain_copy<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut r: R,
    mut w: W,
    idle: Duration,
) -> Result<()> {
    let mut buf = [0; wire::MAX_RECORD];
    loop {
        let n = timeout(idle, r.read(&mut buf)).await??;
        if n == 0 {
            timeout(idle, w.shutdown()).await??;
            return Ok(());
        }
        timeout(idle, w.write_all(&buf[..n])).await??;
    }
}
async fn counted_copy<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut r: R,
    mut w: W,
    idle: Duration,
    rx_counter: &std::sync::atomic::AtomicU64,
    tx_counter: &std::sync::atomic::AtomicU64,
    write_fd: Option<i32>,
    retrans_counter: &std::sync::atomic::AtomicU64,
) -> Result<()> {
    use std::sync::atomic::Ordering::Relaxed;
    const RETRANS_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
    let mut buf = [0; wire::MAX_RECORD];
    let mut prev_retrans = 0u32;
    let mut last_retrans_sample = Instant::now();
    loop {
        let n = timeout(idle, r.read(&mut buf)).await??;
        if n == 0 {
            let res = timeout(idle, w.shutdown()).await;
            sample_fd_retrans(write_fd, &mut prev_retrans, retrans_counter);
            res??;
            return Ok(());
        }
        rx_counter.fetch_add(n as u64, Relaxed);
        let res = timeout(idle, w.write_all(&buf[..n])).await;
        if res.is_err()
            || res.as_ref().is_ok_and(|r| r.is_err())
            || last_retrans_sample.elapsed() >= RETRANS_SAMPLE_INTERVAL
        {
            sample_fd_retrans(write_fd, &mut prev_retrans, retrans_counter);
            last_retrans_sample = Instant::now();
        }
        res??;
        tx_counter.fetch_add(n as u64, Relaxed);
    }
}
async fn bounded_cover(
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

async fn cover(client: &mut TcpStream, raw: Vec<u8>, state: &State) -> Result<()> {
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

const EGRESS_MAGIC: [u8; 4] = *b"MTV2";
const EGRESS_ACK_OK: u8 = 0x00;
const EGRESS_ACK_ERR: u8 = 0x01;

fn ct_eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn write_server_flight(
    client: &mut TcpStream,
    flight: &[u8],
    shaping: bool,
    handshake: Duration,
) -> Result<()> {
    timeout(handshake, async {
        if !shaping || flight.len() <= 256 {
            client.write_all(flight).await?;
            return Ok::<_, std::io::Error>(());
        }
        use rand::Rng;
        let first_chunk = rand::rngs::OsRng.gen_range(95..=165).min(flight.len());
        client.write_all(&flight[..first_chunk]).await?;
        client.flush().await?;
        if first_chunk < flight.len() {
            let delay_us = rand::rngs::OsRng.gen_range(300..=1000);
            tokio::time::sleep(Duration::from_micros(delay_us)).await;
            client.write_all(&flight[first_chunk..]).await?;
            client.flush().await?;
        }
        Ok(())
    })
    .await
    .context("server_hello_write_timeout")?
    .context("server_hello_write_failed")?;
    Ok(())
}

struct EgressProbe {
    tcp_reachable: bool,
    token_status: &'static str,
    dc_reachable: bool,
    detail: String,
}

fn build_egress_wire_preface(
    token: &[u8; 16],
    dc_id: i16,
    dc_header: &[u8; 64],
    use_mtv3: bool,
) -> Result<Vec<u8>> {
    if use_mtv3 {
        use rand::RngCore;
        let now_secs = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let mut nonce = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let preface = wire::build_egress_preface_v3(token, dc_id, now_secs, &nonce, dc_header)?;
        Ok(preface.to_vec())
    } else {
        let mut preface = vec![0u8; wire::EGRESS_PREFACE_V2_LEN];
        preface[..4].copy_from_slice(&EGRESS_MAGIC);
        preface[4..6].copy_from_slice(&dc_id.to_le_bytes());
        preface[8..24].copy_from_slice(token);
        preface[24..88].copy_from_slice(dc_header);
        Ok(preface)
    }
}

#[cfg(test)]
async fn probe_egress_endpoint(
    addr: SocketAddr,
    dc_id: i16,
    token: &[u8; 16],
    limit: Duration,
) -> EgressProbe {
    probe_egress_endpoint_proto(addr, dc_id, token, limit, false).await
}

async fn probe_egress_endpoint_proto(
    addr: SocketAddr,
    dc_id: i16,
    token: &[u8; 16],
    limit: Duration,
    use_mtv3: bool,
) -> EgressProbe {
    let mut stream = match timeout(limit, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(err)) => {
            return EgressProbe {
                tcp_reachable: false,
                token_status: "unknown",
                dc_reachable: false,
                detail: format!("tcp_connect_failed: {err}"),
            };
        }
        Err(_) => {
            return EgressProbe {
                tcp_reachable: false,
                token_status: "unknown",
                dc_reachable: false,
                detail: "tcp_connect_timeout".to_string(),
            };
        }
    };
    let dc = match wire::dc_transport() {
        Ok(dc) => dc,
        Err(err) => {
            return EgressProbe {
                tcp_reachable: true,
                token_status: "unknown",
                dc_reachable: false,
                detail: format!("dc_transport_error: {err:#}"),
            };
        }
    };
    let preface = match build_egress_wire_preface(token, dc_id, &dc.header, use_mtv3) {
        Ok(p) => p,
        Err(err) => {
            return EgressProbe {
                tcp_reachable: true,
                token_status: "unknown",
                dc_reachable: false,
                detail: format!("preface_build_error: {err:#}"),
            };
        }
    };
    if let Err(err) = timeout(limit, stream.write_all(&preface)).await {
        return EgressProbe {
            tcp_reachable: true,
            token_status: "unknown",
            dc_reachable: false,
            detail: format!("preface_write_timeout: {err}"),
        };
    }
    let mut ack = [0u8; 1];
    match timeout(limit, stream.read_exact(&mut ack)).await {
        Ok(Ok(_)) if ack[0] == EGRESS_ACK_OK => EgressProbe {
            tcp_reachable: true,
            token_status: "accepted",
            dc_reachable: true,
            detail: format!("dc {dc_id} reachable via egress"),
        },
        Ok(Ok(_)) => EgressProbe {
            tcp_reachable: true,
            token_status: "accepted",
            dc_reachable: false,
            detail: format!("dc {dc_id} unreachable from egress (negative ack)"),
        },
        Ok(Err(err))
            if matches!(
                err.kind(),
                std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
            ) =>
        {
            EgressProbe {
                tcp_reachable: true,
                token_status: "unknown",
                dc_reachable: false,
                detail: "connection closed before ACK (token rejected, protocol mismatch, or peer reset)".to_string(),
            }
        }
        Ok(Err(err)) => EgressProbe {
            tcp_reachable: true,
            token_status: "unknown",
            dc_reachable: false,
            detail: format!("ack_read_failed: {err}"),
        },
        Err(_) => EgressProbe {
            tcp_reachable: true,
            token_status: "unknown",
            dc_reachable: false,
            detail: "ack_read_timeout".to_string(),
        },
    }
}

fn build_req_pq_multi_frame(nonce: &[u8; 16]) -> Vec<u8> {
    // MTProto unencrypted message: auth_key_id(8=0) + msg_id(8, unix<<32) + msg_len(4=20) +
    // req_pq_multi#be7e8ef1 (4) + nonce(16) = 40 bytes payload.
    // Wrapped in padded-intermediate frame: len(4 LE = 40) + payload(40) = 44 bytes.
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(1_700_000_000);
    let msg_id = (now_secs << 32) & !3u64;
    let mut frame = Vec::with_capacity(44);
    frame.extend_from_slice(&40u32.to_le_bytes());
    frame.extend_from_slice(&0u64.to_le_bytes());
    frame.extend_from_slice(&msg_id.to_le_bytes());
    frame.extend_from_slice(&20u32.to_le_bytes());
    frame.extend_from_slice(&[0xf1, 0x8e, 0x7e, 0xbe]); // req_pq_multi#be7e8ef1
    frame.extend_from_slice(nonce);
    frame
}

fn validate_res_pq_payload(payload: &[u8], expected_nonce: &[u8; 16]) -> Result<()> {
    // Unencrypted MTProto response: auth_key_id(8=0) + msg_id(8) + msg_len(4) + resPQ#05162463(4) + nonce(16) + ...
    ensure!(
        payload.len() >= 40,
        "Telegram DC reply too short ({} bytes)",
        payload.len()
    );
    ensure!(
        payload[0..8] == [0u8; 8],
        "unexpected non-zero auth_key_id in resPQ"
    );
    ensure!(
        payload[20..24] == [0x63, 0x24, 0x16, 0x05],
        "unexpected MTProto constructor (expected resPQ#05162463)"
    );
    ensure!(&payload[24..40] == expected_nonce, "resPQ nonce mismatch");
    Ok(())
}

async fn read_tls_record_raw(stream: &mut TcpStream) -> Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    stream
        .read_exact(&mut hdr)
        .await
        .context("reading TLS record header")?;
    let n = usize::from(u16::from_be_bytes([hdr[3], hdr[4]]));
    ensure!(n <= wire::MAX_RECORD, "TLS record exceeds bound");
    let mut body = vec![0u8; n];
    stream
        .read_exact(&mut body)
        .await
        .context("reading TLS record body")?;
    let mut raw = Vec::with_capacity(5 + n);
    raw.extend_from_slice(&hdr);
    raw.extend_from_slice(&body);
    Ok((hdr[0], raw))
}

async fn probe_telegram_e2e(
    cfg: &Config,
    addr: SocketAddr,
    dc_id: i16,
    limit: Duration,
) -> Result<u64> {
    use rand::RngCore;
    let started = Instant::now();
    timeout(limit, async {
        let mut nonce = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let mut req_frame = build_req_pq_multi_frame(&nonce);

        if cfg.role == Role::Egress {
            let token = cfg.egress_token()?;
            let mut dc = wire::dc_transport()?;
            let mut stream = TcpStream::connect(addr)
                .await
                .with_context(|| format!("connecting to egress {addr}"))?;
            let preface =
                build_egress_wire_preface(&token, dc_id, &dc.header, cfg.egress_use_mtv3)?;
            stream
                .write_all(&preface)
                .await
                .context("writing egress preface")?;
            let mut ack = [0u8; 1];
            stream
                .read_exact(&mut ack)
                .await
                .context("reading egress ACK")?;
            ensure!(ack[0] == EGRESS_ACK_OK, "egress returned negative ACK for DC {dc_id}");
            wire::crypt(&mut dc.encrypt, &mut req_frame);
            stream.write_all(&req_frame).await.context("sending req_pq_multi")?;

            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).await.context("reading DC frame length")?;
            wire::crypt(&mut dc.decrypt, &mut len_buf);
            let frame_len = (u32::from_le_bytes(len_buf) & 0x7fff_ffff) as usize;
            ensure!((40..=4096).contains(&frame_len), "unexpected DC frame length {frame_len}");
            let mut payload = vec![0u8; frame_len];
            stream.read_exact(&mut payload).await.context("reading DC resPQ payload")?;
            wire::crypt(&mut dc.decrypt, &mut payload);
            validate_res_pq_payload(&payload, &nonce)?;
            return Ok(started.elapsed().as_millis() as u64);
        }

        let secrets = cfg.secrets()?;
        let secret = &secrets[0].key;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let (hello_rec, client_random, client_session) =
            wire::build_client_hello(secret, &cfg.sni, now, &mut rand::rngs::OsRng)?;

        let mut stream = TcpStream::connect(addr)
            .await
            .with_context(|| format!("connecting to proxy {addr}"))?;
        stream.write_all(&hello_rec).await.context("writing FakeTLS ClientHello")?;

        let mut flight = Vec::new();
        for expected_kind in [0x16u8, 0x14u8, 0x17u8] {
            let (kind, raw) = read_tls_record_raw(&mut stream).await?;
            ensure!(
                kind == expected_kind,
                "unexpected ServerHello flight record kind 0x{kind:02x} (expected 0x{expected_kind:02x})"
            );
            flight.extend_from_slice(&raw);
        }
        wire::verify_server_flight(secret, &client_random, &client_session, &flight)?;

        let (init_hdr, mut encrypt, mut decrypt) = wire::build_client_init(secret, dc_id)?;
        wire::crypt(&mut encrypt, &mut req_frame);
        let mut combined = Vec::with_capacity(init_hdr.len() + req_frame.len());
        combined.extend_from_slice(&init_hdr);
        combined.extend_from_slice(&req_frame);
        let app_rec = wire::record(0x17, &combined)?;
        stream.write_all(&app_rec).await.context("writing obfuscated2 init + req_pq_multi")?;

        let mut tls_reader = TlsReader::default();
        let mut len_buf = [0u8; 4];
        let mut off = 0;
        while off < 4 {
            let n = tls_reader.read_into(&mut stream, &mut len_buf[off..]).await?;
            ensure!(n > 0, "EOF before Telegram DC reply length");
            off += n;
        }
        wire::crypt(&mut decrypt, &mut len_buf);
        let frame_len = (u32::from_le_bytes(len_buf) & 0x7fff_ffff) as usize;
        ensure!((40..=4096).contains(&frame_len), "unexpected Telegram reply frame length {frame_len}");
        let mut payload = vec![0u8; frame_len];
        let mut p_off = 0;
        while p_off < frame_len {
            let n = tls_reader.read_into(&mut stream, &mut payload[p_off..]).await?;
            ensure!(n > 0, "EOF before Telegram resPQ payload");
            p_off += n;
        }
        wire::crypt(&mut decrypt, &mut payload);
        validate_res_pq_payload(&payload, &nonce)?;
        Ok(started.elapsed().as_millis() as u64)
    })
    .await
    .context("probe_telegram_timeout")?
}

#[cfg(test)]
fn default_media_override_map() -> HashMap<i16, Vec<SocketAddr>> {
    Config {
        role: Role::Direct,
        listen: SocketAddr::from(([127, 0, 0, 1], 24443)),
        secret_file: None,
        users_file: None,
        replay_file: None,
        sni: String::new(),
        cover: String::new(),
        enable_dd: false,
        proxy_protocol: false,
        dc: Vec::new(),
        egress_upstreams: Vec::new(),
        egress_strategy: EgressStrategy::RoundRobin,
        egress_token_file: None,
        max_connections: 128,
        client_hello_timeout_secs: 5,
        handshake_timeout_secs: 10,
        idle_timeout_secs: 300,
        drain_timeout_secs: 5,
        fake_tls_cert_bytes: wire::DEFAULT_CERT_BYTES,
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
        dc_media_override: config::default_dc_media_override(),
        dc_probe_interval_secs: config::default_dc_probe_interval_secs(),
        cover_dns_ttl_secs: config::default_cover_dns_ttl_secs(),
        diagnostics: false,
        metrics_listen: None,
    }
    .dc_media_overrides()
    .unwrap_or_default()
}

#[cfg(test)]
fn lookup_dc_addr(dcs: &HashMap<i16, SocketAddr>, dc_id: i16) -> Option<SocketAddr> {
    lookup_dc_candidates(dcs, dc_id, 0).into_iter().next()
}

#[cfg(test)]
fn lookup_dc_candidates(dcs: &HashMap<i16, SocketAddr>, dc_id: i16, seq: usize) -> Vec<SocketAddr> {
    lookup_dc_candidates_with_overrides(dcs, &default_media_override_map(), dc_id, seq)
}

fn lookup_dc_candidates_with_overrides(
    dcs: &HashMap<i16, SocketAddr>,
    overrides: &HashMap<i16, Vec<SocketAddr>>,
    dc_id: i16,
    seq: usize,
) -> Vec<SocketAddr> {
    let std_dc2 = SocketAddr::from(([149, 154, 167, 51], 443));
    let std_dc2_media = SocketAddr::from(([149, 154, 167, 151], 443));
    let std_dc4 = SocketAddr::from(([149, 154, 167, 91], 443));
    let std_dc4_media = SocketAddr::from(([149, 154, 166, 120], 443));

    if let Some(&addr) = dcs.get(&dc_id) {
        let mut out = vec![addr];
        let is_standard_prod = (dc_id == 2 && addr == std_dc2)
            || (dc_id == -2 && addr == std_dc2_media)
            || (dc_id == 4 && addr == std_dc4)
            || (dc_id == -4 && addr == std_dc4_media);
        let apply_ovr = is_standard_prod
            || overrides
                .get(&dc_id)
                .is_some_and(|list| list.contains(&addr));
        if apply_ovr {
            if let Some(ovr_list) = overrides.get(&dc_id) {
                if dc_id < 0 && ovr_list.len() >= 2 && seq % 2 == 1 {
                    let mut rot = Vec::with_capacity(ovr_list.len() + 2);
                    for (i, &cand) in ovr_list.iter().enumerate() {
                        if i > 0 && !rot.contains(&cand) {
                            rot.push(cand);
                        }
                    }
                    if !rot.contains(&addr) {
                        rot.push(addr);
                    }
                    if let Some(&first) = ovr_list.first() {
                        if !rot.contains(&first) {
                            rot.push(first);
                        }
                    }
                    out = rot;
                } else {
                    for &cand in ovr_list {
                        if !out.contains(&cand) {
                            out.push(cand);
                        }
                    }
                }
            }
            if dc_id < 0 {
                if let Some(&base) = dcs.get(&dc_id.abs()) {
                    if !out.contains(&base) {
                        out.push(base);
                    }
                } else if dc_id == -2 && !out.contains(&std_dc2) {
                    out.push(std_dc2);
                } else if dc_id == -4 && !out.contains(&std_dc4) {
                    out.push(std_dc4);
                }
            }
        }
        return out;
    }
    if dc_id < 0 {
        if let Some(ovr_list) = overrides.get(&dc_id).filter(|l| !l.is_empty()) {
            let apply = match dcs.get(&dc_id.abs()) {
                Some(&base) => {
                    (dc_id == -2 && base == std_dc2)
                        || (dc_id == -4 && base == std_dc4)
                        || ovr_list.iter().any(|c| {
                            c.ip() != std_dc2_media.ip()
                                && c.ip() != std_dc4_media.ip()
                                && c.ip() != std::net::IpAddr::from([149, 154, 167, 220])
                                && c.ip() != std::net::IpAddr::from([149, 154, 167, 92])
                        })
                }
                None => false,
            };
            if apply {
                let mut out = if ovr_list.len() >= 2 && seq % 2 == 1 {
                    let mut rot = ovr_list[1..].to_vec();
                    rot.push(ovr_list[0]);
                    rot
                } else {
                    ovr_list.clone()
                };
                if let Some(&base) = dcs.get(&dc_id.abs()) {
                    if !out.contains(&base) {
                        out.push(base);
                    }
                }
                return out;
            }
        }
    }
    let Some(&base) = dcs.get(&dc_id.abs()) else {
        return Vec::new();
    };
    vec![base]
}

async fn run_dc_reachability_check_once(
    dcs: &HashMap<i16, SocketAddr>,
    overrides: &HashMap<i16, Vec<SocketAddr>>,
    counters: &telemetry::Counters,
    per_target_limit: Duration,
) -> (usize, usize) {
    use std::sync::atomic::Ordering::Relaxed;
    let mut targets: Vec<(i16, SocketAddr)> = Vec::new();
    let mut ids: Vec<i16> = dcs.keys().copied().collect();
    for &id in overrides.keys() {
        if !ids.contains(&id) && dcs.contains_key(&id.abs()) {
            ids.push(id);
        }
    }
    ids.sort();
    for id in ids {
        for addr in lookup_dc_candidates_with_overrides(dcs, overrides, id, 0) {
            if !targets.iter().any(|(_, a)| *a == addr) {
                targets.push((id, addr));
            }
        }
    }
    let mut ok_count = 0usize;
    let mut fail_count = 0usize;
    let mut checks = Vec::with_capacity(targets.len());
    for (dc_id, addr) in targets {
        let t0 = Instant::now();
        let reachable = timeout(per_target_limit, TcpStream::connect(addr))
            .await
            .is_ok_and(|res| res.is_ok());
        let rtt_ms = t0.elapsed().as_millis() as u64;
        if reachable {
            ok_count += 1;
            counters.dc_self_check_ok.fetch_add(1, Relaxed);
        } else {
            fail_count += 1;
            counters.dc_self_check_failed.fetch_add(1, Relaxed);
        }
        checks.push(json!({
            "dc": dc_id,
            "address": addr.to_string(),
            "reachable": reachable,
            "rtt_ms": rtt_ms,
        }));
    }
    telemetry::event(
        "dc_self_check",
        0,
        json!({
            "reachable_count": ok_count,
            "unreachable_count": fail_count,
            "checks": checks,
        }),
    );
    (ok_count, fail_count)
}

async fn monitor_dc_reachability(
    dcs: Arc<HashMap<i16, SocketAddr>>,
    overrides: Arc<HashMap<i16, Vec<SocketAddr>>>,
    counters: Arc<telemetry::Counters>,
    period: Duration,
) {
    let mut interval = tokio::time::interval(period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let _ = run_dc_reachability_check_once(&dcs, &overrides, &counters, Duration::from_secs(3))
            .await;
    }
}

async fn connect_dc_candidates(
    candidates: &[SocketAddr],
    handshake: Duration,
) -> Result<TcpStream> {
    ensure!(!candidates.is_empty(), "DC not configured");
    if candidates.len() == 1 {
        let stream = timeout(handshake, TcpStream::connect(candidates[0]))
            .await
            .context("dc_connect_timeout")?
            .context("dc_connect_failed")?;
        configure_tcp_socket(&stream)?;
        return Ok(stream);
    }
    let per_try = (handshake / (candidates.len() as u32))
        .max(Duration::from_millis(200))
        .min(Duration::from_millis(1500));
    timeout(handshake, async {
        let mut last_err = None;
        for &addr in candidates {
            match timeout(per_try, TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => {
                    configure_tcp_socket(&stream)?;
                    return Ok(stream);
                }
                Ok(Err(err)) => last_err = Some(anyhow::Error::from(err)),
                Err(_) => last_err = Some(anyhow::anyhow!("dc_connect_timeout")),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("dc_connect_failed")))
            .context("dc_connect_failed")
    })
    .await
    .context("dc_connect_timeout")?
}

enum EgressAttemptErr {
    Node(anyhow::Error),
    Dc(anyhow::Error),
}

async fn dial_egress_candidate(
    state: &State,
    idx: usize,
    dc_id: i16,
    dc_abs: i16,
    dc_header: &[u8; 64],
    per_try: Duration,
) -> std::result::Result<TcpStream, EgressAttemptErr> {
    use std::sync::atomic::Ordering::Relaxed;
    let addr = state.egress_upstreams[idx];
    match timeout(per_try, async {
        let mut upstream = TcpStream::connect(addr)
            .await
            .map_err(|e| EgressAttemptErr::Node(e.into()))?;
        configure_tcp_socket(&upstream).map_err(EgressAttemptErr::Node)?;
        let preface =
            build_egress_wire_preface(&state.egress_token, dc_id, dc_header, state.egress_use_mtv3)
                .map_err(EgressAttemptErr::Node)?;
        upstream
            .write_all(&preface)
            .await
            .map_err(|e| EgressAttemptErr::Node(e.into()))?;
        state
            .counters
            .upstream_tx_bytes
            .fetch_add(preface.len() as u64, Relaxed);
        let mut ack = [0u8; 1];
        upstream
            .read_exact(&mut ack)
            .await
            .map_err(|e| EgressAttemptErr::Node(e.into()))?;
        state
            .counters
            .upstream_rx_bytes
            .fetch_add(ack.len() as u64, Relaxed);
        if ack[0] == EGRESS_ACK_OK {
            Ok(upstream)
        } else if ack[0] == EGRESS_ACK_ERR {
            Err(EgressAttemptErr::Dc(anyhow::anyhow!(
                "egress DC {dc_abs} unreachable (negative ACK)"
            )))
        } else {
            Err(EgressAttemptErr::Node(anyhow::anyhow!(
                "egress upstream invalid ACK byte"
            )))
        }
    })
    .await
    {
        Ok(res) => res,
        Err(_) => Err(EgressAttemptErr::Node(anyhow::anyhow!(
            "egress_connect_timeout"
        ))),
    }
}

fn finalize_egress_success(
    state: &State,
    idx: usize,
    claim: EgressAttemptClaim<'_>,
    ordered: bool,
    last_err: &Option<anyhow::Error>,
    default_backup_reason: &'static str,
) {
    let addr = state.egress_upstreams[idx];
    claim.record_success();
    let (healthy, total) = EgressHealth::set_node_availability(&state.egress_health, idx, true);
    let (next_state, reason, active_override) = if ordered {
        if idx == 0 {
            (
                EdgeRouteState::PrimaryOk,
                "primary_recovered".to_string(),
                Some(addr),
            )
        } else {
            state
                .counters
                .egress_failover_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            (
                EdgeRouteState::FailoverBackup(idx),
                last_err
                    .as_ref()
                    .map(|e| format!("{e:#}"))
                    .unwrap_or_else(|| default_backup_reason.to_string()),
                Some(addr),
            )
        }
    } else if healthy == total {
        (
            EdgeRouteState::PrimaryOk,
            "all_egress_recovered".to_string(),
            Some(addr),
        )
    } else {
        (
            EdgeRouteState::Degraded { healthy, total },
            last_err
                .as_ref()
                .map(|e| format!("{e:#}"))
                .unwrap_or_else(|| default_backup_reason.to_string()),
            Some(addr),
        )
    };
    if let Some(ev) = EgressHealth::transition_route_state(
        &state.egress_health,
        next_state,
        &state.egress_upstreams,
        reason,
        state.egress_strategy,
        active_override,
    ) {
        emit_edge_route_alert(state, ev);
    }
}

fn finalize_egress_error(
    state: &State,
    idx: usize,
    claim: EgressAttemptClaim<'_>,
    err: EgressAttemptErr,
) -> anyhow::Error {
    EgressHealth::set_node_availability(&state.egress_health, idx, false);
    match err {
        EgressAttemptErr::Dc(e) => {
            claim.record_dc_failure(state.egress_cooldown, state.egress_cooldown_max);
            e
        }
        EgressAttemptErr::Node(e) => {
            claim.record_node_failure(state.egress_cooldown, state.egress_cooldown_max);
            e
        }
    }
}

async fn connect_upstream(
    state: &State,
    dc_id: i16,
    dc_header: &[u8; 64],
) -> Result<(TcpStream, &'static str)> {
    use std::sync::atomic::Ordering::Relaxed;
    if state.egress_upstreams.is_empty() {
        let seq = state.egress_rr.fetch_add(1, Relaxed);
        let candidates =
            lookup_dc_candidates_with_overrides(&state.dcs, &state.dc_media_overrides, dc_id, seq);
        let mut upstream = connect_dc_candidates(&candidates, state.handshake).await?;
        timeout(state.handshake, upstream.write_all(dc_header)).await??;
        state
            .counters
            .upstream_tx_bytes
            .fetch_add(dc_header.len() as u64, Relaxed);
        return Ok((upstream, "direct"));
    }
    let count = state.egress_upstreams.len();
    let start = match state.egress_strategy {
        EgressStrategy::Ordered => 0,
        EgressStrategy::RoundRobin => state.egress_rr.fetch_add(1, Relaxed),
    };
    let per_try = (state.handshake / (count as u32).max(1))
        .max(Duration::from_millis(150))
        .min(Duration::from_secs(2));
    let dc_abs = dc_id.abs();
    let ordered = state.egress_strategy == EgressStrategy::Ordered;
    let hedge_delay = (ordered && state.egress_hedge_ms > 0)
        .then(|| Duration::from_millis(state.egress_hedge_ms))
        .filter(|d| *d < per_try);
    timeout(state.handshake, async {
        let mut last_err: Option<anyhow::Error> = None;
        let mut attempted_any = false;
        let mut hedged_this_conn = false;
        let mut offset = 0;
        while offset < count {
            let idx = (start + offset) % count;
            offset += 1;
            let Some(claim) =
                EgressHealth::try_claim(&state.egress_health, idx, dc_abs, Instant::now())
            else {
                continue;
            };
            attempted_any = true;
            if let Some(h_delay) = hedge_delay.filter(|_| !hedged_this_conn && offset < count) {
                let fut1 = dial_egress_candidate(state, idx, dc_id, dc_abs, dc_header, per_try);
                tokio::pin!(fut1);
                let early = tokio::select! {
                    biased;
                    res1 = &mut fut1 => Some(res1),
                    () = tokio::time::sleep(h_delay) => None,
                };
                if let Some(res1) = early {
                    match res1 {
                        Ok(upstream) => {
                            finalize_egress_success(
                                state,
                                idx,
                                claim,
                                ordered,
                                &last_err,
                                "primary_in_cooldown",
                            );
                            return Ok((upstream, "egress"));
                        }
                        Err(err1) => {
                            last_err = Some(finalize_egress_error(state, idx, claim, err1));
                            continue;
                        }
                    }
                }
                // Primary did not ACK within hedge_delay: claim next available candidate for hedge (at most 1 per conn).
                let mut backup_claim = None;
                while offset < count {
                    let cand_idx = (start + offset) % count;
                    offset += 1;
                    if let Some(c2) = EgressHealth::try_claim(
                        &state.egress_health,
                        cand_idx,
                        dc_abs,
                        Instant::now(),
                    ) {
                        backup_claim = Some((cand_idx, c2));
                        break;
                    }
                }
                let Some((idx2, claim2)) = backup_claim else {
                    match fut1.await {
                        Ok(upstream) => {
                            finalize_egress_success(
                                state,
                                idx,
                                claim,
                                ordered,
                                &last_err,
                                "primary_in_cooldown",
                            );
                            return Ok((upstream, "egress"));
                        }
                        Err(err1) => {
                            last_err = Some(finalize_egress_error(state, idx, claim, err1));
                            continue;
                        }
                    }
                };
                hedged_this_conn = true;
                state.counters.hedge_started.fetch_add(1, Relaxed);
                let fut2 = dial_egress_candidate(state, idx2, dc_id, dc_abs, dc_header, per_try);
                tokio::pin!(fut2);
                enum HedgeRace {
                    First(std::result::Result<TcpStream, EgressAttemptErr>),
                    Second(std::result::Result<TcpStream, EgressAttemptErr>),
                }
                let first_done = tokio::select! {
                    res1 = &mut fut1 => HedgeRace::First(res1),
                    res2 = &mut fut2 => HedgeRace::Second(res2),
                };
                match first_done {
                    HedgeRace::First(Ok(stream1)) => {
                        drop(claim2);
                        finalize_egress_success(
                            state,
                            idx,
                            claim,
                            ordered,
                            &last_err,
                            "primary_in_cooldown",
                        );
                        return Ok((stream1, "egress"));
                    }
                    HedgeRace::First(Err(err1)) => {
                        last_err = Some(finalize_egress_error(state, idx, claim, err1));
                        match fut2.await {
                            Ok(stream2) => {
                                state.counters.hedge_won_by_backup.fetch_add(1, Relaxed);
                                finalize_egress_success(
                                    state,
                                    idx2,
                                    claim2,
                                    ordered,
                                    &last_err,
                                    "hedged_connect_backup_won",
                                );
                                return Ok((stream2, "egress"));
                            }
                            Err(err2) => {
                                last_err = Some(finalize_egress_error(state, idx2, claim2, err2));
                                continue;
                            }
                        }
                    }
                    HedgeRace::Second(Ok(stream2)) => {
                        state.counters.hedge_won_by_backup.fetch_add(1, Relaxed);
                        last_err = Some(finalize_egress_error(
                            state,
                            idx,
                            claim,
                            EgressAttemptErr::Node(anyhow::anyhow!("hedged_primary_slow_ack")),
                        ));
                        finalize_egress_success(
                            state,
                            idx2,
                            claim2,
                            ordered,
                            &last_err,
                            "hedged_connect_backup_won",
                        );
                        return Ok((stream2, "egress"));
                    }
                    HedgeRace::Second(Err(err2)) => {
                        last_err = Some(finalize_egress_error(state, idx2, claim2, err2));
                        match fut1.await {
                            Ok(stream1) => {
                                finalize_egress_success(
                                    state,
                                    idx,
                                    claim,
                                    ordered,
                                    &last_err,
                                    "primary_in_cooldown",
                                );
                                return Ok((stream1, "egress"));
                            }
                            Err(err1) => {
                                last_err = Some(finalize_egress_error(state, idx, claim, err1));
                                continue;
                            }
                        }
                    }
                }
            }

            match dial_egress_candidate(state, idx, dc_id, dc_abs, dc_header, per_try).await {
                Ok(upstream) => {
                    finalize_egress_success(
                        state,
                        idx,
                        claim,
                        ordered,
                        &last_err,
                        "primary_in_cooldown",
                    );
                    return Ok((upstream, "egress"));
                }
                Err(err) => {
                    last_err = Some(finalize_egress_error(state, idx, claim, err));
                }
            }
        }
        // Fail-open when all nodes were in cooldown: force a single probe on the node
        // whose cooldown expires soonest (at most 1 concurrent forced probe per node).
        if !attempted_any {
            if let Some((idx, claim)) =
                EgressHealth::try_claim_forced_soonest(&state.egress_health, count, dc_abs)
            {
                match dial_egress_candidate(state, idx, dc_id, dc_abs, dc_header, per_try).await {
                    Ok(upstream) => {
                        finalize_egress_success(
                            state,
                            idx,
                            claim,
                            ordered,
                            &last_err,
                            "forced_probe_recovered",
                        );
                        return Ok((upstream, "egress"));
                    }
                    Err(err) => {
                        last_err = Some(finalize_egress_error(state, idx, claim, err));
                    }
                }
            }
        }
        let err = last_err
            .unwrap_or_else(|| anyhow::anyhow!("all egress upstreams in cooldown or unavailable"));
        if let Some(ev) = EgressHealth::transition_route_state(
            &state.egress_health,
            EdgeRouteState::AllDown,
            &state.egress_upstreams,
            format!("{err:#}"),
            state.egress_strategy,
            None,
        ) {
            emit_edge_route_alert(state, ev);
        }
        Err(err).context("egress_connect_failed")
    })
    .await
    .context("egress_budget_timeout")?
}

#[derive(Clone)]
struct EgressSecurityConfig {
    accept_legacy: bool,
    allow_from: Vec<config::IpCidr>,
    max_failed_per_ip: usize,
    failed_window: Duration,
    max_unauth_handshakes: usize,
    dc_media_overrides: HashMap<i16, Vec<SocketAddr>>,
}

impl EgressSecurityConfig {
    #[cfg(test)]
    fn default_for(max_connections: usize) -> Self {
        Self {
            accept_legacy: true,
            allow_from: Vec::new(),
            max_failed_per_ip: config::default_egress_max_failed_per_ip(),
            failed_window: Duration::from_secs(60),
            max_unauth_handshakes: (max_connections / 4).clamp(4, 128),
            dc_media_overrides: default_media_override_map(),
        }
    }

    fn allows_ip(&self, ip: std::net::IpAddr) -> bool {
        self.allow_from.is_empty() || self.allow_from.iter().any(|cidr| cidr.contains(ip))
    }
}

struct IpFailureTracker {
    entries: HashMap<std::net::IpAddr, std::collections::VecDeque<Instant>>,
    window: Duration,
    max_failed: usize,
}

impl IpFailureTracker {
    fn new(window: Duration, max_failed: usize) -> Self {
        Self {
            entries: HashMap::new(),
            window,
            max_failed,
        }
    }

    fn prune(&mut self, now: Instant) {
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

    fn is_rate_limited(&mut self, ip: std::net::IpAddr, now: Instant) -> bool {
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

    fn record_failure(&mut self, ip: std::net::IpAddr, now: Instant) {
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

struct EgressRuntimeSecurity {
    cfg: EgressSecurityConfig,
    unauth_permits: Semaphore,
    nonce_replay: Mutex<ReplayCache>,
    failed_by_ip: std::sync::Mutex<IpFailureTracker>,
}

impl EgressRuntimeSecurity {
    fn new(cfg: EgressSecurityConfig) -> Self {
        let max_unauth = cfg.max_unauth_handshakes.max(1);
        let failed_tracker = IpFailureTracker::new(cfg.failed_window, cfg.max_failed_per_ip);
        Self {
            cfg,
            unauth_permits: Semaphore::new(max_unauth),
            nonce_replay: Mutex::new(ReplayCache::new(16384, Duration::from_secs(65))),
            failed_by_ip: std::sync::Mutex::new(failed_tracker),
        }
    }

    fn check_peer_allowed(&self, ip: std::net::IpAddr) -> Result<()> {
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

    fn record_auth_failure(&self, ip: std::net::IpAddr) {
        let mut tracker = self.failed_by_ip.lock().unwrap_or_else(|e| e.into_inner());
        tracker.record_failure(ip, Instant::now());
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
async fn serve_egress(
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
async fn serve_egress_with_security(
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
async fn egress_connection(
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

#[cfg(test)]
mod tests;
