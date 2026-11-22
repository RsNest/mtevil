use anyhow::{bail, ensure, Context, Result};
use clap::{Parser, Subcommand};
use mtevil_egress::compute_egress_cooldown;
#[cfg(test)]
use mtevil_egress::{apply_cooldown_jitter_ms, compute_egress_cooldown_unclamped_ms};
use mtevil_guard::replay::{self, Decision, ReplayCache};
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

mod config;
use config::{Config, EgressStrategy, NamedSecret, Role};
mod telemetry;
use serde_json::json;

mod alerts;
mod connect;
mod cover;
mod egress_health;
mod egress_server;
mod me;
mod relay;
mod serve;

use alerts::*;
use connect::*;
use cover::*;
use egress_health::*;
use egress_server::*;
use relay::*;
use serve::*;

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
            egress_nonce_cache_capacity: None,
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
            me: config::MeConfig::default(),
        };
        config.validate()?;
        Ok(config)
    }
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
    /// Per-egress cooldown strictly for `MTV4` (when an egress rejects `MTV4` or is `v0.2.0`),
    /// kept separate from `EgressHealth` so `MTV3` Direct fallback is never penalized.
    mtv4_cooldown: std::sync::Mutex<Vec<Option<Instant>>>,
    egress_probe_notify: Arc<tokio::sync::Notify>,
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
    me: Option<Arc<me::MeRuntime>>,
    edge_me: Option<Arc<me::EdgeMeSettings>>,
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

const RUNTIME_STATS_DEFAULT_PATH: &str = "/var/lib/mtevil-replay/runtime-stats.json";
const RUNTIME_STATS_LEGACY_PATH: &str = "/var/lib/mtevil/runtime-stats.json";

fn default_runtime_stats_path() -> PathBuf {
    let preferred = PathBuf::from(RUNTIME_STATS_DEFAULT_PATH);
    if preferred.parent().is_some_and(|p| p.is_dir()) {
        preferred
    } else {
        PathBuf::from(RUNTIME_STATS_LEGACY_PATH)
    }
}

fn write_runtime_stats_atomic(
    path: &std::path::Path,
    counters: &telemetry::Counters,
    role: &str,
    me: Option<&me::MeRuntime>,
) -> Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            return Ok(());
        }
    }
    let me_snap = me.map(me::MeRuntime::telemetry_snapshot);
    let val = counters.snapshot_json_with_me(role, me_snap.as_ref());
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
    me: Option<Arc<me::MeRuntime>>,
    mut stop_rx: tokio::sync::oneshot::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    counters.ensure_started();
    let _ = write_runtime_stats_atomic(&path, &counters, role, me.as_deref());
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(period);
        interval.tick().await;
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = &mut stop_rx => break,
            }
            let _ = write_runtime_stats_atomic(&path, &counters, role, me.as_deref());
        }
        let _ = write_runtime_stats_atomic(&path, &counters, role, me.as_deref());
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
                let effective = if !stats_file.exists()
                    && stats_file == std::path::Path::new(RUNTIME_STATS_DEFAULT_PATH)
                    && std::path::Path::new(RUNTIME_STATS_LEGACY_PATH).exists()
                {
                    PathBuf::from(RUNTIME_STATS_LEGACY_PATH)
                } else {
                    stats_file
                };
                let text = std::fs::read_to_string(&effective).with_context(|| {
                    format!("reading runtime stats file {}", effective.display())
                })?;
                let val: serde_json::Value = serde_json::from_str(&text).with_context(|| {
                    format!("parsing runtime stats file {}", effective.display())
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
                .and_then(|p| p.parent().map(|dir| dir.join("runtime-stats.json")))
        })
        .or_else(|| {
            let preferred = PathBuf::from(RUNTIME_STATS_DEFAULT_PATH);
            preferred
                .parent()
                .is_some_and(|p| p.is_dir())
                .then_some(preferred)
        })
        .or_else(|| {
            config
                .secret_file
                .as_ref()
                .or(config.egress_token_file.as_ref())
                .and_then(|p| p.parent().map(|dir| dir.join("runtime-stats.json")))
        })
        .unwrap_or_else(default_runtime_stats_path);
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
        let me_cache_dir = stats_path
            .parent()
            .map(|d| d.join("me-cache"))
            .unwrap_or_else(|| PathBuf::from("/var/lib/mtevil-replay/me-cache"));
        let egress_me_rt = if config.me.enabled {
            Some(me::MeRuntime::start(config.me.clone(), me_cache_dir, counters.clone()).await)
        } else {
            None
        };
        let (stats_stop_tx, stats_stop_rx) = tokio::sync::oneshot::channel::<()>();
        let stats_task = spawn_stats_writer(
            counters.clone(),
            "egress",
            stats_path,
            Duration::from_millis(500),
            egress_me_rt.clone(),
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
            nonce_cache_capacity: config
                .egress_nonce_cache_capacity
                .unwrap_or_else(|| config::default_egress_nonce_cache_capacity(effective_max)),
            dc_media_overrides: dc_media_overrides.clone(),
            me: egress_me_rt.clone(),
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
        if let Some(me_rt) = &egress_me_rt {
            me_rt.shutdown();
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
    let me_cache_dir = config
        .replay_file
        .as_ref()
        .and_then(|p| p.parent().map(|d| d.join("me-cache")))
        .or_else(|| stats_path.parent().map(|d| d.join("me-cache")))
        .unwrap_or_else(|| PathBuf::from("/var/lib/mtevil-replay/me-cache"));
    let is_edge_role = config.role == Role::Edge || !config.egress_upstreams.is_empty();
    let me_runtime = if config.me.enabled && !is_edge_role {
        Some(me::MeRuntime::start(config.me.clone(), me_cache_dir, counters.clone()).await)
    } else {
        None
    };
    let edge_me_settings = if config.me.enabled && is_edge_role {
        Some(Arc::new(me::EdgeMeSettings::new(
            config.me.fallback_to_direct,
            config.me.send_client_ip,
        )))
    } else {
        None
    };
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
        mtv4_cooldown: std::sync::Mutex::new(vec![None; egress_count]),
        egress_probe_notify: Arc::new(tokio::sync::Notify::new()),
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
        me: me_runtime.clone(),
        edge_me: edge_me_settings,
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
        me_runtime.clone(),
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
    if let Some(me_rt) = &state.me {
        me_rt.shutdown();
    }
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

#[cfg(test)]
mod tests;
