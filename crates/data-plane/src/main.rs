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
    #[arg(long, conflicts_with_all=["listen","secret_file","users_file","replay_file","sni","cover","dc","egress_upstreams","egress_strategy","egress_token_file","role","enable_dd","proxy_protocol","max_connections","client_hello_timeout_secs","handshake_timeout_secs","idle_timeout_secs","drain_timeout_secs","fake_tls_cert_bytes","fake_tls_cert_jitter","flight_shaping","client_mss","client_mss_bulk"])]
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
        };
        config.validate()?;
        Ok(config)
    }
}

#[derive(Default, Clone, Copy)]
struct CooldownSlot {
    until: Option<Instant>,
    probing: bool,
}

#[derive(Default)]
struct EgressHealth {
    nodes: Vec<CooldownSlot>,
    dc_slots: HashMap<(usize, i16), CooldownSlot>,
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
    fn new(node_count: usize) -> Self {
        Self {
            nodes: vec![CooldownSlot::default(); node_count],
            dc_slots: HashMap::new(),
        }
    }

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
}

impl<'a> EgressAttemptClaim<'a> {
    fn record_success(mut self) {
        self.completed = true;
        let mut h = self.health.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(slot) = h.nodes.get_mut(self.idx) {
            slot.until = None;
            slot.probing = false;
        }
        if let Some(slot) = h.dc_slots.get_mut(&(self.idx, self.dc)) {
            slot.until = None;
            slot.probing = false;
        }
    }

    fn record_node_failure(mut self, cooldown: Duration) {
        self.completed = true;
        let mut h = self.health.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(slot) = h.nodes.get_mut(self.idx) {
            slot.until = Some(Instant::now() + cooldown);
            slot.probing = false;
        }
        if self.dc_probe {
            if let Some(slot) = h.dc_slots.get_mut(&(self.idx, self.dc)) {
                slot.probing = false;
            }
        }
    }

    fn record_dc_failure(mut self, cooldown: Duration) {
        self.completed = true;
        let mut h = self.health.lock().unwrap_or_else(|e| e.into_inner());
        if self.node_probe {
            if let Some(slot) = h.nodes.get_mut(self.idx) {
                slot.until = None;
                slot.probing = false;
            }
        }
        h.dc_slots.insert(
            (self.idx, self.dc),
            CooldownSlot {
                until: Some(Instant::now() + cooldown),
                probing: false,
            },
        );
    }
}

struct State {
    secrets: std::sync::RwLock<Arc<Vec<NamedSecret>>>,
    sni: String,
    cover: String,
    enable_dd: bool,
    proxy_protocol: bool,
    cover_permits: Semaphore,
    dcs: HashMap<i16, SocketAddr>,
    egress_upstreams: Vec<SocketAddr>,
    egress_strategy: EgressStrategy,
    egress_token: [u8; 16],
    egress_rr: std::sync::atomic::AtomicUsize,
    egress_health: std::sync::Mutex<EgressHealth>,
    egress_cooldown: Duration,
    client_hello: Duration,
    handshake: Duration,
    idle: Duration,
    drain: Duration,
    flight: wire::ServerFlightProfile,
    flight_shaping: bool,
    client_mss_bulk: Option<u16>,
    replay: Mutex<ReplayCache>,
    counters: Arc<telemetry::Counters>,
}

impl State {
    fn current_secrets(&self) -> Arc<Vec<NamedSecret>> {
        self.secrets
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn reload_secrets(&self, config: &Config) {
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

// Query TCP_INFO on Linux to measure TCP retransmissions on mtevil's own sockets only,
// excluding unrelated VPS traffic even when running with network_mode: host.
#[cfg(unix)]
#[allow(unsafe_code)]
fn sample_fd_retrans(fd: Option<std::os::fd::RawFd>, prev: &mut u32, acc: &std::sync::atomic::AtomicU64) {
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
                        format!("ee{key}{}", hex::encode(config.sni.as_bytes()))
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
                    let probe = probe_egress_endpoint(*addr, dc, &token, per_try).await;
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
                let text = std::fs::read_to_string(&stats_file)
                    .with_context(|| format!("reading runtime stats file {}", stats_file.display()))?;
                let val: serde_json::Value = serde_json::from_str(&text)
                    .with_context(|| format!("parsing runtime stats file {}", stats_file.display()))?;
                println!("{}", serde_json::to_string_pretty(&val)?);
                return Ok(());
            }
        }
    }
    let check_config = args.check_config;
    let config = args.runtime_config()?;
    let dcs = config.datacenters().unwrap_or_default();
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
        let listener = bind_listener(config.listen, None)?;
        telemetry::event(
            "startup",
            0,
            json!({
                "version":BUILD_VERSION,
                "role":"egress",
                "listen":listener.local_addr()?.to_string(),
                "max_connections":config.max_connections,
                "authenticated":config.egress_token_file.is_some(),
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
        #[cfg(unix)]
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let res = serve_egress(
            listener,
            Arc::new(dcs),
            egress_token,
            config.max_connections,
            Duration::from_secs(config.handshake_timeout_secs),
            Duration::from_secs(config.idle_timeout_secs),
            Duration::from_secs(config.drain_timeout_secs),
            counters,
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
        let _ = stats_stop_tx.send(());
        let _ = stats_task.await;
        return res;
    }
    let secrets = config.secrets()?;
    if check_config {
        println!("configuration valid");
        return Ok(());
    }
    let replay_ttl = Duration::from_secs(300);
    let replay = match &config.replay_file {
        Some(path) => ReplayCache::load_or_new(path.clone(), 65536, replay_ttl)?,
        None => ReplayCache::new(65536, replay_ttl),
    };
    let max_cover_connections = (config.max_connections / 4).max(1);
    let user_count = secrets.len();
    let persistent_replay = config.replay_file.is_some();
    let reload_config = config.users_file.is_some().then(|| config.clone());
    let egress_count = config.egress_upstreams.len();
    let counters = Arc::new(telemetry::Counters::default());
    counters.ensure_started();
    let state = Arc::new(State {
        secrets: std::sync::RwLock::new(Arc::new(secrets)),
        sni: config.sni,
        cover: config.cover,
        enable_dd: config.enable_dd,
        proxy_protocol: config.proxy_protocol,
        cover_permits: Semaphore::new(max_cover_connections),
        dcs,
        egress_upstreams: config.egress_upstreams,
        egress_strategy: config.egress_strategy,
        egress_token,
        egress_rr: std::sync::atomic::AtomicUsize::new(0),
        egress_health: std::sync::Mutex::new(EgressHealth::new(egress_count)),
        egress_cooldown: Duration::from_secs(15),
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
    let listener = bind_listener(config.listen, config.client_mss)?;
    telemetry::event(
        "startup",
        0,
        json!({
            "version":BUILD_VERSION,
            "role": role_str,
            "listen":listener.local_addr()?.to_string(),
            "max_connections":config.max_connections,
            "max_cover_connections":max_cover_connections,
            "users":user_count,
            "persistent_replay":persistent_replay,
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
                        Ok(Err(err)) => telemetry::event(
                            "replay_flush_failed",
                            0,
                            json!({"error": format!("{err:#}")}),
                        ),
                        Err(err) => telemetry::event(
                            "replay_flush_failed",
                            0,
                            json!({"error": format!("{err:#}")}),
                        ),
                    }
                }
            }
        })
    });
    let (users_stop_tx, users_stop_rx) = tokio::sync::oneshot::channel::<()>();
    let users_task = reload_config
        .map(|cfg| spawn_users_reloader(state.clone(), cfg, Duration::from_secs(1), users_stop_rx));
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let res = serve(listener, state.clone(), config.max_connections, async {
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
    let _ = users_stop_tx.send(());
    if let Some(task) = users_task {
        let _ = task.await;
    }
    let _ = flush_stop_tx.send(());
    if let Some(task) = flush_task {
        let _ = task.await;
    }
    if let Err(err) = state.replay.lock().await.flush_snapshot() {
        telemetry::event("replay_flush_failed", 0, json!({"error": format!("{err:#}")}));
    }
    res
}

async fn serve(
    listener: TcpListener,
    state: Arc<State>,
    max_connections: usize,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    let permits = Arc::new(Semaphore::new(max_connections));
    let mut tasks = tokio::task::JoinSet::new();
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
        let (socket, _) = tokio::select! {
            accepted = listener.accept() => accepted?,
            _ = &mut shutdown => break,
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

async fn read_proxy_v2<R: AsyncRead + Unpin>(
    r: &mut R,
    limit: Duration,
) -> Result<ProxyV2Outcome> {
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
            if state
                .replay
                .lock()
                .await
                .check_and_insert(key, Instant::now())
                != Decision::Fresh
            {
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
    let (auth, failure) = match received {
        Ok(Ok(Some(bytes))) => {
            let mut matched = None;
            let mut last_err = String::new();
            for s in secrets.iter() {
                match wire::authenticate_with_record_version(
                    &bytes,
                    record_minor,
                    &s.key,
                    &state.sni,
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
    let accepted = {
        let mut cache = state.replay.lock().await;
        cache.check_and_insert(hello.replay_key, Instant::now()) == Decision::Fresh
    };
    if !accepted {
        telemetry::event(
            "cover_selected",
            session_id,
            json!({"reason":"replay_or_cache_full"}),
        );
        return bounded_cover(client, raw, state, session_id).await;
    }
    let flight =
        wire::server_flight(&matched_secret.key, &hello, &state.flight, &mut rand::rngs::OsRng)?;
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
    let transport = wire::client_transport(&frame, &matched_secret.key)
        .context("inner_transport_invalid")?;
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

#[derive(Default)]
struct TlsReader {
    pending: Vec<u8>,
    offset: usize,
    /// Wire bytes read from the socket, including TLS headers and partial records.
    consumed: u64,
}
impl TlsReader {
    async fn read_exact_counted<R: AsyncRead + Unpin>(
        r: &mut R,
        mut bytes: &mut [u8],
        consumed: &mut u64,
    ) -> std::io::Result<()> {
        while !bytes.is_empty() {
            let n = r.read(bytes).await?;
            if n == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            *consumed += n as u64;
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
                let n = r.read(&mut h[..1]).await?;
                if n == 0 {
                    return Ok(0);
                }
                self.consumed += n as u64;
                Self::read_exact_counted(r, &mut h[1..], &mut self.consumed).await?;
                ensure!(h[1..3] == [3, 3], "TLS record version");
                let n = usize::from(u16::from_be_bytes([h[3], h[4]]));
                let limit = if h[0] == 0x17 {
                    MAX_CLIENT_RECORD
                } else {
                    wire::MAX_RECORD
                };
                ensure!(n > 0 && n <= limit, "TLS record limit");
                self.pending.resize(n, 0);
                Self::read_exact_counted(r, &mut self.pending, &mut self.consumed).await?;
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
    let mut buf = [0u8; wire::MAX_RECORD];
    let mut prefix = [0u8; 28];
    let mut prefix_len = 0;
    let mut prev_retrans = 0u32;
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
                sample_fd_retrans(stats.upstream_fd, &mut prev_retrans, &counters.upstream_retrans_segs);
            }
            return res;
        }
        stats.client_reads.fetch_add(1, Relaxed);
        stats.record_activity();
        stats.timeline.mark("client_read", n as u64);
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
                    sample_fd_retrans(stats.upstream_fd, &mut prev_retrans, &counters.upstream_retrans_segs);
                }
                return stats.failed("dc_write_error", error.into());
            }
            Err(error) => {
                if let Some(counters) = &stats.counters {
                    sample_fd_retrans(stats.upstream_fd, &mut prev_retrans, &counters.upstream_retrans_segs);
                }
                return stats.failed("dc_write_idle", error.into());
            }
        }
        if let Some(counters) = &stats.counters {
            counters.upstream_tx_bytes.fetch_add(n as u64, Relaxed);
            sample_fd_retrans(stats.upstream_fd, &mut prev_retrans, &counters.upstream_retrans_segs);
        }
        stats.uploaded.fetch_add(n as u64, Relaxed);
        stats.dc_writes.fetch_add(1, Relaxed);
        stats.timeline.mark("dc_write", n as u64);
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
    let mut buf = [0u8; wire::MAX_RECORD];
    let mut prefix = [0u8; 28];
    let mut prefix_len = 0;
    let mut prev_retrans = 0u32;
    loop {
        let n = match r.read(&mut buf).await {
            Ok(n) => n,
            Err(error) => return stats.failed("dc_read_error", error.into()),
        };
        if n == 0 {
            let _ = stats.first_eof.compare_exchange(0, 2, Relaxed, Relaxed);
            stats.timeline.close("dc_eof", "fin");
            let res = match timeout(write_timeout.min(DC_EOF_SHUTDOWN_TIMEOUT), w.shutdown()).await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) => stats.failed("client_write_error", error.into()),
                Err(error) => stats.failed("client_write_idle", error.into()),
            };
            if let Some(counters) = &stats.counters {
                sample_fd_retrans(stats.client_fd, &mut prev_retrans, &counters.downstream_retrans_segs);
            }
            return res;
        }
        if let Some(counters) = &stats.counters {
            counters.upstream_rx_bytes.fetch_add(n as u64, Relaxed);
        }
        stats.dc_reads.fetch_add(1, Relaxed);
        stats.record_activity();
        stats.timeline.mark("dc_read", n as u64);
        wire::crypt(&mut decrypt, &mut buf[..n]);
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
        wire::crypt(&mut encrypt, &mut buf[..n]);
        let record;
        let bytes = if framed {
            record = wire::record(0x17, &buf[..n])?;
            record.as_slice()
        } else {
            &buf[..n]
        };
        match timeout(write_timeout, w.write_all(bytes)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                if let Some(counters) = &stats.counters {
                    sample_fd_retrans(stats.client_fd, &mut prev_retrans, &counters.downstream_retrans_segs);
                }
                return stats.failed("client_write_error", error.into());
            }
            Err(error) => {
                if let Some(counters) = &stats.counters {
                    sample_fd_retrans(stats.client_fd, &mut prev_retrans, &counters.downstream_retrans_segs);
                }
                return stats.failed("client_write_idle", error.into());
            }
        }
        if let Some(counters) = &stats.counters {
            counters.downstream_tx_bytes.fetch_add(bytes.len() as u64, Relaxed);
            sample_fd_retrans(stats.client_fd, &mut prev_retrans, &counters.downstream_retrans_segs);
        }
        stats.downloaded.fetch_add(n as u64, Relaxed);
        stats.client_writes.fetch_add(1, Relaxed);
        stats.timeline.mark("client_write", n as u64);
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
    let mut buf = [0; wire::MAX_RECORD];
    let mut prev_retrans = 0u32;
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
        sample_fd_retrans(write_fd, &mut prev_retrans, retrans_counter);
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
    let mut upstream = timeout(state.handshake, TcpStream::connect(&state.cover)).await??;
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
        let mut off = 0;
        let mut first = true;
        while off < flight.len() {
            let rem = flight.len() - off;
            let chunk = if rem <= 240 {
                rem
            } else if first {
                first = false;
                rand::rngs::OsRng.gen_range(95..=165).min(rem)
            } else {
                rand::rngs::OsRng.gen_range(260..=880).min(rem)
            };
            client.write_all(&flight[off..off + chunk]).await?;
            client.flush().await?;
            off += chunk;
            if off < flight.len() {
                let delay_us = rand::rngs::OsRng.gen_range(300..=2200);
                tokio::time::sleep(Duration::from_micros(delay_us)).await;
            }
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

async fn probe_egress_endpoint(
    addr: SocketAddr,
    dc_id: i16,
    token: &[u8; 16],
    limit: Duration,
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
    let mut preface = [0u8; 88];
    preface[..4].copy_from_slice(&EGRESS_MAGIC);
    preface[4..6].copy_from_slice(&dc_id.to_le_bytes());
    preface[8..24].copy_from_slice(token);
    preface[24..88].copy_from_slice(&dc.header);
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

async fn connect_upstream(
    state: &State,
    dc_id: i16,
    dc_header: &[u8; 64],
) -> Result<(TcpStream, &'static str)> {
    use std::sync::atomic::Ordering::Relaxed;
    if state.egress_upstreams.is_empty() {
        let address = state.dcs.get(&dc_id.abs()).context("DC not configured")?;
        let mut upstream = timeout(state.handshake, TcpStream::connect(address))
            .await
            .context("dc_connect_timeout")?
            .context("dc_connect_failed")?;
        configure_tcp_socket(&upstream)?;
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
    timeout(state.handshake, async {
        let mut last_err = None;
        for offset in 0..count {
            let idx = (start + offset) % count;
            let claim = if ordered {
                let Some(c) = EgressHealth::try_claim(&state.egress_health, idx, dc_abs, Instant::now()) else {
                    continue;
                };
                Some(c)
            } else {
                None
            };
            let addr = state.egress_upstreams[idx];
            enum AttemptErr {
                Node(anyhow::Error),
                Dc(anyhow::Error),
            }
            let attempt = timeout(per_try, async {
                let mut upstream = TcpStream::connect(addr)
                    .await
                    .map_err(|e| AttemptErr::Node(e.into()))?;
                configure_tcp_socket(&upstream).map_err(AttemptErr::Node)?;
                let mut preface = [0u8; 88];
                preface[..4].copy_from_slice(&EGRESS_MAGIC);
                preface[4..6].copy_from_slice(&dc_id.to_le_bytes());
                preface[8..24].copy_from_slice(&state.egress_token);
                preface[24..88].copy_from_slice(dc_header);
                upstream
                    .write_all(&preface)
                    .await
                    .map_err(|e| AttemptErr::Node(e.into()))?;
                state
                    .counters
                    .upstream_tx_bytes
                    .fetch_add(preface.len() as u64, Relaxed);
                let mut ack = [0u8; 1];
                upstream
                    .read_exact(&mut ack)
                    .await
                    .map_err(|e| AttemptErr::Node(e.into()))?;
                state
                    .counters
                    .upstream_rx_bytes
                    .fetch_add(ack.len() as u64, Relaxed);
                if ack[0] == EGRESS_ACK_OK {
                    Ok(upstream)
                } else if ack[0] == EGRESS_ACK_ERR {
                    Err(AttemptErr::Dc(anyhow::anyhow!(
                        "egress DC {dc_abs} unreachable (negative ACK)"
                    )))
                } else {
                    Err(AttemptErr::Node(anyhow::anyhow!(
                        "egress upstream invalid ACK byte"
                    )))
                }
            })
            .await;
            match attempt {
                Ok(Ok(upstream)) => {
                    if let Some(c) = claim {
                        c.record_success();
                    }
                    return Ok((upstream, "egress"));
                }
                Ok(Err(AttemptErr::Dc(err))) => {
                    if let Some(c) = claim {
                        c.record_dc_failure(state.egress_cooldown);
                    }
                    last_err = Some(err);
                }
                Ok(Err(AttemptErr::Node(err))) => {
                    if let Some(c) = claim {
                        c.record_node_failure(state.egress_cooldown);
                    }
                    last_err = Some(err);
                }
                Err(_) => {
                    if let Some(c) = claim {
                        c.record_node_failure(state.egress_cooldown);
                    }
                    last_err = Some(anyhow::anyhow!("egress_connect_timeout"));
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("all egress upstreams in cooldown or unavailable")))
            .context("egress_connect_failed")
    })
    .await
    .context("egress_budget_timeout")?
}

#[allow(clippy::too_many_arguments)]
async fn serve_egress(
    listener: TcpListener,
    dcs: Arc<HashMap<i16, SocketAddr>>,
    egress_token: [u8; 16],
    max_connections: usize,
    handshake: Duration,
    idle: Duration,
    drain: Duration,
    counters: Arc<telemetry::Counters>,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    let permits = Arc::new(Semaphore::new(max_connections));
    let mut tasks = tokio::task::JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        while tasks.try_join_next().is_some() {}
        let permit = tokio::select! {
            permit = permits.clone().acquire_owned() => permit?,
            _ = &mut shutdown => break,
        };
        let (mut edge, _) = tokio::select! {
            accepted = listener.accept() => accepted?,
            _ = &mut shutdown => break,
        };
        let dcs = dcs.clone();
        let counters = counters.clone();
        tasks.spawn(async move {
            let _permit = permit;
            let mut session = telemetry::Session::new(&counters);
            let res = egress_connection(&mut edge, &dcs, &egress_token, handshake, idle, &counters).await;
            session.finish(&res);
        });
    }
    drop(listener);
    if timeout(drain, async {
        while tasks.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        tasks.shutdown().await;
    }
    Ok(())
}

async fn egress_connection(
    edge: &mut TcpStream,
    dcs: &HashMap<i16, SocketAddr>,
    expected_token: &[u8; 16],
    handshake: Duration,
    idle: Duration,
    counters: &telemetry::Counters,
) -> Result<()> {
    use std::sync::atomic::Ordering::Relaxed;
    configure_tcp_socket(edge)?;
    let mut hdr = [0u8; 24];
    timeout(handshake, edge.read_exact(&mut hdr))
        .await
        .context("egress_header_timeout")?
        .context("egress_header_eof")?;
    counters
        .downstream_rx_bytes
        .fetch_add(hdr.len() as u64, Relaxed);
    ensure!(hdr[..4] == EGRESS_MAGIC, "invalid egress magic");
    let token: [u8; 16] = hdr[8..24].try_into()?;
    ensure!(ct_eq_16(&token, expected_token), "egress token mismatch");
    let dc_id = i16::from_le_bytes([hdr[4], hdr[5]]).abs();
    let Some(addr) = dcs.get(&dc_id) else {
        if edge.write_all(&[EGRESS_ACK_ERR]).await.is_ok() {
            counters.downstream_tx_bytes.fetch_add(1, Relaxed);
        }
        let _ = edge.shutdown().await;
        bail!("DC not configured on egress");
    };
    let mut dc = match timeout(handshake, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => stream,
        _ => {
            if edge.write_all(&[EGRESS_ACK_ERR]).await.is_ok() {
                counters.downstream_tx_bytes.fetch_add(1, Relaxed);
            }
            let _ = edge.shutdown().await;
            bail!("dc_connect_failed");
        }
    };
    configure_tcp_socket(&dc)?;
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
