use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpCidr {
    V4 { net: u32, mask: u32 },
    V6 { net: u128, mask: u128 },
}

impl IpCidr {
    pub fn parse(text: &str) -> Result<Self> {
        let trimmed = text.trim();
        let (ip_str, prefix_opt) = match trimmed.split_once('/') {
            Some((ip_part, p_part)) => (ip_part, Some(p_part)),
            None => (trimmed, None),
        };
        let ip: IpAddr = ip_str
            .parse()
            .with_context(|| format!("invalid CIDR IP '{ip_str}'"))?;
        match ip {
            IpAddr::V4(v4) => {
                let prefix: u8 = match prefix_opt {
                    Some(p) => p.parse().context("invalid IPv4 CIDR prefix")?,
                    None => 32,
                };
                ensure!(prefix <= 32, "IPv4 CIDR prefix must be 0..=32");
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                let net = u32::from_be_bytes(v4.octets()) & mask;
                Ok(Self::V4 { net, mask })
            }
            IpAddr::V6(v6) => {
                let prefix: u8 = match prefix_opt {
                    Some(p) => p.parse().context("invalid IPv6 CIDR prefix")?,
                    None => 128,
                };
                ensure!(prefix <= 128, "IPv6 CIDR prefix must be 0..=128");
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                let net = u128::from_be_bytes(v6.octets()) & mask;
                Ok(Self::V6 { net, mask })
            }
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let canonical = match ip {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(v6),
            },
            v4 => v4,
        };
        match (*self, canonical) {
            (Self::V4 { net, mask }, IpAddr::V4(v4)) => {
                (u32::from_be_bytes(v4.octets()) & mask) == net
            }
            (Self::V6 { net, mask }, IpAddr::V6(v6)) => {
                (u128::from_be_bytes(v6.octets()) & mask) == net
            }
            _ => false,
        }
    }
}

pub fn is_loopback_or_private_ip(ip: IpAddr) -> bool {
    let canonical = match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    };
    match canonical {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            let is_cgnat = octets[0] == 100 && (64..=127).contains(&octets[1]);
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || is_cgnat
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local(),
    }
}

#[derive(Deserialize, clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    #[default]
    Direct,
    Edge,
    Egress,
}

#[derive(Deserialize, clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum EgressStrategy {
    #[default]
    RoundRobin,
    Ordered,
}

pub struct NamedSecret {
    pub name: String,
    pub key: Zeroizing<[u8; 16]>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub role: Role,
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    #[serde(default)]
    pub secret_file: Option<PathBuf>,
    #[serde(default)]
    pub users_file: Option<PathBuf>,
    #[serde(default)]
    pub replay_file: Option<PathBuf>,
    #[serde(default)]
    pub sni: String,
    #[serde(default)]
    pub cover: String,
    #[serde(default)]
    pub enable_dd: bool,
    #[serde(default)]
    pub proxy_protocol: bool,
    #[serde(default)]
    pub dc: Vec<String>,
    #[serde(default)]
    pub egress_upstreams: Vec<SocketAddr>,
    #[serde(default)]
    pub egress_strategy: EgressStrategy,
    #[serde(default)]
    pub egress_token_file: Option<PathBuf>,
    #[serde(default = "default_connections")]
    pub max_connections: usize,
    #[serde(default = "default_client_hello")]
    pub client_hello_timeout_secs: u64,
    #[serde(default = "default_handshake")]
    pub handshake_timeout_secs: u64,
    #[serde(default = "default_idle")]
    pub idle_timeout_secs: u64,
    #[serde(default = "default_drain")]
    pub drain_timeout_secs: u64,
    /// Size of the fake TLS certificate record in the ServerHello flight.
    /// ADR-000 §5.2: the size comes from the measured profile, not a constant.
    #[serde(default = "default_fake_tls_cert_bytes")]
    pub fake_tls_cert_bytes: usize,
    /// Symmetric spread applied to the certificate size.
    #[serde(default = "default_fake_tls_cert_jitter")]
    pub fake_tls_cert_jitter: usize,
    /// Unevenly fragment the outgoing ServerHello flight with small jittered delays.
    #[serde(default)]
    pub flight_shaping: bool,
    /// Optional client-facing TCP MSS (TCP_MAXSEG) applied on the listener before listen(2).
    /// Linux only; e.g. 92 for TSPU handshake fragmentation.
    #[serde(default)]
    pub client_mss: Option<u16>,
    /// Optional bulk-phase TCP MSS applied on the client socket after ServerHello completes.
    #[serde(default)]
    pub client_mss_bulk: Option<u16>,
    /// Optional webhook URL on edge to receive one alert per egress state transition
    /// (primary_ok, failover_backup, all_down).
    #[serde(default)]
    pub alert_webhook_url: Option<String>,
    /// Base cooldown in milliseconds for an egress upstream or DC after a failure.
    #[serde(default = "default_egress_cooldown_base_ms")]
    pub egress_cooldown_base_ms: u64,
    /// Maximum exponential backoff cooldown in milliseconds for an egress upstream or DC.
    #[serde(default = "default_egress_cooldown_max_ms")]
    pub egress_cooldown_max_ms: u64,
    /// Background egress probe interval in seconds when all egress nodes are healthy.
    #[serde(default = "default_egress_probe_interval_secs")]
    pub egress_probe_interval_secs: u64,
    /// Background egress probe interval in seconds while at least one egress node is unavailable.
    #[serde(default = "default_egress_probe_degraded_interval_secs")]
    pub egress_probe_degraded_interval_secs: u64,
    /// Hedged connect delay in milliseconds for ordered egress strategy (0 = disabled).
    #[serde(default = "default_egress_hedge_ms")]
    pub egress_hedge_ms: u64,
    /// Whether egress accepts legacy MTV2 prefaces alongside MTV3.
    #[serde(default = "default_egress_accept_legacy")]
    pub egress_accept_legacy: bool,
    /// Whether edge uses MTV3 (HMAC-SHA256 + timestamp + nonce) when dialing egress.
    #[serde(default = "default_egress_use_mtv3")]
    pub egress_use_mtv3: bool,
    /// Optional CIDR source allowlist on egress (empty = allow any source IP).
    #[serde(default)]
    pub egress_allow_from: Vec<String>,
    /// Maximum failed authentication attempts per source IP within a 60s sliding window on egress.
    #[serde(default = "default_egress_max_failed_per_ip")]
    pub egress_max_failed_per_ip: usize,
    /// Configurable media/alternate DC candidate overrides (`ID=IP:PORT`, multiple entries per ID allowed).
    #[serde(default = "default_dc_media_override")]
    pub dc_media_override: Vec<String>,
    /// Background DC self-check interval in seconds on direct/egress (0 = disabled).
    #[serde(default = "default_dc_probe_interval_secs")]
    pub dc_probe_interval_secs: u64,
    /// Background cover DNS cache TTL / refresh interval in seconds (INV-04).
    #[serde(default = "default_cover_dns_ttl_secs")]
    pub cover_dns_ttl_secs: u64,
}
fn default_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 24443))
}
fn default_connections() -> usize {
    128
}
fn default_client_hello() -> u64 {
    5
}
fn default_handshake() -> u64 {
    10
}
fn default_idle() -> u64 {
    300
}
fn default_drain() -> u64 {
    5
}
fn default_fake_tls_cert_bytes() -> usize {
    mtevil_proto::DEFAULT_CERT_BYTES
}
fn default_fake_tls_cert_jitter() -> usize {
    0
}
pub fn default_egress_cooldown_base_ms() -> u64 {
    3_000
}
pub fn default_egress_cooldown_max_ms() -> u64 {
    60_000
}
pub fn default_egress_probe_interval_secs() -> u64 {
    30
}
pub fn default_egress_probe_degraded_interval_secs() -> u64 {
    5
}
pub fn default_egress_hedge_ms() -> u64 {
    400
}
pub fn default_egress_accept_legacy() -> bool {
    true
}
pub fn default_egress_use_mtv3() -> bool {
    true
}
pub fn default_egress_max_failed_per_ip() -> usize {
    16
}
pub fn default_dc_media_override() -> Vec<String> {
    vec![
        "2=149.154.167.220:443".to_string(),
        "-2=149.154.167.151:443".to_string(),
        "-2=149.154.167.220:443".to_string(),
        "4=149.154.167.92:443".to_string(),
        "-4=149.154.166.120:443".to_string(),
        "-4=149.154.167.92:443".to_string(),
    ]
}
pub fn default_dc_probe_interval_secs() -> u64 {
    60
}
pub fn default_cover_dns_ttl_secs() -> u64 {
    60
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let meta = std::fs::metadata(path).context("config file")?;
        ensure!(meta.len() <= 65536, "config exceeds 64 KiB");
        let bytes = std::fs::read(path).context("config file")?;
        let mut config: Self = serde_json::from_slice(&bytes).context("invalid configuration")?;
        let base = path.parent().unwrap_or(Path::new("."));
        for p in [
            &mut config.secret_file,
            &mut config.users_file,
            &mut config.replay_file,
            &mut config.egress_token_file,
        ]
        .into_iter()
        .flatten()
        {
            if p.is_relative() {
                *p = base.join(&*p);
            }
        }
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=4096).contains(&self.max_connections),
            "max-connections must be 1..4096"
        );
        ensure!(
            (1..=60).contains(&self.client_hello_timeout_secs),
            "client-hello timeout must be 1..60 seconds"
        );
        ensure!(
            (1..=120).contains(&self.handshake_timeout_secs),
            "handshake timeout must be 1..120 seconds"
        );
        ensure!(
            (1..=86400).contains(&self.idle_timeout_secs),
            "idle timeout must be 1..86400 seconds"
        );
        ensure!(
            (1..=300).contains(&self.drain_timeout_secs),
            "drain timeout must be 1..300 seconds"
        );
        ensure!(
            (50..=300_000).contains(&self.egress_cooldown_base_ms),
            "egress_cooldown_base_ms must be 50..=300000"
        );
        ensure!(
            (50..=600_000).contains(&self.egress_cooldown_max_ms)
                && self.egress_cooldown_max_ms >= self.egress_cooldown_base_ms,
            "egress_cooldown_max_ms must be >= egress_cooldown_base_ms and <= 600000"
        );
        ensure!(
            (1..=3600).contains(&self.egress_probe_interval_secs),
            "egress_probe_interval_secs must be 1..=3600"
        );
        ensure!(
            (1..=3600).contains(&self.egress_probe_degraded_interval_secs)
                && self.egress_probe_degraded_interval_secs <= self.egress_probe_interval_secs,
            "egress_probe_degraded_interval_secs must be 1..=egress_probe_interval_secs"
        );
        ensure!(
            self.egress_hedge_ms <= 30_000,
            "egress_hedge_ms must be 0..=30000"
        );
        ensure!(
            (1..=4096).contains(&self.egress_max_failed_per_ip),
            "egress_max_failed_per_ip must be 1..=4096"
        );
        ensure!(
            self.dc_probe_interval_secs <= 86400,
            "dc_probe_interval_secs must be 0..=86400"
        );
        ensure!(
            (1..=86400).contains(&self.cover_dns_ttl_secs),
            "cover_dns_ttl_secs must be 1..=86400"
        );
        self.parsed_egress_allow_from()?;
        self.dc_media_overrides()?;
        mtevil_proto::ServerFlightProfile {
            cert_bytes: self.fake_tls_cert_bytes,
            jitter: self.fake_tls_cert_jitter,
        }
        .validate()
        .context("fake TLS profile")?;
        if let Some(mss) = self.client_mss {
            ensure!((88..=1460).contains(&mss), "client_mss must be 88..=1460");
        }
        if let Some(mss) = self.client_mss_bulk {
            ensure!(
                (88..=1460).contains(&mss),
                "client_mss_bulk must be 88..=1460"
            );
        }
        if self.role == Role::Egress {
            ensure!(!self.dc.is_empty(), "egress role requires at least one DC");
            self.datacenters()?;
            return Ok(());
        }
        ensure!(
            self.secret_file.is_some() || self.users_file.is_some(),
            "secret_file or users_file is required"
        );
        if self.role == Role::Edge {
            ensure!(
                !self.egress_upstreams.is_empty(),
                "edge role requires at least one egress_upstream"
            );
            for addr in &self.egress_upstreams {
                ensure!(addr.port() > 0, "egress_upstream port must not be zero");
            }
        } else {
            self.datacenters()?;
        }
        ensure!(is_valid_sni_hostname(&self.sni), "invalid SNI hostname");
        let (host, port) = self
            .cover
            .rsplit_once(':')
            .context("cover must be host:port")?;
        ensure!(
            !host.is_empty()
                && !host.contains(['/', ' ', '\n', '\r'])
                && port.parse::<u16>().is_ok_and(|p| p > 0),
            "invalid cover host:port"
        );
        Ok(())
    }
    pub fn datacenters(&self) -> Result<HashMap<i16, SocketAddr>> {
        ensure!(!self.dc.is_empty(), "at least one DC is required");
        let mut dcs = HashMap::new();
        for entry in &self.dc {
            let (id, address) = entry.split_once('=').context("DC must be ID=IP:PORT")?;
            let id: i16 = id.parse().context("invalid DC id")?;
            ensure!(
                (-5..=-1).contains(&id) || (1..=5).contains(&id),
                "DC id must be 1..5 or -5..-1"
            );
            let address: SocketAddr = address.parse().context("invalid DC address")?;
            ensure!(address.port() > 0, "DC port must not be zero");
            ensure!(dcs.insert(id, address).is_none(), "duplicate DC id");
        }
        Ok(dcs)
    }
    pub fn dc_media_overrides(&self) -> Result<HashMap<i16, Vec<SocketAddr>>> {
        let mut out: HashMap<i16, Vec<SocketAddr>> = HashMap::new();
        for entry in &self.dc_media_override {
            let (id, address) = entry
                .split_once('=')
                .context("dc_media_override must be ID=IP:PORT")?;
            let id: i16 = id.parse().context("invalid dc_media_override DC id")?;
            ensure!(
                (-5..=-1).contains(&id) || (1..=5).contains(&id),
                "dc_media_override DC id must be 1..5 or -5..-1"
            );
            let address: SocketAddr = address
                .parse()
                .context("invalid dc_media_override address")?;
            ensure!(
                address.port() > 0,
                "dc_media_override port must not be zero"
            );
            let list = out.entry(id).or_default();
            if !list.contains(&address) {
                list.push(address);
            }
        }
        Ok(out)
    }
    pub fn load_secrets_allow_empty(&self) -> Result<Vec<NamedSecret>> {
        let mut out = Vec::new();
        if let Some(path) = &self.secret_file {
            out.push(NamedSecret {
                name: "default".to_string(),
                key: decode_secret_file(path)?,
            });
        }
        if let Some(path) = &self.users_file {
            if path.exists() || self.secret_file.is_none() {
                let meta = std::fs::metadata(path).context("users file")?;
                ensure!(meta.len() <= 262_144, "users file exceeds 256 KiB");
                let text = Zeroizing::new(std::fs::read_to_string(path).context("users file")?);
                let map: HashMap<String, String> =
                    serde_json::from_str(&text).context("invalid users file JSON")?;
                let mut names: Vec<_> = map.keys().cloned().collect();
                names.sort();
                for name in names {
                    ensure!(
                        !name.is_empty()
                            && name.len() <= 32
                            && name
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
                        "invalid user name"
                    );
                    let mut key = Zeroizing::new([0u8; 16]);
                    hex::decode_to_slice(map[&name].trim(), &mut key[..])
                        .with_context(|| format!("invalid 32-hex secret for user {name}"))?;
                    ensure!(
                        !out.iter().any(|existing| *existing.key == *key),
                        "duplicate secret in users_file"
                    );
                    out.push(NamedSecret { name, key });
                }
            }
        }
        Ok(out)
    }

    pub fn secrets(&self) -> Result<Vec<NamedSecret>> {
        let out = self.load_secrets_allow_empty()?;
        ensure!(!out.is_empty(), "at least one secret is required");
        Ok(out)
    }

    pub fn egress_token(&self) -> Result<[u8; 16]> {
        match &self.egress_token_file {
            Some(path) => Ok(*decode_secret_file(path)?),
            None => Ok([0u8; 16]),
        }
    }

    pub fn parsed_egress_allow_from(&self) -> Result<Vec<IpCidr>> {
        let mut cidrs = Vec::with_capacity(self.egress_allow_from.len());
        for raw in &self.egress_allow_from {
            cidrs.push(IpCidr::parse(raw)?);
        }
        Ok(cidrs)
    }

    pub fn allowed_sni_file(&self) -> Option<PathBuf> {
        self.secret_file
            .as_ref()
            .or(self.users_file.as_ref())
            .or(self.replay_file.as_ref())
            .and_then(|p| p.parent().map(|dir| dir.join("allowed-sni.txt")))
    }

    pub fn allowed_snis(&self) -> String {
        let mut list = vec![self.sni.trim().to_ascii_lowercase()];
        if let Some(path) = self.allowed_sni_file() {
            if let Ok(text) = std::fs::read_to_string(&path) {
                for token in text.split(['\n', '\r', ',']) {
                    let s = token.trim().to_ascii_lowercase();
                    if is_valid_sni_hostname(&s) && !list.contains(&s) {
                        list.push(s);
                    }
                }
            }
        }
        list.join(",")
    }
}

pub fn is_valid_sni_hostname(sni: &str) -> bool {
    !sni.is_empty()
        && sni.len() <= 253
        && sni.is_ascii()
        && sni.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn decode_secret_file(path: &Path) -> Result<Zeroizing<[u8; 16]>> {
    ensure!(
        std::fs::metadata(path).context("secret file")?.len() <= 128,
        "secret file too large"
    );
    let text = Zeroizing::new(std::fs::read_to_string(path).context("secret file")?);
    let mut secret = Zeroizing::new([0; 16]);
    hex::decode_to_slice(text.trim(), &mut secret[..])
        .context("secret must contain exactly 32 hex characters")?;
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> Result<Config> {
        Ok(serde_json::from_str(
            r#"{"secret_file":"secret","sni":"example.com","cover":"example.com:443","dc":["2=149.154.167.51:443"]}"#,
        )?)
    }
    #[test]
    fn defaults_are_bounded_and_unknown_settings_fail() -> Result<()> {
        let c = config()?;
        c.validate()?;
        assert_eq!(c.listen, SocketAddr::from(([127, 0, 0, 1], 24443)));
        assert_eq!(c.max_connections, 128);
        assert!(!c.enable_dd);
        assert_eq!(c.fake_tls_cert_bytes, mtevil_proto::DEFAULT_CERT_BYTES);
        assert_eq!(c.fake_tls_cert_jitter, 0);
        assert_eq!(c.egress_cooldown_base_ms, 3_000);
        assert_eq!(c.egress_cooldown_max_ms, 60_000);
        assert_eq!(c.egress_probe_interval_secs, 30);
        assert_eq!(c.egress_probe_degraded_interval_secs, 5);
        assert_eq!(c.egress_hedge_ms, 400);
        assert!(c.egress_accept_legacy);
        assert!(c.egress_use_mtv3);
        assert!(c.egress_allow_from.is_empty());
        assert_eq!(c.egress_max_failed_per_ip, 16);
        assert_eq!(c.dc_media_override.len(), 6);
        assert_eq!(c.dc_probe_interval_secs, 60);
        assert_eq!(c.cover_dns_ttl_secs, 60);
        assert!(serde_json::from_str::<Config>(r#"{"secret_file":"secret","sni":"example.com","cover":"example.com:443","dc":[],"max_conections":100}"#).is_err());
        Ok(())
    }

    #[test]
    fn fake_tls_profile_is_configurable_and_bounded() -> Result<()> {
        let mut c = config()?;
        c.fake_tls_cert_bytes = 4096;
        c.fake_tls_cert_jitter = 128;
        c.validate()?;
        assert_eq!(c.fake_tls_cert_bytes, 4096);

        let mut c = config()?;
        c.fake_tls_cert_bytes = 512;
        c.validate()?;
        c.fake_tls_cert_bytes = 511;
        assert!(c.validate().is_err());
        let mut c = config()?;
        c.fake_tls_cert_bytes = mtevil_proto::MAX_CERT_BYTES + 1;
        assert!(c.validate().is_err());
        let mut c = config()?;
        c.fake_tls_cert_jitter = 4096;
        assert!(c.validate().is_err());
        Ok(())
    }
    #[test]
    fn malformed_limits_hosts_and_duplicate_dcs_are_rejected() -> Result<()> {
        let mut c = config()?;
        c.max_connections = 0;
        assert!(c.validate().is_err());
        let mut c = config()?;
        c.idle_timeout_secs = 0;
        assert!(c.validate().is_err());
        let mut c = config()?;
        c.sni = "https://example.com".into();
        assert!(c.validate().is_err());
        let mut c = config()?;
        c.cover = "example.com:0".into();
        assert!(c.validate().is_err());
        let mut c = config()?;
        c.dc.push("-2=149.154.167.151:443".into());
        c.validate()?;
        let dcs = c.datacenters()?;
        assert_eq!(dcs.get(&-2).copied(), Some("149.154.167.151:443".parse()?));
        let mut c_zero = config()?;
        c_zero.dc.push("0=149.154.167.51:443".into());
        assert!(c_zero.validate().is_err());
        let mut c = config()?;
        c.dc.push(c.dc[0].clone());
        assert!(c.validate().is_err());
        let mut c = config()?;
        c.client_mss = Some(92);
        c.client_mss_bulk = Some(1400);
        c.validate()?;
        c.client_mss = Some(87);
        assert!(c.validate().is_err());
        let mut c = config()?;
        c.client_mss_bulk = Some(1461);
        assert!(c.validate().is_err());
        let mut c = config()?;
        c.egress_cooldown_base_ms = 5_000;
        c.egress_cooldown_max_ms = 3_000;
        assert!(c.validate().is_err());
        let mut c = config()?;
        c.egress_cooldown_base_ms = 10;
        assert!(c.validate().is_err());
        let mut c = config()?;
        c.egress_probe_interval_secs = 10;
        c.egress_probe_degraded_interval_secs = 20;
        assert!(c.validate().is_err());
        let mut c = config()?;
        c.egress_hedge_ms = 30_001;
        assert!(c.validate().is_err());
        let mut c = config()?;
        c.egress_max_failed_per_ip = 0;
        assert!(c.validate().is_err());
        let mut c = config()?;
        c.egress_allow_from = vec!["10.203.0.0/24".into(), "2001:db8::/32".into()];
        c.validate()?;
        let cidrs = c.parsed_egress_allow_from()?;
        assert!(cidrs[0].contains("10.203.0.42".parse()?));
        assert!(!cidrs[0].contains("10.203.1.1".parse()?));
        assert!(cidrs[1].contains("2001:db8::1".parse()?));
        let mut c = config()?;
        c.egress_allow_from = vec!["10.203.0.0/33".into()];
        assert!(c.validate().is_err());
        let mut c = config()?;
        c.dc_media_override = vec!["0=149.154.167.151:443".into()];
        assert!(c.validate().is_err());
        let mut c = config()?;
        c.dc_probe_interval_secs = 86_401;
        assert!(c.validate().is_err());
        let mut c = config()?;
        c.cover_dns_ttl_secs = 0;
        assert!(c.validate().is_err());

        let edge: Config = serde_json::from_str(
            r#"{"role":"edge","users_file":"users.json","sni":"example.com","cover":"127.0.0.1:8443","egress_upstreams":["10.203.0.9:29443"],"flight_shaping":true}"#,
        )?;
        edge.validate()?;
        assert_eq!(edge.egress_strategy, EgressStrategy::RoundRobin);
        let ordered_edge: Config = serde_json::from_str(
            r#"{"role":"edge","users_file":"users.json","sni":"example.com","cover":"127.0.0.1:8443","egress_upstreams":["10.203.0.9:29443"],"egress_strategy":"ordered"}"#,
        )?;
        ordered_edge.validate()?;
        assert_eq!(ordered_edge.egress_strategy, EgressStrategy::Ordered);
        let egress: Config = serde_json::from_str(
            r#"{"role":"egress","listen":"10.203.0.9:29443","dc":["2=149.154.167.51:443"]}"#,
        )?;
        egress.validate()?;
        Ok(())
    }
}
