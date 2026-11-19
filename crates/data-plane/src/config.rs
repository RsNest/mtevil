use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use std::{
    collections::HashMap,
    net::SocketAddr,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

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

#[derive(Deserialize)]
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
            ensure!(
                !self.dc.is_empty(),
                "egress role requires at least one DC"
            );
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
        ensure!(
            !self.sni.is_empty()
                && self.sni.len() <= 253
                && self.sni.is_ascii()
                && self.sni.split('.').all(|label| !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')),
            "invalid SNI hostname"
        );
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
            ensure!((1..=5).contains(&id), "DC id must be 1..5");
            let address: SocketAddr = address.parse().context("invalid DC address")?;
            ensure!(address.port() > 0, "DC port must not be zero");
            ensure!(dcs.insert(id, address).is_none(), "duplicate DC id");
        }
        Ok(dcs)
    }
    pub fn secrets(&self) -> Result<Vec<NamedSecret>> {
        let mut out = Vec::new();
        if let Some(path) = &self.secret_file {
            out.push(NamedSecret {
                name: "default".to_string(),
                key: decode_secret_file(path)?,
            });
        }
        if let Some(path) = &self.users_file {
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
        ensure!(!out.is_empty(), "at least one secret is required");
        Ok(out)
    }

    pub fn egress_token(&self) -> Result<[u8; 16]> {
        match &self.egress_token_file {
            Some(path) => Ok(*decode_secret_file(path)?),
            None => Ok([0u8; 16]),
        }
    }
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
