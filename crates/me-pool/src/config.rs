use anyhow::{bail, ensure, Context, Result};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};

/// Parsed Telegram `proxy-multi.conf` mapping DC IDs (including negative media DCs)
/// to their Middle-End IPv4 endpoints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyMultiConfig {
    pub default_dc: Option<i16>,
    pub dcs: HashMap<i16, Vec<SocketAddrV4>>,
}

impl ProxyMultiConfig {
    /// Parse `proxy-multi.conf` text (`proxy_for <dc> <ip>:<port>;` and `default <dc>;`).
    pub fn parse(text: &str) -> Result<Self> {
        let mut default_dc = None;
        let mut dcs: HashMap<i16, Vec<SocketAddrV4>> = HashMap::new();

        for raw_line in text.lines() {
            let line = raw_line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let stmt = line.trim_end_matches(';').trim();
            let parts: Vec<&str> = stmt.split_whitespace().collect();
            match parts.as_slice() {
                ["default", dc_str] => {
                    if let Ok(dc) = dc_str.parse::<i16>() {
                        if dc != 0 {
                            default_dc = Some(dc);
                        }
                    }
                }
                ["proxy_for", dc_str, addr_str] => {
                    let Ok(dc) = dc_str.parse::<i16>() else {
                        continue;
                    };
                    if dc == 0 {
                        continue;
                    }
                    let Ok(addr) = addr_str.parse::<SocketAddrV4>() else {
                        continue;
                    };
                    if addr.ip().is_unspecified() || addr.port() == 0 {
                        continue;
                    }
                    let list = dcs.entry(dc).or_default();
                    if !list.contains(&addr) {
                        list.push(addr);
                    }
                }
                _ => {
                    // Ignore unknown/IPv6/timeout directives without failing the whole config.
                }
            }
        }

        ensure!(
            !dcs.is_empty(),
            "proxy-multi.conf contains no valid IPv4 proxy_for entries"
        );
        Ok(Self { default_dc, dcs })
    }

    pub fn endpoints_for(&self, dc_id: i16) -> &[SocketAddrV4] {
        if let Some(list) = self.dcs.get(&dc_id) {
            return list.as_slice();
        }
        let abs = dc_id.abs();
        if let Some(list) = self.dcs.get(&abs) {
            return list.as_slice();
        }
        if let Some(def) = self.default_dc {
            if let Some(list) = self.dcs.get(&def) {
                return list.as_slice();
            }
        }
        &[]
    }
}

/// Validated ME bundle (`proxy-secret` bytes + parsed `proxy-multi.conf`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeConfigBundle {
    pub proxy_secret: Vec<u8>,
    pub proxy_conf: ProxyMultiConfig,
}

impl MeConfigBundle {
    pub fn from_raw(proxy_secret: Vec<u8>, proxy_conf_text: &str) -> Result<Self> {
        ensure!(
            proxy_secret.len() >= 16 && proxy_secret.len() <= 4096,
            "proxy-secret length {} out of bounds (16..=4096)",
            proxy_secret.len()
        );
        let proxy_conf = ProxyMultiConfig::parse(proxy_conf_text)?;
        Ok(Self {
            proxy_secret,
            proxy_conf,
        })
    }

    pub fn key_selector(&self) -> Result<[u8; 4]> {
        let Some(slice) = self.proxy_secret.get(..4) else {
            bail!("proxy-secret shorter than 4 bytes");
        };
        let mut out = [0u8; 4];
        out.copy_from_slice(slice);
        Ok(out)
    }
}

/// Atomic last-known-good disk cache for `proxy-secret` and `proxy-multi.conf`.
#[derive(Clone, Debug)]
pub struct MeDiskCache {
    dir: PathBuf,
}

impl MeDiskCache {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn secret_path(&self) -> PathBuf {
        self.dir.join("proxy-secret")
    }

    pub fn conf_path(&self) -> PathBuf {
        self.dir.join("proxy-multi.conf")
    }

    /// Validate first, then atomically replace cached files. Corrupted input never overwrites LKG.
    pub fn save_validated(
        &self,
        proxy_secret: &[u8],
        proxy_conf_text: &str,
    ) -> Result<MeConfigBundle> {
        let bundle = MeConfigBundle::from_raw(proxy_secret.to_vec(), proxy_conf_text)?;
        std::fs::create_dir_all(&self.dir)
            .with_context(|| format!("creating ME cache dir {}", self.dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700));
        }
        atomic_write(&self.secret_path(), proxy_secret)?;
        atomic_write(&self.conf_path(), proxy_conf_text.as_bytes())?;
        Ok(bundle)
    }

    pub fn load(&self) -> Result<MeConfigBundle> {
        let secret = std::fs::read(self.secret_path()).context("reading cached proxy-secret")?;
        let conf_text =
            std::fs::read_to_string(self.conf_path()).context("reading cached proxy-multi.conf")?;
        MeConfigBundle::from_raw(secret, &conf_text)
    }
}

fn atomic_write(dest: &Path, bytes: &[u8]) -> Result<()> {
    let parent = dest.parent().unwrap_or_else(|| Path::new("."));
    let file_name = dest
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("me-cache");
    let tmp = parent.join(format!(".{file_name}.tmp.{}", std::process::id()));
    std::fs::write(&tmp, bytes).with_context(|| format!("writing {}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, dest)
        .with_context(|| format!("renaming {} to {}", tmp.display(), dest.display()))?;
    Ok(())
}

/// Validate and parse a 32-hex-character `ad_tag` (16 bytes).
pub fn parse_ad_tag_hex(raw: &str) -> Result<[u8; 16]> {
    let trimmed = raw.trim();
    ensure!(
        trimmed.len() == 32,
        "ad_tag must be exactly 32 hex characters (got {})",
        trimmed.len()
    );
    let mut out = [0u8; 16];
    let (pairs, _) = trimmed.as_bytes().as_chunks::<2>();
    for (i, chunk) in pairs.iter().enumerate() {
        let hi = hex_nibble(chunk[0]).context("invalid hex in ad_tag")?;
        let lo = hex_nibble(chunk[1]).context("invalid hex in ad_tag")?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => bail!("non-hex byte"),
    }
}

/// Check whether an IPv4 address is globally routable (not loopback/private/link-local/unspecified).
pub fn is_global_ipv4(ip: Ipv4Addr) -> bool {
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast())
}
