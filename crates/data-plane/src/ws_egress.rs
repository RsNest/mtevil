//! Native `ws://` / `wss://` egress transport (RFC 6455 Binary WebSocket) and
//! per-session warm connection pool (`ADR-005`).
//!
//! Each client session acquires its own dedicated TCP+TLS+WebSocket stream from
//! the warm pool so cross-border packet loss never causes TCP-over-TCP
//! head-of-line blocking across independent users.

use super::*;
use rand::RngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    collections::VecDeque,
    fmt,
    io::ErrorKind,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    str::FromStr,
    task::{Context as TaskContext, Poll},
};
use tokio::io::ReadBuf;

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_HTTP_HEADER_BYTES: usize = 8 * 1024;
/// Upper bound on a single inbound WebSocket frame payload (64 KiB).
pub(crate) const MAX_WS_FRAME_PAYLOAD: usize = 64 * 1024;
/// Outbound chunk size per binary WebSocket frame (matches `wire::MAX_RECORD`).
const MAX_WS_WRITE_CHUNK: usize = 16 * 1024;
/// Maximum idle lifetime of a pre-warmed WebSocket connection in the pool.
const WARM_CONN_MAX_IDLE: Duration = Duration::from_secs(45);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WsEndpoint {
    pub tls: bool,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub connect_override: Option<SocketAddr>,
}

impl WsEndpoint {
    pub fn bracketed_host(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        }
    }

    pub fn host_header(&self) -> String {
        let default_port = if self.tls { 443 } else { 80 };
        let bh = self.bracketed_host();
        if self.port == default_port {
            bh
        } else {
            format!("{bh}:{}", self.port)
        }
    }

    pub fn dial_target(&self) -> String {
        match self.connect_override {
            Some(sa) => sa.to_string(),
            None => format!("{}:{}", self.bracketed_host(), self.port),
        }
    }

    pub fn redacted_label(&self) -> String {
        let scheme = if self.tls { "wss" } else { "ws" };
        format!("{scheme}://{}:{}/***", self.bracketed_host(), self.port)
    }
}

impl fmt::Display for WsEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scheme = if self.tls { "wss" } else { "ws" };
        let default_port = if self.tls { 443 } else { 80 };
        let bh = self.bracketed_host();
        if self.port == default_port {
            write!(f, "{scheme}://{bh}{}", self.path)?;
        } else {
            write!(f, "{scheme}://{bh}:{}{}", self.port, self.path)?;
        }
        if let Some(ov) = self.connect_override {
            write!(f, "?connect={ov}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum EgressEndpoint {
    Tcp(SocketAddr),
    Ws(WsEndpoint),
}

impl EgressEndpoint {
    pub fn port(&self) -> u16 {
        match self {
            Self::Tcp(sa) => sa.port(),
            Self::Ws(ws) => ws.port,
        }
    }

    pub fn is_ws(&self) -> bool {
        matches!(self, Self::Ws(_))
    }

    /// Safe label for logs, metrics, `check-egress`, and alerts (redacts secret WS path).
    pub fn redacted_label(&self) -> String {
        match self {
            Self::Tcp(sa) => sa.to_string(),
            Self::Ws(ws) => ws.redacted_label(),
        }
    }
}

impl From<SocketAddr> for EgressEndpoint {
    fn from(value: SocketAddr) -> Self {
        Self::Tcp(value)
    }
}

impl fmt::Display for EgressEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp(sa) => sa.fmt(f),
            Self::Ws(ws) => ws.fmt(f),
        }
    }
}

pub fn validate_egress_ws_path(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    ensure!(
        trimmed.starts_with('/'),
        "egress WebSocket path must start with '/'"
    );
    ensure!(
        trimmed.len() >= 2 && trimmed.len() <= 256,
        "egress WebSocket path length must be 2..=256 bytes (bare '/' is not allowed)"
    );
    ensure!(
        trimmed
            .bytes()
            .all(|b| b.is_ascii_graphic() && !b"?#\"'\\<>".contains(&b)),
        "egress WebSocket path contains invalid characters"
    );
    Ok(trimmed.to_string())
}

fn parse_ws_authority(authority: &str, default_port: u16) -> Result<(String, u16)> {
    ensure!(!authority.is_empty(), "empty host in WebSocket egress URL");
    ensure!(
        !authority.contains('@'),
        "userinfo is not supported in WebSocket egress URL"
    );
    if let Some(rest) = authority.strip_prefix('[') {
        let (v6_str, after) = rest
            .split_once(']')
            .context("unclosed IPv6 bracket in WebSocket egress URL")?;
        let ip: std::net::Ipv6Addr = v6_str
            .parse()
            .context("invalid IPv6 literal in WebSocket egress URL")?;
        let port = if after.is_empty() {
            default_port
        } else if let Some(port_s) = after.strip_prefix(':') {
            let p: u16 = port_s
                .parse()
                .context("invalid port in WebSocket egress URL")?;
            ensure!(p > 0, "port in WebSocket egress URL must not be zero");
            p
        } else {
            bail!("unexpected trailing characters after IPv6 literal in WebSocket egress URL");
        };
        return Ok((ip.to_string(), port));
    }
    let (host_part, port) = match authority.rsplit_once(':') {
        Some((h, p)) => {
            let port_num: u16 = p.parse().context("invalid port in WebSocket egress URL")?;
            ensure!(
                port_num > 0,
                "port in WebSocket egress URL must not be zero"
            );
            (h, port_num)
        }
        None => (authority, default_port),
    };
    ensure!(
        !host_part.is_empty() && host_part.len() <= 253,
        "invalid host in WebSocket egress URL"
    );
    let host_norm = if let Ok(v4) = host_part.parse::<std::net::Ipv4Addr>() {
        ensure!(
            !v4.is_unspecified(),
            "wildcard IP 0.0.0.0 is not allowed in WebSocket egress URL"
        );
        v4.to_string()
    } else {
        let lower = host_part.to_ascii_lowercase();
        ensure!(
            config::is_valid_sni_hostname(&lower) || lower == "localhost",
            "invalid DNS hostname in WebSocket egress URL"
        );
        lower
    };
    Ok((host_norm, port))
}

impl FromStr for EgressEndpoint {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let raw = s.trim();
        ensure!(!raw.is_empty(), "egress upstream cannot be empty");
        if let Some(rest) = raw.strip_prefix("tcp://") {
            let sa: SocketAddr = rest
                .parse()
                .context("invalid tcp://IP:PORT egress upstream")?;
            ensure!(sa.port() > 0, "egress_upstream port must not be zero");
            return Ok(Self::Tcp(sa));
        }
        let ws_scheme = raw
            .strip_prefix("wss://")
            .map(|r| (true, r))
            .or_else(|| raw.strip_prefix("ws://").map(|r| (false, r)));
        if let Some((tls, rest)) = ws_scheme {
            ensure!(
                !rest.contains('#'),
                "URL fragments ('#') are not allowed in WebSocket egress URL"
            );
            let (before_query, query_opt) = match rest.split_once('?') {
                Some((b, q)) => (b, Some(q)),
                None => (rest, None),
            };
            let (authority, raw_path) = before_query.split_once('/').context(
                "WebSocket egress URL must include a non-root secret path (e.g. wss://host/ws/...)",
            )?;
            let default_port = if tls { 443 } else { 80 };
            let (host, port) = parse_ws_authority(authority, default_port)?;
            let path = validate_egress_ws_path(&format!("/{raw_path}"))?;
            let mut connect_override = None;
            if let Some(query) = query_opt {
                for pair in query.split('&').filter(|p| !p.is_empty()) {
                    let (k, v) = pair
                        .split_once('=')
                        .context("invalid query parameter in WebSocket egress URL")?;
                    ensure!(
                        k == "connect",
                        "unsupported query parameter '{k}' in WebSocket egress URL (only ?connect=IP:PORT is supported)"
                    );
                    let sa: SocketAddr = v
                        .parse()
                        .context("invalid ?connect=IP:PORT in WebSocket egress URL")?;
                    ensure!(sa.port() > 0, "?connect port must not be zero");
                    connect_override = Some(sa);
                }
            }
            return Ok(Self::Ws(WsEndpoint {
                tls,
                host,
                port,
                path,
                connect_override,
            }));
        }
        let sa: SocketAddr = raw
            .parse()
            .context("egress upstream must be IP:PORT or wss://host/path")?;
        ensure!(sa.port() > 0, "egress_upstream port must not be zero");
        Ok(Self::Tcp(sa))
    }
}

impl Serialize for EgressEndpoint {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for EgressEndpoint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse::<Self>().map_err(serde::de::Error::custom)
    }
}

const B64_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub(crate) fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let triple = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        out.push(B64_TABLE[((triple >> 18) & 0x3f) as usize] as char);
        out.push(B64_TABLE[((triple >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64_TABLE[((triple >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64_TABLE[(triple & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

pub(crate) fn compute_ws_accept(client_key_b64: &str) -> String {
    let mut hasher = sha1::Sha1::new();
    hasher.update(client_key_b64.trim().as_bytes());
    hasher.update(WS_GUID.as_bytes());
    let digest = hasher.finalize();
    base64_encode(&digest)
}

fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
}

pub(crate) enum MaybeTlsStream {
    Plain(TcpStream),
    Tls(Box<tokio_native_tls::TlsStream<TcpStream>>),
}

impl MaybeTlsStream {
    pub(crate) fn tcp_ref(&self) -> &TcpStream {
        match self {
            Self::Plain(tcp) => tcp,
            Self::Tls(tls) => tls.get_ref().get_ref().get_ref(),
        }
    }
}

impl AsyncRead for MaybeTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MaybeTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Bounded RFC 6455 Binary WebSocket byte-stream adapter.
pub(crate) struct WsStream<S> {
    inner: S,
    is_client: bool,
    rx_raw: Vec<u8>,
    rx_raw_pos: usize,
    rx_app: Vec<u8>,
    rx_app_pos: usize,
    rx_eof: bool,
    tx_buf: Vec<u8>,
    tx_pos: usize,
    staged_input_len: usize,
    pending_pong: Option<Vec<u8>>,
    close_encoded: bool,
}

impl<S> WsStream<S> {
    pub(crate) fn new(inner: S, is_client: bool, initial_raw: Vec<u8>) -> Self {
        Self {
            inner,
            is_client,
            rx_raw: initial_raw,
            rx_raw_pos: 0,
            rx_app: Vec::new(),
            rx_app_pos: 0,
            rx_eof: false,
            tx_buf: Vec::with_capacity(MAX_WS_WRITE_CHUNK + 16),
            tx_pos: 0,
            staged_input_len: 0,
            pending_pong: None,
            close_encoded: false,
        }
    }

    pub(crate) fn inner_ref(&self) -> &S {
        &self.inner
    }

    fn encode_frame_into(dst: &mut Vec<u8>, opcode: u8, payload: &[u8], mask_client: bool) {
        dst.push(0x80 | (opcode & 0x0f));
        let mask_bit = if mask_client { 0x80u8 } else { 0x00u8 };
        let len = payload.len();
        if len < 126 {
            dst.push(mask_bit | (len as u8));
        } else {
            dst.push(mask_bit | 126);
            dst.extend_from_slice(&(len as u16).to_be_bytes());
        }
        if mask_client {
            let mut mask = [0u8; 4];
            rand::rngs::OsRng.fill_bytes(&mut mask);
            dst.extend_from_slice(&mask);
            for (i, &b) in payload.iter().enumerate() {
                dst.push(b ^ mask[i & 3]);
            }
        } else {
            dst.extend_from_slice(payload);
        }
    }

    fn compact_rx_raw(&mut self) {
        if self.rx_raw_pos == 0 {
            return;
        }
        if self.rx_raw_pos >= self.rx_raw.len() {
            self.rx_raw.clear();
            self.rx_raw_pos = 0;
        } else if self.rx_raw_pos >= 4096 {
            self.rx_raw.drain(..self.rx_raw_pos);
            self.rx_raw_pos = 0;
        }
    }

    /// Attempt to parse one complete WebSocket frame from `rx_raw[rx_raw_pos..]`.
    fn try_decode_frame(&mut self) -> std::io::Result<bool> {
        let avail = &self.rx_raw[self.rx_raw_pos..];
        if avail.len() < 2 {
            return Ok(false);
        }
        let b0 = avail[0];
        let b1 = avail[1];
        if (b0 & 0x70) != 0 {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "WebSocket RSV bits must be zero",
            ));
        }
        let opcode = b0 & 0x0f;
        let masked = (b1 & 0x80) != 0;
        // RFC 6455 §5.1: server MUST reject unmasked client frames; client MUST reject masked server frames.
        if self.is_client && masked {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "server sent masked WebSocket frame",
            ));
        }
        if !self.is_client && !masked {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "client sent unmasked WebSocket frame",
            ));
        }
        let len_code = usize::from(b1 & 0x7f);
        let (payload_len, mut hdr_len) = if len_code < 126 {
            (len_code, 2usize)
        } else if len_code == 126 {
            if avail.len() < 4 {
                return Ok(false);
            }
            let n = usize::from(u16::from_be_bytes([avail[2], avail[3]]));
            (n, 4usize)
        } else {
            if avail.len() < 10 {
                return Ok(false);
            }
            let mut raw8 = [0u8; 8];
            raw8.copy_from_slice(&avail[2..10]);
            let n64 = u64::from_be_bytes(raw8);
            if n64 > MAX_WS_FRAME_PAYLOAD as u64 {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "WebSocket frame exceeds 64 KiB bound",
                ));
            }
            (n64 as usize, 10usize)
        };
        if payload_len > MAX_WS_FRAME_PAYLOAD {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "WebSocket frame exceeds 64 KiB bound",
            ));
        }
        let mask_key = if masked {
            if avail.len() < hdr_len + 4 {
                return Ok(false);
            }
            let m = [
                avail[hdr_len],
                avail[hdr_len + 1],
                avail[hdr_len + 2],
                avail[hdr_len + 3],
            ];
            hdr_len += 4;
            Some(m)
        } else {
            None
        };
        let total_len = hdr_len + payload_len;
        if avail.len() < total_len {
            return Ok(false);
        }

        let payload_start = self.rx_raw_pos + hdr_len;
        let payload_end = payload_start + payload_len;
        match opcode {
            // Continuation (0x0), Text (0x1), Binary (0x2)
            0x0..=0x2 => {
                if self.rx_app_pos >= self.rx_app.len() {
                    self.rx_app.clear();
                    self.rx_app_pos = 0;
                }
                if let Some(mask) = mask_key {
                    self.rx_app.reserve(payload_len);
                    for (i, &b) in self.rx_raw[payload_start..payload_end].iter().enumerate() {
                        self.rx_app.push(b ^ mask[i & 3]);
                    }
                } else {
                    self.rx_app
                        .extend_from_slice(&self.rx_raw[payload_start..payload_end]);
                }
            }
            // Close (0x8)
            0x8 => {
                self.rx_eof = true;
            }
            // Ping (0x9)
            0x9 => {
                if payload_len > 125 {
                    return Err(std::io::Error::new(
                        ErrorKind::InvalidData,
                        "WebSocket Ping payload > 125 bytes",
                    ));
                }
                let mut ping_data = self.rx_raw[payload_start..payload_end].to_vec();
                if let Some(mask) = mask_key {
                    for (i, b) in ping_data.iter_mut().enumerate() {
                        *b ^= mask[i & 3];
                    }
                }
                let mut pong = Vec::with_capacity(ping_data.len() + 8);
                Self::encode_frame_into(&mut pong, 0xA, &ping_data, self.is_client);
                self.pending_pong = Some(pong);
            }
            // Pong (0xA)
            0xA => {
                if payload_len > 125 {
                    return Err(std::io::Error::new(
                        ErrorKind::InvalidData,
                        "WebSocket Pong payload > 125 bytes",
                    ));
                }
            }
            _ => {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "unsupported WebSocket opcode",
                ));
            }
        }
        self.rx_raw_pos += total_len;
        self.compact_rx_raw();
        Ok(true)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> WsStream<S> {
    fn poll_drain_tx(&mut self, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        while self.tx_pos < self.tx_buf.len() {
            let n = match Pin::new(&mut self.inner).poll_write(cx, &self.tx_buf[self.tx_pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        ErrorKind::WriteZero,
                        "WebSocket underlying stream write zero",
                    )));
                }
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            self.tx_pos += n;
        }
        self.tx_buf.clear();
        self.tx_pos = 0;
        Pin::new(&mut self.inner).poll_flush(cx)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.rx_app_pos < this.rx_app.len() {
                let avail = &this.rx_app[this.rx_app_pos..];
                let n = avail.len().min(buf.remaining());
                buf.put_slice(&avail[..n]);
                this.rx_app_pos += n;
                if this.rx_app_pos >= this.rx_app.len() {
                    this.rx_app.clear();
                    this.rx_app_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if this.rx_eof {
                return Poll::Ready(Ok(()));
            }
            match this.try_decode_frame() {
                Ok(true) => continue,
                Ok(false) => {}
                Err(e) => return Poll::Ready(Err(e)),
            }

            let mut tmp = [0u8; 8192];
            let mut rbuf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut this.inner).poll_read(cx, &mut rbuf) {
                Poll::Ready(Ok(())) => {
                    let filled = rbuf.filled();
                    if filled.is_empty() {
                        if this.rx_raw_pos < this.rx_raw.len() {
                            return Poll::Ready(Err(std::io::Error::new(
                                ErrorKind::UnexpectedEof,
                                "truncated WebSocket frame before EOF",
                            )));
                        }
                        this.rx_eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    this.rx_raw.extend_from_slice(filled);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        src: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.staged_input_len == 0 && !this.tx_buf.is_empty() {
            // Drain a previously queued Pong before staging user payload.
            if this.poll_drain_tx(cx).is_pending() {
                return Poll::Pending;
            }
        }
        if this.staged_input_len == 0 {
            if src.is_empty() {
                return Poll::Ready(Ok(0));
            }
            if let Some(pong) = this.pending_pong.take() {
                this.tx_buf.extend_from_slice(&pong);
            }
            let take = src.len().min(MAX_WS_WRITE_CHUNK);
            Self::encode_frame_into(&mut this.tx_buf, 0x2, &src[..take], this.is_client);
            this.staged_input_len = take;
        }
        match this.poll_drain_tx(cx) {
            Poll::Ready(Ok(())) => {
                let done = this.staged_input_len;
                this.staged_input_len = 0;
                Poll::Ready(Ok(done))
            }
            Poll::Ready(Err(e)) => {
                this.staged_input_len = 0;
                this.tx_buf.clear();
                this.tx_pos = 0;
                Poll::Ready(Err(e))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.tx_buf.is_empty() {
            if let Some(pong) = this.pending_pong.take() {
                this.tx_buf.extend_from_slice(&pong);
            }
        }
        this.poll_drain_tx(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if !this.close_encoded {
            if let Some(pong) = this.pending_pong.take() {
                this.tx_buf.extend_from_slice(&pong);
            }
            // RFC 6455 status code 1000 (Normal Closure) = 0x03e8 before TCP FIN.
            Self::encode_frame_into(&mut this.tx_buf, 0x8, &[0x03, 0xe8], this.is_client);
            this.close_encoded = true;
        }
        match this.poll_drain_tx(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

pub(crate) enum UpstreamStream {
    Tcp(TcpStream),
    Ws(Box<WsStream<MaybeTlsStream>>),
}

impl UpstreamStream {
    pub(crate) fn tcp_ref(&self) -> &TcpStream {
        match self {
            Self::Tcp(tcp) => tcp,
            Self::Ws(ws) => ws.inner_ref().tcp_ref(),
        }
    }
}

impl AsyncRead for UpstreamStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            Self::Ws(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for UpstreamStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            Self::Ws(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_flush(cx),
            Self::Ws(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Self::Ws(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

pub(crate) fn build_tls_connector(
    ca_file: Option<&std::path::Path>,
) -> Result<tokio_native_tls::TlsConnector> {
    let mut builder = native_tls::TlsConnector::builder();
    builder.min_protocol_version(Some(native_tls::Protocol::Tlsv12));
    if let Some(path) = ca_file {
        let pem_bytes = std::fs::read(path)
            .with_context(|| format!("reading egress_tls_ca_file {}", path.display()))?;
        let cert = native_tls::Certificate::from_pem(&pem_bytes)
            .with_context(|| format!("parsing PEM certificate in {}", path.display()))?;
        builder.add_root_certificate(cert);
    }
    let connector = builder
        .build()
        .context("initializing native TLS connector for WSS egress")?;
    Ok(tokio_native_tls::TlsConnector::from(connector))
}

pub(crate) async fn client_ws_upgrade<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    host_header: &str,
    path: &str,
) -> Result<WsStream<S>> {
    let mut key_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut key_bytes);
    let key_b64 = base64_encode(&key_bytes);
    let expected_accept = compute_ws_accept(&key_b64);

    let req = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host_header}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {key_b64}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n\r\n"
    );
    stream
        .write_all(req.as_bytes())
        .await
        .context("writing WebSocket Upgrade request")?;
    stream
        .flush()
        .await
        .context("flushing WebSocket Upgrade request")?;

    let mut raw = Vec::with_capacity(512);
    let mut chunk = [0u8; 1024];
    let hdr_end = loop {
        if let Some(end) = find_header_end(&raw) {
            break end;
        }
        ensure!(
            raw.len() < MAX_HTTP_HEADER_BYTES,
            "WebSocket response headers exceeded 8 KiB bound"
        );
        let n = stream
            .read(&mut chunk)
            .await
            .context("reading WebSocket Upgrade response")?;
        ensure!(n > 0, "EOF before WebSocket HTTP 101 response");
        raw.extend_from_slice(&chunk[..n]);
    };

    let hdr_text =
        std::str::from_utf8(&raw[..hdr_end]).context("non-UTF8 WebSocket HTTP response")?;
    let mut lines = hdr_text.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    ensure!(
        status_code == 101,
        "WebSocket upgrade rejected with HTTP status '{status_line}'"
    );

    let mut has_upgrade_ws = false;
    let mut has_conn_upgrade = false;
    let mut accept_ok = false;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, val)) = line.split_once(':') {
            let v = val.trim();
            if name.eq_ignore_ascii_case("upgrade") && v.eq_ignore_ascii_case("websocket") {
                has_upgrade_ws = true;
            } else if name.eq_ignore_ascii_case("connection")
                && v.split(',')
                    .any(|tok| tok.trim().eq_ignore_ascii_case("upgrade"))
            {
                has_conn_upgrade = true;
            } else if name.eq_ignore_ascii_case("sec-websocket-accept") {
                accept_ok = ct_eq_bytes(v.as_bytes(), expected_accept.as_bytes());
            }
        }
    }
    ensure!(
        has_upgrade_ws && has_conn_upgrade,
        "WebSocket 101 response missing Upgrade/Connection headers"
    );
    ensure!(accept_ok, "WebSocket Sec-WebSocket-Accept mismatch");

    let trailing = raw[hdr_end..].to_vec();
    Ok(WsStream::new(stream, true, trailing))
}

pub(crate) async fn dial_ws_endpoint(
    ep: &WsEndpoint,
    tls_connector: Option<&tokio_native_tls::TlsConnector>,
) -> Result<WsStream<MaybeTlsStream>> {
    let target = ep.dial_target();
    let tcp = TcpStream::connect(&target)
        .await
        .with_context(|| format!("connecting to WS egress {}", ep.redacted_label()))?;
    configure_tcp_socket(&tcp)?;
    let maybe_tls = if ep.tls {
        let connector = match tls_connector {
            Some(c) => c.clone(),
            None => build_tls_connector(None)?,
        };
        let tls_stream = connector
            .connect(&ep.host, tcp)
            .await
            .with_context(|| format!("TLS handshake failed with {}", ep.redacted_label()))?;
        MaybeTlsStream::Tls(Box::new(tls_stream))
    } else {
        MaybeTlsStream::Plain(tcp)
    };
    let host_hdr = ep.host_header();
    client_ws_upgrade(maybe_tls, &host_hdr, &ep.path).await
}

/// Accept a server-side HTTP/1.1 WebSocket Upgrade on `egress` after reading `b"GET "`.
pub(crate) async fn server_ws_accept(
    mut edge: TcpStream,
    first4: &[u8; 4],
    expected_path: &str,
    peer_ip: IpAddr,
) -> Result<(WsStream<TcpStream>, IpAddr, usize, usize)> {
    let mut raw = Vec::with_capacity(512);
    raw.extend_from_slice(first4);
    let mut chunk = [0u8; 1024];
    let hdr_end = loop {
        if let Some(end) = find_header_end(&raw) {
            break end;
        }
        ensure!(
            raw.len() < MAX_HTTP_HEADER_BYTES,
            "inbound HTTP headers on egress exceeded 8 KiB bound"
        );
        let n = edge
            .read(&mut chunk)
            .await
            .context("reading HTTP Upgrade headers on egress")?;
        ensure!(n > 0, "EOF during HTTP Upgrade headers on egress");
        raw.extend_from_slice(&chunk[..n]);
    };

    let rx_hdr_bytes = raw.len().saturating_sub(4);
    let hdr_text = match std::str::from_utf8(&raw[..hdr_end]) {
        Ok(s) => s,
        Err(_) => {
            let _ = edge
                .write_all(
                    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            let _ = edge.shutdown().await;
            bail!("non-UTF8 HTTP header on egress");
        }
    };

    let mut lines = hdr_text.split("\r\n");
    let req_line = lines.next().unwrap_or("");
    let mut req_parts = req_line.split_whitespace();
    let method = req_parts.next().unwrap_or("");
    let raw_target = req_parts.next().unwrap_or("");
    let req_path = raw_target.split('?').next().unwrap_or("");

    let mut forwarded_ip: Option<IpAddr> = None;
    let mut has_upgrade_ws = false;
    let mut ws_key: Option<String> = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, val)) = line.split_once(':') {
            let v = val.trim();
            if name.eq_ignore_ascii_case("upgrade") && v.eq_ignore_ascii_case("websocket") {
                has_upgrade_ws = true;
            } else if name.eq_ignore_ascii_case("sec-websocket-key")
                && !v.is_empty()
                && v.len() <= 64
            {
                ws_key = Some(v.to_string());
            } else if peer_ip.is_loopback() && name.eq_ignore_ascii_case("x-real-ip") {
                if let Ok(ip) = v.parse::<IpAddr>() {
                    forwarded_ip = Some(ip);
                }
            } else if peer_ip.is_loopback()
                && forwarded_ip.is_none()
                && name.eq_ignore_ascii_case("x-forwarded-for")
            {
                if let Some(first_hop) = v.split(',').next() {
                    if let Ok(ip) = first_hop.trim().parse::<IpAddr>() {
                        forwarded_ip = Some(ip);
                    }
                }
            }
        }
    }
    let effective_ip = forwarded_ip.unwrap_or(peer_ip);

    if method != "GET" || !ct_eq_bytes(req_path.as_bytes(), expected_path.as_bytes()) {
        let resp = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let _ = edge.write_all(resp).await;
        let _ = edge.shutdown().await;
        bail!("egress WebSocket path mismatch");
    }

    let Some(key_b64) = ws_key.filter(|_| has_upgrade_ws) else {
        let resp =
            b"HTTP/1.1 426 Upgrade Required\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let _ = edge.write_all(resp).await;
        let _ = edge.shutdown().await;
        bail!("missing WebSocket Upgrade headers on egress");
    };

    let accept_val = compute_ws_accept(&key_b64);
    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {accept_val}\r\n\r\n"
    );
    edge.write_all(resp.as_bytes())
        .await
        .context("writing WebSocket 101 response on egress")?;
    edge.flush()
        .await
        .context("flushing WebSocket 101 response on egress")?;

    let trailing = raw[hdr_end..].to_vec();
    Ok((
        WsStream::new(edge, false, trailing),
        effective_ip,
        rx_hdr_bytes,
        resp.len(),
    ))
}

struct WarmSlot {
    endpoint: WsEndpoint,
    idle: std::sync::Mutex<VecDeque<(WsStream<MaybeTlsStream>, Instant)>>,
    refill_notify: Arc<tokio::sync::Notify>,
}

/// Per-upstream warm pool of pre-connected, TLS+WS-upgraded idle streams on `edge`.
pub(crate) struct WsWarmPool {
    target_per_node: usize,
    tls_connector: tokio_native_tls::TlsConnector,
    slots: HashMap<usize, Arc<WarmSlot>>,
}

impl WsWarmPool {
    pub(crate) fn new(
        upstreams: &[EgressEndpoint],
        target_per_node: usize,
        ca_file: Option<&std::path::Path>,
    ) -> Result<Self> {
        let tls_connector = build_tls_connector(ca_file)?;
        let mut slots = HashMap::new();
        for (idx, ep) in upstreams.iter().enumerate() {
            if let EgressEndpoint::Ws(ws_ep) = ep {
                slots.insert(
                    idx,
                    Arc::new(WarmSlot {
                        endpoint: ws_ep.clone(),
                        idle: std::sync::Mutex::new(VecDeque::with_capacity(
                            target_per_node.max(1),
                        )),
                        refill_notify: Arc::new(tokio::sync::Notify::new()),
                    }),
                );
            }
        }
        Ok(Self {
            target_per_node,
            tls_connector,
            slots,
        })
    }

    pub(crate) fn tls_connector(&self) -> &tokio_native_tls::TlsConnector {
        &self.tls_connector
    }

    pub(crate) fn pop_warm(&self, idx: usize) -> Option<WsStream<MaybeTlsStream>> {
        let slot = self.slots.get(&idx)?;
        let now = Instant::now();
        let mut q = slot.idle.lock().unwrap_or_else(|e| e.into_inner());
        let mut found = None;
        while let Some((conn, created_at)) = q.pop_front() {
            if now.saturating_duration_since(created_at) < WARM_CONN_MAX_IDLE {
                found = Some(conn);
                break;
            }
        }
        let need_refill = q.len() < self.target_per_node;
        drop(q);
        if need_refill && self.target_per_node > 0 {
            slot.refill_notify.notify_one();
        }
        found
    }

    pub(crate) fn clear_node(&self, idx: usize) {
        if let Some(slot) = self.slots.get(&idx) {
            let mut q = slot.idle.lock().unwrap_or_else(|e| e.into_inner());
            q.clear();
            drop(q);
            if self.target_per_node > 0 {
                slot.refill_notify.notify_one();
            }
        }
    }

    pub(crate) fn spawn_replenishers(
        self: &Arc<Self>,
        state: Arc<State>,
        mut stop_rx: tokio::sync::watch::Receiver<bool>,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        if self.target_per_node == 0 {
            return Vec::new();
        }
        let mut handles = Vec::with_capacity(self.slots.len());
        for (&idx, slot) in &self.slots {
            let pool = self.clone();
            let slot = slot.clone();
            let st = state.clone();
            let mut rx = stop_rx.clone();
            handles.push(tokio::spawn(async move {
                loop {
                    if *rx.borrow() {
                        break;
                    }
                    // Evict expired idle streams and check how many warm connections are missing.
                    let missing = {
                        let now = Instant::now();
                        let mut q = slot.idle.lock().unwrap_or_else(|e| e.into_inner());
                        while let Some((_, created_at)) = q.front() {
                            if now.saturating_duration_since(*created_at) >= WARM_CONN_MAX_IDLE {
                                q.pop_front();
                            } else {
                                break;
                            }
                        }
                        pool.target_per_node.saturating_sub(q.len())
                    };

                    // Do not aggressively pre-dial while the upstream node is in failure cooldown.
                    let in_cooldown = {
                        let h = st.egress_health.lock().unwrap_or_else(|e| e.into_inner());
                        h.nodes
                            .get(idx)
                            .and_then(|s| s.until)
                            .is_some_and(|u| Instant::now() < u)
                    };

                    if missing > 0 && !in_cooldown {
                        let dial_budget = st.handshake.min(Duration::from_secs(5));
                        match timeout(
                            dial_budget,
                            dial_ws_endpoint(&slot.endpoint, Some(&pool.tls_connector)),
                        )
                        .await
                        {
                            Ok(Ok(ws_conn)) => {
                                let mut q = slot.idle.lock().unwrap_or_else(|e| e.into_inner());
                                if q.len() < pool.target_per_node {
                                    q.push_back((ws_conn, Instant::now()));
                                }
                                continue;
                            }
                            _ => {
                                // Back off briefly on background pre-warm failure.
                                tokio::select! {
                                    _ = rx.changed() => if *rx.borrow() { break; },
                                    () = tokio::time::sleep(Duration::from_secs(2)) => {}
                                }
                                continue;
                            }
                        }
                    }

                    tokio::select! {
                        _ = rx.changed() => {
                            if *rx.borrow() {
                                break;
                            }
                        }
                        () = slot.refill_notify.notified() => {}
                        () = tokio::time::sleep(Duration::from_secs(10)) => {}
                    }
                }
            }));
        }
        // Silence unused mut warning if slots is empty.
        let _ = &mut stop_rx;
        handles
    }
}

#[cfg(test)]
mod ws_tests {
    use super::*;
    use aes::cipher::KeyIvInit;

    #[test]
    fn endpoint_parsing_redaction_and_rfc6455_accept_vector() -> Result<()> {
        // Normative RFC 6455 §4.2.2 vector
        assert_eq!(
            compute_ws_accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );

        let tcp_bare: EgressEndpoint = "10.203.0.9:29443".parse()?;
        let tcp_uri: EgressEndpoint = "tcp://10.203.0.9:29443".parse()?;
        assert_eq!(tcp_bare, tcp_uri);
        assert_eq!(tcp_bare.redacted_label(), "10.203.0.9:29443");
        assert!(!tcp_bare.is_ws());

        let wss: EgressEndpoint = "wss://CH.Example.com/ws/9f3c8a1b2d".parse()?;
        assert!(wss.is_ws());
        assert_eq!(wss.port(), 443);
        assert_eq!(wss.redacted_label(), "wss://ch.example.com:443/***");
        assert!(!wss.redacted_label().contains("9f3c8a1b2d"));
        assert_eq!(wss.to_string(), "wss://ch.example.com/ws/9f3c8a1b2d");

        let wss_ov: EgressEndpoint =
            "wss://[2001:db8::1]:8443/ws/sec_1?connect=127.0.0.1:18443".parse()?;
        assert_eq!(wss_ov.port(), 8443);
        assert_eq!(wss_ov.redacted_label(), "wss://[2001:db8::1]:8443/***");
        let serialized = serde_json::to_string(&wss_ov)?;
        let roundtrip: EgressEndpoint = serde_json::from_str(&serialized)?;
        assert_eq!(wss_ov, roundtrip);

        // Reject root path, fragments, unknown query params, wildcard IPs, zero port
        for bad in [
            "wss://ch.example.com/",
            "wss://ch.example.com",
            "wss://ch.example.com/ws/abc#frag",
            "wss://ch.example.com/ws/abc?foo=1",
            "ws://0.0.0.0:8080/ws/abc",
            "wss://user@ch.example.com/ws/abc",
            "wss://ch.example.com:0/ws/abc",
        ] {
            assert!(
                bad.parse::<EgressEndpoint>().is_err(),
                "expected error for {bad}"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn ws_codec_masking_large_chunks_ping_pong_and_close() -> Result<()> {
        let (a, b) = tokio::io::duplex(128 * 1024);
        let mut client = WsStream::new(a, true, Vec::new());
        let mut server = WsStream::new(b, false, Vec::new());

        // 40 KiB payload splits across multiple 16 KiB masked frames.
        let mut payload = vec![0u8; 40_000];
        rand::rngs::OsRng.fill_bytes(&mut payload);
        let expected = payload.clone();

        let writer = tokio::spawn(async move {
            client.write_all(&payload).await?;
            client.shutdown().await?;
            Ok::<_, std::io::Error>(client)
        });

        let mut received = Vec::new();
        server.read_to_end(&mut received).await?;
        assert_eq!(received, expected);
        let _client = writer.await??;

        // Verify server rejects unmasked client frames per RFC 6455 §5.1.
        let (mut raw_cl, raw_srv) = tokio::io::duplex(1024);
        let mut srv_ws = WsStream::new(raw_srv, false, Vec::new());
        raw_cl.write_all(&[0x82, 0x03, b'a', b'b', b'c']).await?;
        let mut out = [0u8; 8];
        assert!(srv_ws.read(&mut out).await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn ws_egress_e2e_path_guard_warm_pool_stale_retry_and_failover() -> Result<()> {
        // 1. Mock Telegram DC2 responder (`req_pq_multi` -> `resPQ` with echoed nonce).
        let dc_listener = TcpListener::bind("127.0.0.1:0").await?;
        let dc_addr = dc_listener.local_addr()?;
        let _dc_task = tokio::spawn(async move {
            while let Ok((mut s, _)) = dc_listener.accept().await {
                tokio::spawn(async move {
                    let mut hdr = [0u8; 64];
                    if s.read_exact(&mut hdr).await.is_err() {
                        return;
                    }
                    let Ok(mut dec) = AesCtr::new_from_slices(&hdr[8..40], &hdr[40..56]) else {
                        return;
                    };
                    let mut plain_hdr = hdr;
                    wire::crypt(&mut dec, &mut plain_hdr);
                    let reversed: Vec<u8> = hdr[8..56].iter().rev().copied().collect();
                    let Ok(mut enc) = AesCtr::new_from_slices(&reversed[..32], &reversed[32..])
                    else {
                        return;
                    };
                    let mut len_b = [0u8; 4];
                    if s.read_exact(&mut len_b).await.is_err() {
                        return;
                    }
                    wire::crypt(&mut dec, &mut len_b);
                    let flen = (u32::from_le_bytes(len_b) & 0x7fff_ffff) as usize;
                    if !(40..=4096).contains(&flen) {
                        return;
                    }
                    let mut req = vec![0u8; flen];
                    if s.read_exact(&mut req).await.is_err() {
                        return;
                    }
                    wire::crypt(&mut dec, &mut req);
                    let mut nonce = [0u8; 16];
                    nonce.copy_from_slice(&req[24..40]);

                    // Build 40-byte unencrypted resPQ#05162463 response in padded-intermediate frame
                    let mut resp = Vec::with_capacity(44);
                    resp.extend_from_slice(&40u32.to_le_bytes());
                    resp.extend_from_slice(&0u64.to_le_bytes());
                    resp.extend_from_slice(&req[8..16]);
                    resp.extend_from_slice(&20u32.to_le_bytes());
                    resp.extend_from_slice(&[0x63, 0x24, 0x16, 0x05]);
                    resp.extend_from_slice(&nonce);
                    wire::crypt(&mut enc, &mut resp);
                    let _ = s.write_all(&resp).await;
                    let _ = s.shutdown().await;
                });
            }
        });

        let token = [0x42u8; 16];
        let mut dcs = HashMap::new();
        dcs.insert(2i16, dc_addr);
        let dcs_arc = Arc::new(dcs);

        // 2. Start Primary and Backup WS egress servers on loopback with ws_path = "/ws/secret-99".
        let eg1_listener = TcpListener::bind("127.0.0.1:0").await?;
        let eg1_addr = eg1_listener.local_addr()?;
        let (eg1_stop_tx, eg1_stop_rx) = tokio::sync::oneshot::channel::<()>();
        let mut sec1 = EgressSecurityConfig::default_for(64);
        sec1.accept_legacy = false;
        sec1.max_failed_per_ip = 2;
        sec1.ws_path = Some("/ws/secret-99".to_string());
        let eg1_counters = Arc::new(telemetry::Counters::default());
        let dcs1 = dcs_arc.clone();
        let eg1_task = tokio::spawn(async move {
            serve_egress_with_security(
                eg1_listener,
                dcs1,
                token,
                64,
                Duration::from_secs(3),
                Duration::from_secs(10),
                Duration::from_secs(1),
                eg1_counters,
                sec1,
                async {
                    let _ = eg1_stop_rx.await;
                },
            )
            .await
        });

        let eg2_listener = TcpListener::bind("127.0.0.1:0").await?;
        let eg2_addr = eg2_listener.local_addr()?;
        let (eg2_stop_tx, eg2_stop_rx) = tokio::sync::oneshot::channel::<()>();
        let mut sec2 = EgressSecurityConfig::default_for(64);
        sec2.accept_legacy = false;
        sec2.ws_path = Some("/ws/secret-99".to_string());
        let eg2_counters = Arc::new(telemetry::Counters::default());
        let dcs2 = dcs_arc.clone();
        let eg2_task = tokio::spawn(async move {
            serve_egress_with_security(
                eg2_listener,
                dcs2,
                token,
                64,
                Duration::from_secs(3),
                Duration::from_secs(10),
                Duration::from_secs(1),
                eg2_counters,
                sec2,
                async {
                    let _ = eg2_stop_rx.await;
                },
            )
            .await
        });

        // 3. Verify wrong WS path returns 404 AND repeated scanner hits with X-Forwarded-For
        //    do NOT rate-limit 127.0.0.1 loopback reverse-proxy traffic!
        for _ in 0..5 {
            let mut probe_s = TcpStream::connect(eg1_addr).await?;
            let bad_req = "GET /wrong-path HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 198.51.100.99\r\nConnection: close\r\n\r\n";
            probe_s.write_all(bad_req.as_bytes()).await?;
            let mut resp = Vec::new();
            probe_s.read_to_end(&mut resp).await?;
            let txt = String::from_utf8_lossy(&resp);
            assert!(txt.starts_with("HTTP/1.1 404"), "unexpected reply: {txt}");
        }

        // 4. Configure Edge with `ws://` upstreams + WsWarmPool (`pool_size = 2`) and run E2E probe!
        let upstreams: Vec<EgressEndpoint> = vec![
            format!("ws://{eg1_addr}/ws/secret-99").parse()?,
            format!("ws://{eg2_addr}/ws/secret-99").parse()?,
        ];
        let ws_pool = Arc::new(WsWarmPool::new(&upstreams, 2, None)?);
        let secret_key = [0x11u8; 16];
        let tmp_dir = std::env::temp_dir().join(format!("mtevil-ws-test-{}", std::process::id()));
        std::fs::create_dir_all(&tmp_dir)?;
        let sec_file = tmp_dir.join("secret");
        let tok_file = tmp_dir.join("egress-token");
        std::fs::write(&sec_file, hex::encode(secret_key))?;
        std::fs::write(&tok_file, hex::encode(token))?;

        let counters = Arc::new(telemetry::Counters::default());
        let cover_resolver = Arc::new(CoverResolver::new(
            "127.0.0.1:9".to_string(),
            Duration::from_secs(60),
        ));
        let edge_state = Arc::new(State {
            secrets: std::sync::RwLock::new(Arc::new(vec![NamedSecret {
                name: "default".to_string(),
                key: Zeroizing::new(secret_key),
            }])),
            sni: "example.com".to_string(),
            allowed_snis: std::sync::RwLock::new(Arc::new("example.com".to_string())),
            cover_resolver,
            enable_dd: true,
            proxy_protocol: false,
            cover_permits: Semaphore::new(8),
            dcs: HashMap::new(),
            dc_media_overrides: HashMap::new(),
            egress_upstreams: upstreams.clone(),
            ws_pool: Some(ws_pool.clone()),
            egress_strategy: EgressStrategy::Ordered,
            egress_token: token,
            egress_rr: std::sync::atomic::AtomicUsize::new(0),
            egress_health: std::sync::Mutex::new(EgressHealth::new(2)),
            mtv4_cooldown: std::sync::Mutex::new(vec![None; 2]),
            egress_probe_notify: Arc::new(tokio::sync::Notify::new()),
            egress_cooldown: Duration::from_millis(500),
            egress_cooldown_max: Duration::from_secs(5),
            egress_probe_interval: Duration::from_secs(30),
            egress_probe_degraded_interval: Duration::from_secs(5),
            egress_hedge_ms: 150,
            egress_use_mtv3: true,
            client_hello: Duration::from_secs(3),
            handshake: Duration::from_secs(4),
            idle: Duration::from_secs(10),
            drain: Duration::from_secs(1),
            flight: wire::ServerFlightProfile {
                cert_bytes: wire::DEFAULT_CERT_BYTES,
                jitter: 0,
            },
            flight_cert_bytes: Arc::new(std::sync::atomic::AtomicUsize::new(
                wire::DEFAULT_CERT_BYTES,
            )),
            flight_shaping: false,
            client_mss_bulk: None,
            replay: Mutex::new(ReplayCache::new(1024, Duration::from_secs(60))),
            counters,
            alert_webhook_url: None,
            alerts_file: None,
            diagnostics: false,
            me: None,
            edge_me: None,
        });

        let (pool_stop_tx, pool_stop_rx) = tokio::sync::watch::channel(false);
        let pool_tasks = ws_pool.spawn_replenishers(edge_state.clone(), pool_stop_rx);

        // Wait briefly so warm pool pre-establishes 2 idle WS connections to primary.
        tokio::time::sleep(Duration::from_millis(120)).await;

        let edge_listener = TcpListener::bind("127.0.0.1:0").await?;
        let edge_addr = edge_listener.local_addr()?;
        let (edge_stop_tx, edge_stop_rx) = tokio::sync::oneshot::channel::<()>();
        let st_run = edge_state.clone();
        let edge_task = tokio::spawn(async move {
            serve(edge_listener, st_run, 64, async {
                let _ = edge_stop_rx.await;
            })
            .await
        });

        let probe_cfg = Config {
            role: Role::Edge,
            listen: edge_addr,
            secret_file: Some(sec_file),
            users_file: None,
            replay_file: None,
            sni: "example.com".to_string(),
            cover: "127.0.0.1:9".to_string(),
            enable_dd: true,
            proxy_protocol: false,
            dc: Vec::new(),
            egress_upstreams: upstreams,
            egress_strategy: EgressStrategy::Ordered,
            egress_token_file: Some(tok_file),
            egress_ws_path: None,
            egress_ws_pool_size: 2,
            egress_tls_ca_file: None,
            max_connections: 64,
            client_hello_timeout_secs: 3,
            handshake_timeout_secs: 4,
            idle_timeout_secs: 10,
            drain_timeout_secs: 1,
            fake_tls_cert_bytes: wire::DEFAULT_CERT_BYTES,
            fake_tls_cert_bytes_explicit: true,
            fake_tls_cert_jitter: 0,
            flight_shaping: false,
            client_mss: None,
            client_mss_bulk: None,
            alert_webhook_url: None,
            egress_cooldown_base_ms: 500,
            egress_cooldown_max_ms: 5000,
            egress_probe_interval_secs: 30,
            egress_probe_degraded_interval_secs: 5,
            egress_hedge_ms: 150,
            egress_accept_legacy: false,
            egress_use_mtv3: true,
            egress_allow_from: Vec::new(),
            egress_max_failed_per_ip: 16,
            egress_nonce_cache_capacity: None,
            dc_media_override: Vec::new(),
            dc_probe_interval_secs: 0,
            cover_dns_ttl_secs: 60,
            diagnostics: false,
            metrics_listen: None,
            me: config::MeConfig::default(),
        };

        // Hit warm pool on primary
        probe_telegram_e2e(&probe_cfg, edge_addr, 2, Duration::from_secs(4)).await?;
        probe_telegram_e2e(&probe_cfg, edge_addr, 2, Duration::from_secs(4)).await?;

        // Inject a broken/closed warm socket into slot 0 and verify inline fresh-dial recovery!
        {
            let dead_l = TcpListener::bind("127.0.0.1:0").await?;
            let dead_a = dead_l.local_addr()?;
            let c_fut = TcpStream::connect(dead_a);
            let (c_res, a_res) = tokio::join!(c_fut, dead_l.accept());
            let dead_client = c_res?;
            let (mut dead_srv, _) = a_res?;
            let _ = dead_srv.shutdown().await;
            drop(dead_srv);
            tokio::time::sleep(Duration::from_millis(20)).await;
            if let Some(slot0) = ws_pool.slots.get(&0) {
                let mut q = slot0.idle.lock().unwrap_or_else(|e| e.into_inner());
                q.clear();
                q.push_front((
                    WsStream::new(MaybeTlsStream::Plain(dead_client), true, Vec::new()),
                    Instant::now(),
                ));
            }
        }
        // Must succeed on first attempt despite dead warm socket!
        probe_telegram_e2e(&probe_cfg, edge_addr, 2, Duration::from_secs(4)).await?;

        // 5. Stop Primary egress completely -> verify seamless failover to Backup WS egress!
        let _ = eg1_stop_tx.send(());
        let _ = eg1_task.await;
        probe_telegram_e2e(&probe_cfg, edge_addr, 2, Duration::from_secs(4)).await?;
        assert!(
            edge_state
                .counters
                .egress_failover_total
                .load(std::sync::atomic::Ordering::Relaxed)
                >= 1
        );

        let _ = pool_stop_tx.send(true);
        for t in pool_tasks {
            let _ = t.await;
        }
        let _ = edge_stop_tx.send(());
        let _ = edge_task.await;
        let _ = eg2_stop_tx.send(());
        let _ = eg2_task.await;
        let _ = std::fs::remove_dir_all(&tmp_dir);
        Ok(())
    }
}
