//! Bounded, allocation-capped parsers for HTTP/1.1 WebSocket Upgrade headers
//! (8 KiB bound) and RFC 6455 frame headers (64 KiB payload bound).
//!
//! Shared by `mtevil-data-plane::ws_egress` and fuzzed directly in `fuzz/`.

use anyhow::{bail, ensure, Result};
use std::net::IpAddr;

/// Hard upper bound on HTTP/1.1 WebSocket Upgrade request/response header block.
pub const MAX_WS_HTTP_HEADER_BYTES: usize = 8 * 1024;
/// Hard upper bound on a single inbound RFC 6455 WebSocket frame payload.
pub const MAX_WS_FRAME_PAYLOAD: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedWsUpgradeRequest {
    pub hdr_end: usize,
    pub path: String,
    pub has_upgrade_websocket: bool,
    pub ws_key: Option<String>,
    pub forwarded_ip: Option<IpAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsFrameDecision {
    Incomplete,
    Header(ParsedWsFrameHeader),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedWsFrameHeader {
    pub fin: bool,
    pub opcode: u8,
    pub mask_key: Option<[u8; 4]>,
    pub payload_start_rel: usize,
    pub payload_len: usize,
    pub total_len: usize,
}

pub fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn find_ws_http_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
}

/// Parse an HTTP/1.1 WebSocket Upgrade request header block (bounded to 8 KiB).
///
/// Returns `Ok(None)` if the `\r\n\r\n` terminator has not been received yet and
/// `raw.len() <= MAX_WS_HTTP_HEADER_BYTES`. Returns `Err` if malformed or > 8 KiB.
pub fn parse_ws_upgrade_request(
    raw: &[u8],
    trust_forwarded_headers: bool,
) -> Result<Option<ParsedWsUpgradeRequest>> {
    let Some(hdr_end) = find_ws_http_header_end(raw) else {
        ensure!(
            raw.len() <= MAX_WS_HTTP_HEADER_BYTES,
            "inbound HTTP headers on egress exceeded 8 KiB bound"
        );
        return Ok(None);
    };
    ensure!(
        hdr_end <= MAX_WS_HTTP_HEADER_BYTES,
        "inbound HTTP headers on egress exceeded 8 KiB bound"
    );
    let hdr_text =
        std::str::from_utf8(&raw[..hdr_end]).context_utf8("non-UTF8 HTTP header on egress")?;
    let mut lines = hdr_text.split("\r\n");
    let req_line = lines.next().unwrap_or("");
    let mut req_parts = req_line.split_whitespace();
    let method = req_parts.next().unwrap_or("");
    let raw_target = req_parts.next().unwrap_or("");
    let _version = req_parts.next().unwrap_or("");
    ensure!(
        method == "GET",
        "unsupported HTTP method for WebSocket upgrade"
    );
    let req_path = raw_target.split('?').next().unwrap_or("");
    ensure!(
        !req_path.is_empty() && req_path.starts_with('/'),
        "invalid HTTP request target for WebSocket upgrade"
    );

    let mut has_upgrade_websocket = false;
    let mut has_conn_upgrade = false;
    let mut ws_key: Option<String> = None;
    let mut real_ip: Option<IpAddr> = None;
    let mut xff_ip: Option<IpAddr> = None;

    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, val)) = line.split_once(':') else {
            continue;
        };
        let v = val.trim();
        if name.eq_ignore_ascii_case("upgrade") && v.eq_ignore_ascii_case("websocket") {
            has_upgrade_websocket = true;
        } else if name.eq_ignore_ascii_case("connection")
            && v.split(',')
                .any(|tok| tok.trim().eq_ignore_ascii_case("upgrade"))
        {
            has_conn_upgrade = true;
        } else if name.eq_ignore_ascii_case("sec-websocket-key") && !v.is_empty() && v.len() <= 64 {
            ws_key = Some(v.to_string());
        } else if trust_forwarded_headers && name.eq_ignore_ascii_case("x-real-ip") {
            if let Ok(ip) = v.parse::<IpAddr>() {
                real_ip = Some(ip);
            }
        } else if trust_forwarded_headers
            && xff_ip.is_none()
            && name.eq_ignore_ascii_case("x-forwarded-for")
        {
            if let Some(first_hop) = v.split(',').next() {
                if let Ok(ip) = first_hop.trim().parse::<IpAddr>() {
                    xff_ip = Some(ip);
                }
            }
        }
    }

    Ok(Some(ParsedWsUpgradeRequest {
        hdr_end,
        path: req_path.to_string(),
        has_upgrade_websocket: has_upgrade_websocket && has_conn_upgrade,
        ws_key,
        forwarded_ip: real_ip.or(xff_ip),
    }))
}

trait StrResultExt<T> {
    fn context_utf8(self, msg: &'static str) -> Result<T>;
}

impl<T> StrResultExt<T> for std::result::Result<T, std::str::Utf8Error> {
    fn context_utf8(self, msg: &'static str) -> Result<T> {
        self.map_err(|e| anyhow::anyhow!("{msg}: {e}"))
    }
}

/// Parse and validate an HTTP/1.1 101 Switching Protocols response (bounded to 8 KiB).
pub fn parse_ws_upgrade_response(raw: &[u8], expected_accept: &str) -> Result<Option<usize>> {
    let Some(hdr_end) = find_ws_http_header_end(raw) else {
        ensure!(
            raw.len() <= MAX_WS_HTTP_HEADER_BYTES,
            "WebSocket response headers exceeded 8 KiB bound"
        );
        return Ok(None);
    };
    ensure!(
        hdr_end <= MAX_WS_HTTP_HEADER_BYTES,
        "WebSocket response headers exceeded 8 KiB bound"
    );
    let hdr_text =
        std::str::from_utf8(&raw[..hdr_end]).context_utf8("non-UTF8 WebSocket HTTP response")?;
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
    Ok(Some(hdr_end))
}

/// Parse one RFC 6455 frame header (bounded to `MAX_WS_FRAME_PAYLOAD` = 64 KiB).
pub fn parse_ws_frame_header(avail: &[u8], is_client: bool) -> Result<WsFrameDecision> {
    if avail.len() < 2 {
        return Ok(WsFrameDecision::Incomplete);
    }
    let b0 = avail[0];
    let b1 = avail[1];
    ensure!((b0 & 0x70) == 0, "WebSocket RSV bits must be zero");
    let fin = (b0 & 0x80) != 0;
    let opcode = b0 & 0x0f;
    ensure!(
        matches!(opcode, 0x0..=0x2 | 0x8..=0xA),
        "unsupported WebSocket opcode"
    );
    if opcode >= 0x8 {
        ensure!(fin, "WebSocket control frames must not be fragmented");
    }
    let masked = (b1 & 0x80) != 0;
    // RFC 6455 §5.1: server MUST reject unmasked client frames; client MUST reject masked server frames.
    if is_client && masked {
        bail!("server sent masked WebSocket frame");
    }
    if !is_client && !masked {
        bail!("client sent unmasked WebSocket frame");
    }

    let len_code = usize::from(b1 & 0x7f);
    let (payload_len, mut hdr_len) = if len_code < 126 {
        (len_code, 2usize)
    } else if len_code == 126 {
        if avail.len() < 4 {
            return Ok(WsFrameDecision::Incomplete);
        }
        let n = usize::from(u16::from_be_bytes([avail[2], avail[3]]));
        ensure!(n >= 126, "non-minimal 16-bit WebSocket length encoding");
        (n, 4usize)
    } else {
        if avail.len() < 10 {
            return Ok(WsFrameDecision::Incomplete);
        }
        let mut raw8 = [0u8; 8];
        raw8.copy_from_slice(&avail[2..10]);
        ensure!((raw8[0] & 0x80) == 0, "WebSocket 64-bit length MSB set");
        let n64 = u64::from_be_bytes(raw8);
        ensure!(n64 >= 65536, "non-minimal 64-bit WebSocket length encoding");
        ensure!(
            n64 <= MAX_WS_FRAME_PAYLOAD as u64,
            "WebSocket frame exceeds 64 KiB bound"
        );
        (n64 as usize, 10usize)
    };
    ensure!(
        payload_len <= MAX_WS_FRAME_PAYLOAD,
        "WebSocket frame exceeds 64 KiB bound"
    );
    if opcode >= 0x8 {
        ensure!(
            payload_len <= 125,
            "WebSocket control frame payload > 125 bytes"
        );
        if opcode == 0x8 {
            ensure!(
                payload_len != 1,
                "WebSocket Close frame payload length 1 is invalid"
            );
        }
    }

    let mask_key = if masked {
        if avail.len() < hdr_len + 4 {
            return Ok(WsFrameDecision::Incomplete);
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

    let Some(total_len) = hdr_len.checked_add(payload_len) else {
        bail!("WebSocket frame total length overflow");
    };
    if avail.len() < total_len {
        return Ok(WsFrameDecision::Incomplete);
    }

    Ok(WsFrameDecision::Header(ParsedWsFrameHeader {
        fin,
        opcode,
        mask_key,
        payload_start_rel: hdr_len,
        payload_len,
        total_len,
    }))
}
