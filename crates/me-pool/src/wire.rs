use anyhow::{bail, ensure, Result};
use std::net::{Ipv4Addr, SocketAddrV4};

/// Telegram ME wire opcodes (little-endian u32 on wire).
pub const RPC_NONCE: u32 = 0x7acb_87aa;
pub const RPC_HANDSHAKE: u32 = 0x7682_eef5;
pub const RPC_PROXY_REQ: u32 = 0x36ce_f1ee;
pub const RPC_PROXY_ANS: u32 = 0x4403_da0d;
pub const RPC_SIMPLE_ACK: u32 = 0x3bac_409b;
pub const RPC_CLOSE_EXT: u32 = 0x5eb6_34a2;
pub const RPC_PING: u32 = 0x5730_a2df;
pub const RPC_PONG: u32 = 0x8430_eaa7;

pub const CRYPTO_AES: u32 = 1;
pub const RPC_PADDING_WORD: u32 = 4;

/// `RPC_PROXY_REQ` extra TL constructor (`proxy_tag#db1e26ae`, little-endian on wire).
pub const TL_PROXY_TAG: u32 = 0xdb1e_26ae;
/// Byte length of the `FLAG_HAS_AD_TAG` extra payload after the 4-byte `extra_size` field:
/// `TL_PROXY_TAG` (4) + `tl_encode_bytes(&[u8; 16])` (1 + 16 + 3 = 20) = 24 bytes.
pub const AD_TAG_EXTRA_SIZE: u32 = 24;

/// `RPC_PROXY_REQ` flags (little-endian u32 on wire, verified against MIT `alexbers/mtprotoproxy`
/// and Apache-2.0 `seriyps/mtproto_proxy`).
pub const FLAG_NOT_ENCRYPTED: u32 = 0x0000_0002;
pub const FLAG_HAS_AD_TAG: u32 = 0x0000_0008;
pub const FLAG_MAGIC: u32 = 0x0000_1000;
pub const FLAG_EXTMODE2: u32 = 0x0002_0000;
pub const FLAG_PAD: u32 = 0x0800_0000;
pub const FLAG_INTERMEDIATE: u32 = 0x2000_0000;
pub const FLAG_ABRIDGED: u32 = 0x4000_0000;
pub const FLAG_QUICKACK: u32 = 0x8000_0000;

/// Client MTProto framing transport reported to Telegram ME in `RPC_PROXY_REQ` flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MeClientProto {
    Abridged,
    Intermediate,
    PaddedIntermediate,
}

impl MeClientProto {
    pub const fn wire_flags(self) -> u32 {
        match self {
            Self::Abridged => FLAG_ABRIDGED,
            Self::Intermediate => FLAG_INTERMEDIATE,
            Self::PaddedIntermediate => FLAG_INTERMEDIATE | FLAG_PAD,
        }
    }
}

/// Maximum accepted ME RPC frame size (1 MiB) checked before allocation (INV-08).
pub const MAX_RPC_FRAME_LEN: usize = 1024 * 1024;
pub const MIN_RPC_FRAME_LEN: usize = 12;

/// Pack a framed RPC packet: `[len: u32 LE][seq_no: i32 LE][payload][crc32: u32 LE]`
/// plus optional 4-byte `0x00000004` padding words to align to 16 bytes for AES-CBC.
pub fn pack_rpc_frame(seq_no: i32, payload: &[u8], pad_to_16: bool) -> Result<Vec<u8>> {
    ensure!(
        payload.len().is_multiple_of(4),
        "ME RPC payload length {} must be 4-byte aligned",
        payload.len()
    );
    let total_len = MIN_RPC_FRAME_LEN
        .checked_add(payload.len())
        .ok_or_else(|| anyhow::anyhow!("RPC frame length overflow"))?;
    ensure!(
        total_len <= MAX_RPC_FRAME_LEN,
        "RPC frame length {total_len} exceeds bound {MAX_RPC_FRAME_LEN}"
    );
    let pad_bytes = if pad_to_16 {
        (16 - (total_len % 16)) % 16
    } else {
        0
    };
    let mut out = Vec::with_capacity(total_len + pad_bytes);
    out.extend_from_slice(&(total_len as u32).to_le_bytes());
    out.extend_from_slice(&seq_no.to_le_bytes());
    out.extend_from_slice(payload);
    let crc = crc32fast::hash(&out);
    out.extend_from_slice(&crc.to_le_bytes());
    for _ in 0..(pad_bytes / 4) {
        out.extend_from_slice(&RPC_PADDING_WORD.to_le_bytes());
    }
    Ok(out)
}

/// Try to decode one complete RPC frame from `buf`, stripping leading `0x00000004` padding words.
/// Returns `Ok(None)` when more bytes are needed; returns `Err` on malformed length or CRC32 mismatch.
pub fn decode_rpc_frame(buf: &mut Vec<u8>) -> Result<Option<(i32, Vec<u8>)>> {
    let mut offset = 0usize;
    while buf.len().saturating_sub(offset) >= 4 {
        let word = u32::from_le_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]);
        if word == RPC_PADDING_WORD {
            offset += 4;
            continue;
        }
        let total_len = word as usize;
        ensure!(
            (MIN_RPC_FRAME_LEN..=MAX_RPC_FRAME_LEN).contains(&total_len)
                && total_len.is_multiple_of(4),
            "invalid ME RPC frame length {total_len}"
        );
        if buf.len().saturating_sub(offset) < total_len {
            if offset > 0 {
                buf.drain(..offset);
            }
            return Ok(None);
        }
        let frame = &buf[offset..offset + total_len];
        let crc_exp = crc32fast::hash(&frame[..total_len - 4]);
        let crc_got = u32::from_le_bytes([
            frame[total_len - 4],
            frame[total_len - 3],
            frame[total_len - 2],
            frame[total_len - 1],
        ]);
        ensure!(
            crc_got == crc_exp,
            "ME RPC CRC32 mismatch (got=0x{crc_got:08x}, exp=0x{crc_exp:08x})"
        );
        let seq_no = i32::from_le_bytes([frame[4], frame[5], frame[6], frame[7]]);
        let payload = frame[8..total_len - 4].to_vec();
        buf.drain(..offset + total_len);
        return Ok(Some((seq_no, payload)));
    }
    if offset > 0 {
        buf.drain(..offset);
    }
    Ok(None)
}

/// Encode IPv4 address as 16-byte IPv4-mapped IPv6 (`::ffff:a.b.c.d`).
pub fn ipv4_mapped_16(ip: Ipv4Addr) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[10] = 0xff;
    out[11] = 0xff;
    out[12..16].copy_from_slice(&ip.octets());
    out
}

/// Encode a byte slice using MTProto TL bytes encoding (4-byte aligned).
pub fn tl_encode_bytes(data: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        data.len() < (1 << 24),
        "TL bytes length exceeds 24-bit limit"
    );
    let mut out = Vec::with_capacity(data.len() + 8);
    if data.len() < 254 {
        out.push(data.len() as u8);
    } else {
        out.push(254);
        out.push((data.len() & 0xff) as u8);
        out.push(((data.len() >> 8) & 0xff) as u8);
        out.push(((data.len() >> 16) & 0xff) as u8);
    }
    out.extend_from_slice(data);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    Ok(out)
}

pub fn encode_nonce(key_selector: [u8; 4], ts: u32, nonce: &[u8; 16]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..4].copy_from_slice(&RPC_NONCE.to_le_bytes());
    out[4..8].copy_from_slice(&key_selector);
    out[8..12].copy_from_slice(&CRYPTO_AES.to_le_bytes());
    out[12..16].copy_from_slice(&ts.to_le_bytes());
    out[16..32].copy_from_slice(nonce);
    out
}

pub fn encode_handshake(flags: u32, sender_pid: &[u8; 12], peer_pid: &[u8; 12]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..4].copy_from_slice(&RPC_HANDSHAKE.to_le_bytes());
    out[4..8].copy_from_slice(&flags.to_le_bytes());
    out[8..20].copy_from_slice(sender_pid);
    out[20..32].copy_from_slice(peer_pid);
    out
}

pub fn encode_proxy_req(
    conn_id: u64,
    remote_addr: Option<SocketAddrV4>,
    our_addr: SocketAddrV4,
    proto: MeClientProto,
    quick_ack: bool,
    ad_tag: Option<&[u8; 16]>,
    mtproto_payload: &[u8],
) -> Result<Vec<u8>> {
    ensure!(
        mtproto_payload.len().is_multiple_of(4),
        "MTProto payload length {} must be 4-byte aligned",
        mtproto_payload.len()
    );
    let mut flags = FLAG_MAGIC | FLAG_EXTMODE2 | proto.wire_flags();
    if quick_ack {
        flags |= FLAG_QUICKACK;
    }
    if mtproto_payload.len() >= 8 && mtproto_payload[..8] == [0u8; 8] {
        flags |= FLAG_NOT_ENCRYPTED;
    }
    let extra = match ad_tag {
        Some(tag) => {
            flags |= FLAG_HAS_AD_TAG;
            let tl_tag = tl_encode_bytes(tag)?;
            let mut section = Vec::with_capacity(8 + tl_tag.len());
            section.extend_from_slice(&AD_TAG_EXTRA_SIZE.to_le_bytes());
            section.extend_from_slice(&TL_PROXY_TAG.to_le_bytes());
            section.extend_from_slice(&tl_tag);
            section
        }
        None => Vec::new(),
    };
    let remote = remote_addr.unwrap_or_else(|| SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
    let mut out = Vec::with_capacity(56 + extra.len() + mtproto_payload.len());
    out.extend_from_slice(&RPC_PROXY_REQ.to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&conn_id.to_le_bytes());
    out.extend_from_slice(&ipv4_mapped_16(*remote.ip()));
    out.extend_from_slice(&u32::from(remote.port()).to_le_bytes());
    out.extend_from_slice(&ipv4_mapped_16(*our_addr.ip()));
    out.extend_from_slice(&u32::from(our_addr.port()).to_le_bytes());
    out.extend_from_slice(&extra);
    out.extend_from_slice(mtproto_payload);
    Ok(out)
}

pub fn encode_close_ext(conn_id: u64) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[0..4].copy_from_slice(&RPC_CLOSE_EXT.to_le_bytes());
    out[4..12].copy_from_slice(&conn_id.to_le_bytes());
    out
}

pub fn encode_ping(ping_id: i64) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[0..4].copy_from_slice(&RPC_PING.to_le_bytes());
    out[4..12].copy_from_slice(&ping_id.to_le_bytes());
    out
}

pub fn encode_pong(ping_id: i64) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[0..4].copy_from_slice(&RPC_PONG.to_le_bytes());
    out[4..12].copy_from_slice(&ping_id.to_le_bytes());
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RpcMessage {
    Nonce {
        key_selector: [u8; 4],
        schema: u32,
        ts: u32,
        nonce: [u8; 16],
    },
    Handshake {
        flags: u32,
        sender_pid: [u8; 12],
        peer_pid: [u8; 12],
    },
    ProxyAns {
        flags: u32,
        conn_id: u64,
        payload: Vec<u8>,
    },
    SimpleAck {
        conn_id: u64,
        confirm_key: u32,
    },
    CloseExt {
        conn_id: u64,
    },
    Ping {
        ping_id: i64,
    },
    Pong {
        ping_id: i64,
    },
    Unknown {
        op: u32,
    },
}

pub fn parse_rpc_message(payload: &[u8]) -> Result<RpcMessage> {
    ensure!(payload.len() >= 4, "ME RPC payload shorter than 4 bytes");
    let op = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    match op {
        RPC_NONCE => {
            ensure!(payload.len() >= 32, "RPC_NONCE shorter than 32 bytes");
            let mut key_selector = [0u8; 4];
            key_selector.copy_from_slice(&payload[4..8]);
            let schema = u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]);
            let ts = u32::from_le_bytes([payload[12], payload[13], payload[14], payload[15]]);
            let mut nonce = [0u8; 16];
            nonce.copy_from_slice(&payload[16..32]);
            Ok(RpcMessage::Nonce {
                key_selector,
                schema,
                ts,
                nonce,
            })
        }
        RPC_HANDSHAKE => {
            ensure!(payload.len() >= 32, "RPC_HANDSHAKE shorter than 32 bytes");
            let flags = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
            let mut sender_pid = [0u8; 12];
            sender_pid.copy_from_slice(&payload[8..20]);
            let mut peer_pid = [0u8; 12];
            peer_pid.copy_from_slice(&payload[20..32]);
            Ok(RpcMessage::Handshake {
                flags,
                sender_pid,
                peer_pid,
            })
        }
        RPC_PROXY_ANS => {
            ensure!(payload.len() >= 16, "RPC_PROXY_ANS shorter than 16 bytes");
            let flags = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
            let conn_id = u64::from_le_bytes([
                payload[8],
                payload[9],
                payload[10],
                payload[11],
                payload[12],
                payload[13],
                payload[14],
                payload[15],
            ]);
            Ok(RpcMessage::ProxyAns {
                flags,
                conn_id,
                payload: payload[16..].to_vec(),
            })
        }
        RPC_SIMPLE_ACK => {
            ensure!(payload.len() >= 16, "RPC_SIMPLE_ACK shorter than 16 bytes");
            let conn_id = u64::from_le_bytes([
                payload[4],
                payload[5],
                payload[6],
                payload[7],
                payload[8],
                payload[9],
                payload[10],
                payload[11],
            ]);
            let confirm_key =
                u32::from_le_bytes([payload[12], payload[13], payload[14], payload[15]]);
            Ok(RpcMessage::SimpleAck {
                conn_id,
                confirm_key,
            })
        }
        RPC_CLOSE_EXT => {
            ensure!(payload.len() >= 12, "RPC_CLOSE_EXT shorter than 12 bytes");
            let conn_id = u64::from_le_bytes([
                payload[4],
                payload[5],
                payload[6],
                payload[7],
                payload[8],
                payload[9],
                payload[10],
                payload[11],
            ]);
            Ok(RpcMessage::CloseExt { conn_id })
        }
        RPC_PING => {
            ensure!(payload.len() >= 12, "RPC_PING shorter than 12 bytes");
            let ping_id = i64::from_le_bytes([
                payload[4],
                payload[5],
                payload[6],
                payload[7],
                payload[8],
                payload[9],
                payload[10],
                payload[11],
            ]);
            Ok(RpcMessage::Ping { ping_id })
        }
        RPC_PONG => {
            ensure!(payload.len() >= 12, "RPC_PONG shorter than 12 bytes");
            let ping_id = i64::from_le_bytes([
                payload[4],
                payload[5],
                payload[6],
                payload[7],
                payload[8],
                payload[9],
                payload[10],
                payload[11],
            ]);
            Ok(RpcMessage::Pong { ping_id })
        }
        other => Ok(RpcMessage::Unknown { op: other }),
    }
}

/// Build an unencrypted MTProto `req_pq_multi` message (40 bytes) for live ME health/spike checks.
pub fn build_req_pq_multi(nonce: &[u8; 16], now_secs: u64) -> [u8; 40] {
    let msg_id = (now_secs << 32) & !3u64;
    let mut out = [0u8; 40];
    out[8..16].copy_from_slice(&msg_id.to_le_bytes());
    out[16..20].copy_from_slice(&20u32.to_le_bytes());
    out[20..24].copy_from_slice(&[0xf1, 0x8e, 0x7e, 0xbe]);
    out[24..40].copy_from_slice(nonce);
    out
}

/// Validate a `resPQ#05162463` unencrypted MTProto response matching `expected_nonce`.
pub fn validate_res_pq(payload: &[u8], expected_nonce: &[u8; 16]) -> Result<()> {
    if payload.len() < 40 {
        bail!("resPQ reply too short ({} bytes)", payload.len());
    }
    ensure!(payload[0..8] == [0u8; 8], "non-zero auth_key_id in resPQ");
    ensure!(
        payload[20..24] == [0x63, 0x24, 0x16, 0x05],
        "unexpected MTProto constructor in resPQ"
    );
    ensure!(&payload[24..40] == expected_nonce, "resPQ nonce mismatch");
    Ok(())
}
