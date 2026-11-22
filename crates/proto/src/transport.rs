//! Bounded MTProto client inner transport framing codecs (`abridged`, `intermediate`,
//! `padded-intermediate`) and quick-ack encoding (INV-08: length bounds checked before allocation).
use anyhow::{bail, ensure, Result};

/// Maximum accepted MTProto client frame payload length (1 MiB, INV-08).
pub const MAX_MTPROTO_FRAME_LEN: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientProtoKind {
    Abridged,
    Intermediate,
    PaddedIntermediate,
}

impl ClientProtoKind {
    pub fn from_tag(tag: [u8; 4]) -> Option<Self> {
        match tag {
            [0xef, 0xef, 0xef, 0xef] => Some(Self::Abridged),
            [0xee, 0xee, 0xee, 0xee] => Some(Self::Intermediate),
            [0xdd, 0xdd, 0xdd, 0xdd] => Some(Self::PaddedIntermediate),
            _ => None,
        }
    }

    pub fn tag(self) -> [u8; 4] {
        match self {
            Self::Abridged => [0xef; 4],
            Self::Intermediate => [0xee; 4],
            Self::PaddedIntermediate => [0xdd; 4],
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Abridged => "abridged",
            Self::Intermediate => "intermediate",
            Self::PaddedIntermediate => "padded-intermediate",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientFrame {
    pub payload: Vec<u8>,
    pub quick_ack: bool,
}

/// Decode one complete MTProto frame from decrypted client stream buffer `buf`.
/// Returns `Ok(None)` when more bytes are needed, or `Err` on malformed/oversized length
/// before allocating the payload (INV-08).
pub fn decode_client_frame(
    kind: ClientProtoKind,
    buf: &mut Vec<u8>,
) -> Result<Option<ClientFrame>> {
    match kind {
        ClientProtoKind::Abridged => {
            if buf.is_empty() {
                return Ok(None);
            }
            let b0 = buf[0];
            let quick_ack = (b0 & 0x80) != 0;
            let len_tag = b0 & 0x7f;
            let (header_len, len_words) = if len_tag < 0x7f {
                (1usize, usize::from(len_tag))
            } else {
                if buf.len() < 4 {
                    return Ok(None);
                }
                let words =
                    usize::from(buf[1]) | (usize::from(buf[2]) << 8) | (usize::from(buf[3]) << 16);
                (4usize, words)
            };
            let payload_len = len_words
                .checked_mul(4)
                .ok_or_else(|| anyhow::anyhow!("abridged frame length overflow"))?;
            ensure!(
                (4..=MAX_MTPROTO_FRAME_LEN).contains(&payload_len),
                "abridged frame length {payload_len} out of bounds"
            );
            let total_needed = header_len
                .checked_add(payload_len)
                .ok_or_else(|| anyhow::anyhow!("abridged total length overflow"))?;
            if buf.len() < total_needed {
                return Ok(None);
            }
            let payload = buf[header_len..total_needed].to_vec();
            buf.drain(..total_needed);
            Ok(Some(ClientFrame { payload, quick_ack }))
        }
        ClientProtoKind::Intermediate => {
            if buf.len() < 4 {
                return Ok(None);
            }
            let raw_len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
            let quick_ack = (raw_len & 0x8000_0000) != 0;
            let payload_len = (raw_len & 0x7fff_ffff) as usize;
            ensure!(
                (4..=MAX_MTPROTO_FRAME_LEN).contains(&payload_len) && payload_len.is_multiple_of(4),
                "intermediate frame length {payload_len} out of bounds or unaligned"
            );
            let total_needed = 4usize
                .checked_add(payload_len)
                .ok_or_else(|| anyhow::anyhow!("intermediate total length overflow"))?;
            if buf.len() < total_needed {
                return Ok(None);
            }
            let payload = buf[4..total_needed].to_vec();
            buf.drain(..total_needed);
            Ok(Some(ClientFrame { payload, quick_ack }))
        }
        ClientProtoKind::PaddedIntermediate => {
            if buf.len() < 4 {
                return Ok(None);
            }
            let raw_len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
            let quick_ack = (raw_len & 0x8000_0000) != 0;
            let total_payload_len = (raw_len & 0x7fff_ffff) as usize;
            ensure!(
                (4..=MAX_MTPROTO_FRAME_LEN + 15).contains(&total_payload_len),
                "padded-intermediate frame length {total_payload_len} out of bounds"
            );
            let aligned_len = total_payload_len & !3;
            ensure!(
                (4..=MAX_MTPROTO_FRAME_LEN).contains(&aligned_len),
                "padded-intermediate aligned length {aligned_len} out of bounds"
            );
            let total_needed = 4usize
                .checked_add(total_payload_len)
                .ok_or_else(|| anyhow::anyhow!("padded-intermediate total length overflow"))?;
            if buf.len() < total_needed {
                return Ok(None);
            }
            let raw_slice = &buf[4..4 + total_payload_len];
            // Unencrypted MTProto handshake messages (auth_key_id == 0) carry an exact
            // message_data_length at bytes 16..20; strip full 0..=15 padding when it matches.
            let final_len = if total_payload_len >= 20 && raw_slice[..8] == [0u8; 8] {
                let msg_len = u32::from_le_bytes([
                    raw_slice[16],
                    raw_slice[17],
                    raw_slice[18],
                    raw_slice[19],
                ]) as usize;
                let exact = 20usize.saturating_add(msg_len);
                if exact >= 20
                    && exact.is_multiple_of(4)
                    && exact <= total_payload_len
                    && total_payload_len - exact <= 15
                {
                    exact
                } else {
                    aligned_len
                }
            } else {
                aligned_len
            };
            let payload = raw_slice[..final_len].to_vec();
            buf.drain(..total_needed);
            Ok(Some(ClientFrame { payload, quick_ack }))
        }
    }
}

/// Encode an MTProto payload into the client's transport frame (plaintext, prior to obfuscated2 AES-CTR).
/// For `PaddedIntermediate`, `pad_bytes` (0..=15 random bytes) is appended after `payload`.
pub fn encode_client_frame(
    kind: ClientProtoKind,
    payload: &[u8],
    pad_bytes: &[u8],
) -> Result<Vec<u8>> {
    ensure!(
        (4..=MAX_MTPROTO_FRAME_LEN).contains(&payload.len()) && payload.len().is_multiple_of(4),
        "MTProto payload length {} invalid for encoding",
        payload.len()
    );
    match kind {
        ClientProtoKind::Abridged => {
            let words = payload.len() / 4;
            if words < 0x7f {
                let mut out = Vec::with_capacity(1 + payload.len());
                out.push(words as u8);
                out.extend_from_slice(payload);
                Ok(out)
            } else if words <= 0x00ff_ffff {
                let mut out = Vec::with_capacity(4 + payload.len());
                out.push(0x7f);
                out.push((words & 0xff) as u8);
                out.push(((words >> 8) & 0xff) as u8);
                out.push(((words >> 16) & 0xff) as u8);
                out.extend_from_slice(payload);
                Ok(out)
            } else {
                bail!("abridged frame exceeds 24-bit word limit");
            }
        }
        ClientProtoKind::Intermediate => {
            let mut out = Vec::with_capacity(4 + payload.len());
            out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            out.extend_from_slice(payload);
            Ok(out)
        }
        ClientProtoKind::PaddedIntermediate => {
            let pad = &pad_bytes[..pad_bytes.len().min(15)];
            let total_len = payload.len() + pad.len();
            let mut out = Vec::with_capacity(4 + total_len);
            out.extend_from_slice(&(total_len as u32).to_le_bytes());
            out.extend_from_slice(payload);
            out.extend_from_slice(pad);
            Ok(out)
        }
    }
}

/// Encode a 4-byte quick-ack token (`RPC_SIMPLE_ACK`) into the client's transport format.
pub fn encode_quick_ack(kind: ClientProtoKind, confirm_key: u32) -> [u8; 4] {
    let token = confirm_key | 0x8000_0000;
    match kind {
        ClientProtoKind::Abridged => token.to_be_bytes(),
        ClientProtoKind::Intermediate | ClientProtoKind::PaddedIntermediate => token.to_le_bytes(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_three_transports_fragmented_and_large() -> Result<()> {
        for kind in [
            ClientProtoKind::Abridged,
            ClientProtoKind::Intermediate,
            ClientProtoKind::PaddedIntermediate,
        ] {
            for size in [4usize, 64, 512, 65536] {
                let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
                let pad = if kind == ClientProtoKind::PaddedIntermediate {
                    &[0xaa, 0xbb, 0xcc][..]
                } else {
                    &[][..]
                };
                let mut encoded = encode_client_frame(kind, &payload, pad)?;
                // Set quick-ack bit on header to test quick-ack flag decoding.
                match kind {
                    ClientProtoKind::Abridged => encoded[0] |= 0x80,
                    ClientProtoKind::Intermediate | ClientProtoKind::PaddedIntermediate => {
                        encoded[3] |= 0x80;
                    }
                }
                // Feed byte-by-byte to verify arbitrary fragmentation handling.
                let mut buf = Vec::new();
                let mut decoded = None;
                for &b in &encoded {
                    buf.push(b);
                    if let Some(frame) = decode_client_frame(kind, &mut buf)? {
                        decoded = Some(frame);
                        break;
                    }
                }
                let frame = decoded.ok_or_else(|| anyhow::anyhow!("missing decoded frame"))?;
                assert_eq!(frame.payload, payload);
                assert!(frame.quick_ack);
                assert!(buf.is_empty());
            }
        }
        Ok(())
    }

    #[test]
    fn inv08_oversized_and_malformed_frames_rejected_before_alloc() {
        // Abridged: 0-length and > 1 MiB
        assert!(decode_client_frame(ClientProtoKind::Abridged, &mut vec![0x00]).is_err());
        assert!(decode_client_frame(
            ClientProtoKind::Abridged,
            &mut vec![0x7f, 0x01, 0x00, 0x04] // 0x040001 * 4 > 1 MiB
        )
        .is_err());
        // Intermediate: unaligned and > 1 MiB
        assert!(decode_client_frame(
            ClientProtoKind::Intermediate,
            &mut 5u32.to_le_bytes().to_vec()
        )
        .is_err());
        assert!(decode_client_frame(
            ClientProtoKind::Intermediate,
            &mut ((MAX_MTPROTO_FRAME_LEN as u32) + 4).to_le_bytes().to_vec()
        )
        .is_err());
        // PaddedIntermediate: < 4 and > 1 MiB + 15
        assert!(decode_client_frame(
            ClientProtoKind::PaddedIntermediate,
            &mut 3u32.to_le_bytes().to_vec()
        )
        .is_err());
        assert!(decode_client_frame(
            ClientProtoKind::PaddedIntermediate,
            &mut ((MAX_MTPROTO_FRAME_LEN as u32) + 16).to_le_bytes().to_vec()
        )
        .is_err());
    }

    #[test]
    fn quick_ack_encoding_sets_msb_in_wire_order() {
        let ab = encode_quick_ack(ClientProtoKind::Abridged, 0x1234_5678);
        assert_eq!(ab[0] & 0x80, 0x80);
        assert_eq!(u32::from_be_bytes(ab), 0x9234_5678);

        let im = encode_quick_ack(ClientProtoKind::Intermediate, 0x1234_5678);
        assert_eq!(im[3] & 0x80, 0x80);
        assert_eq!(u32::from_le_bytes(im), 0x9234_5678);

        let pi = encode_quick_ack(ClientProtoKind::PaddedIntermediate, 0x1234_5678);
        assert_eq!(pi, im);
    }
}
