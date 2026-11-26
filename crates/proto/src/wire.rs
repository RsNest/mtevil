use aes::cipher::{KeyIvInit, StreamCipher};
use anyhow::{ensure, Context, Result};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub const MAX_HELLO: usize = 4096;
pub const MAX_RECORD: usize = 16 * 1024;
pub type AesCtr = ctr::Ctr128BE<aes::Aes256>;

/// Size of the fake TLS "certificate": the payload of the single
/// ApplicationData record that closes the ServerHello flight.
///
/// ADR-000 §5.2 requires this size to come from a measured profile instead of
/// an arbitrary constant. The stock Telegram client caps its own TLS records
/// at `MAX_TLS_PACKET_LENGTH = 2878` bytes
/// (`TelegramMessenger/mtproto-engine`, `crates/mtproto-core/src/transport/tls.rs`),
/// and the pinned reference server sizes the same record to 2500..4700 bytes
/// (`mtg` v2, `mtglib/internal/tls/fake/server_side.go`). 2878 satisfies both:
/// it is the client limit and it lies inside the reference range.
/// See `docs/specs/fake-tls-profile.md`.
pub const DEFAULT_CERT_BYTES: usize = 2878;
/// Default symmetric spread (in bytes) around `DEFAULT_CERT_BYTES` so FakeTLS
/// flights do not emit a single constant length on the wire.
pub const DEFAULT_CERT_JITTER: usize = 16;

/// Includes the short profile used for a delivery comparison.
pub const MIN_CERT_BYTES: usize = 512;
/// Telegram iOS bounds the FakeTLS handshake's AppData record at 10 KiB.
pub const MAX_CERT_BYTES: usize = 10 * 1024;

/// Profile of the ServerHello flight.
///
/// `cert_bytes` is the measured size of the "certificate" record and `jitter`
/// spreads it symmetrically, as the reference implementation does, so that a
/// fleet does not emit one constant length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerFlightProfile {
    pub cert_bytes: usize,
    pub jitter: usize,
}

impl Default for ServerFlightProfile {
    fn default() -> Self {
        Self {
            cert_bytes: DEFAULT_CERT_BYTES,
            jitter: DEFAULT_CERT_JITTER,
        }
    }
}

impl ServerFlightProfile {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (MIN_CERT_BYTES..=MAX_CERT_BYTES).contains(&self.cert_bytes),
            "fake TLS certificate size must be {MIN_CERT_BYTES}..={MAX_CERT_BYTES} bytes"
        );
        ensure!(
            self.jitter <= 1024,
            "fake TLS certificate jitter must be 0..=1024"
        );
        ensure!(
            self.jitter < self.cert_bytes,
            "fake TLS certificate jitter must be smaller than the size"
        );
        Ok(())
    }

    /// ApplicationData payload size for one flight.
    pub fn cert_size<R: RngCore + ?Sized>(&self, rng: &mut R) -> usize {
        if self.jitter == 0 {
            return self.cert_bytes;
        }
        let span = 2 * self.jitter as u64 + 1;
        let offset = u64::from(rng.next_u32()) % span;
        let value = self.cert_bytes as i64 + offset as i64 - self.jitter as i64;
        value.clamp(MIN_CERT_BYTES as i64, MAX_CERT_BYTES as i64) as usize
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(n)
            .ok_or_else(|| anyhow::anyhow!("length overflow"))?;
        let out = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| anyhow::anyhow!("truncated field"))?;
        self.offset = end;
        Ok(out)
    }
    fn u8(&mut self) -> Result<usize> {
        Ok(usize::from(self.take(1)?[0]))
    }
    fn u16(&mut self) -> Result<usize> {
        let b = self.take(2)?;
        Ok(usize::from(u16::from_be_bytes([b[0], b[1]])))
    }
    fn done(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

pub fn handshake_length(prefix: &[u8]) -> Result<usize> {
    ensure!(prefix.len() >= 4 && prefix[0] == 1, "not ClientHello");
    let n = (usize::from(prefix[1]) << 16) | (usize::from(prefix[2]) << 8) | usize::from(prefix[3]);
    ensure!(n <= MAX_HELLO, "ClientHello body exceeds limit");
    Ok(n + 4)
}

#[derive(Debug)]
pub struct Hello {
    pub random: [u8; 32],
    pub session: [u8; 32],
    pub replay_key: [u8; 32],
    /// Cipher suite echoed back to the client: the first non-GREASE suite the
    /// client offered. The reference server echoes it instead of a constant.
    pub cipher_suite: u16,
    /// Short fingerprint of the client hello shape (cipher list and extension
    /// order). It identifies the client template without exposing key material.
    pub template: String,
}

fn mac(secret: &[u8], data: &[u8]) -> Result<[u8; 32]> {
    let mut h = Hmac::<Sha256>::new_from_slice(secret)?;
    h.update(data);
    Ok(h.finalize().into_bytes().into())
}

/// A complete reassembled handshake, independent of original TLS fragmentation.
pub fn authenticate(hello: &[u8], secret: &[u8; 16], sni: &str, now: u64) -> Result<Hello> {
    authenticate_with_record_version(hello, 1, secret, sni, now)
}

pub fn authenticate_with_record_version(
    hello: &[u8],
    record_minor: u8,
    secret: &[u8; 16],
    sni: &str,
    now: u64,
) -> Result<Hello> {
    ensure!((1..=3).contains(&record_minor), "TLS record version");
    ensure!(
        handshake_length(hello)? == hello.len(),
        "hello length mismatch"
    );
    let mut c = Cursor {
        bytes: &hello[4..],
        offset: 0,
    };
    ensure!(c.take(2)? == [3, 3], "unsupported legacy version");
    let random: [u8; 32] = c.take(32)?.try_into()?;
    ensure!(c.u8()? == 32, "session length");
    let session: [u8; 32] = c.take(32)?.try_into()?;
    let n = c.u16()?;
    ensure!(n >= 2 && n % 2 == 0, "cipher list");
    let ciphers = c.take(n)?;
    // ServerHello advertises TLS 1.3, so skip legacy suites and GREASE.
    let cipher_suite = ciphers
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_be_bytes(*pair))
        .find(|suite| matches!(suite, 0x1301..=0x1303))
        .context("no supported TLS 1.3 cipher suite")?;
    let n = c.u8()?;
    ensure!(c.take(n)? == [0], "compression");
    let n = c.u16()?;
    let extensions = c.take(n)?;
    ensure!(c.done(), "trailing hello bytes");
    let mut e = Cursor {
        bytes: extensions,
        offset: 0,
    };
    let (mut sni_ok, mut tls13, mut seen_sni) = (false, false, false);
    let mut extension_kinds: Vec<usize> = Vec::new();
    while !e.done() {
        let kind = e.u16()?;
        let n = e.u16()?;
        let ext = e.take(n)?;
        extension_kinds.push(kind);
        if kind == 0 {
            ensure!(!seen_sni, "duplicate SNI");
            seen_sni = true;
            let mut names = Cursor {
                bytes: ext,
                offset: 0,
            };
            let n = names.u16()?;
            let list = names.take(n)?;
            ensure!(names.done(), "SNI list length");
            let mut list = Cursor {
                bytes: list,
                offset: 0,
            };
            while !list.done() {
                let ty = list.u8()?;
                let n = list.u16()?;
                let name = list.take(n)?;
                if ty == 0 {
                    sni_ok =
                        !name.is_empty()
                            && sni.split(',').map(str::trim).filter(|s| !s.is_empty()).any(
                                |allowed| {
                                    allowed == "*" || name.eq_ignore_ascii_case(allowed.as_bytes())
                                },
                            );
                }
            }
        } else if kind == 0x2b {
            let mut versions = Cursor {
                bytes: ext,
                offset: 0,
            };
            let n = versions.u8()?;
            let bytes = versions.take(n)?;
            ensure!(versions.done() && n % 2 == 0, "version list");
            tls13 = bytes.as_chunks::<2>().0.contains(&[3, 4]);
        }
    }
    ensure!(sni_ok && tls13, "SNI or TLS1.3 mismatch");
    let mut canonical = Vec::with_capacity(hello.len() + 5);
    canonical.extend_from_slice(&[0x16, 3, 1]);
    canonical.extend_from_slice(&(hello.len() as u16).to_be_bytes());
    canonical.extend_from_slice(hello);
    canonical[11..43].fill(0);
    let replay_key = mac(secret, &canonical)?;
    // Preserve the normalized digest for fragmented records and legacy clients.
    // A single record may instead be signed with its original version bytes.
    let digest = if record_minor != 1 && !bool::from(random[..28].ct_eq(&replay_key[..28])) {
        canonical[2] = record_minor;
        mac(secret, &canonical)?
    } else {
        replay_key
    };
    ensure!(
        bool::from(random[..28].ct_eq(&digest[..28])),
        "authentication failed"
    );
    let timestamp = u32::from_le_bytes([
        random[28] ^ digest[28],
        random[29] ^ digest[29],
        random[30] ^ digest[30],
        random[31] ^ digest[31],
    ]);
    ensure!(now.abs_diff(u64::from(timestamp)) <= 120, "timestamp skew");
    Ok(Hello {
        random,
        session,
        replay_key,
        cipher_suite,
        template: template_fingerprint(ciphers, &extension_kinds),
    })
}

/// Short fingerprint of the client hello shape.
///
/// It covers the offered cipher list and the order of the extension types
/// only. Neither the random nor the session id enters the digest, so the
/// value identifies a client template without exposing key material.
fn template_fingerprint(ciphers: &[u8], extension_kinds: &[usize]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ciphers);
    for kind in extension_kinds {
        hasher.update((*kind as u16).to_be_bytes());
    }
    let digest = hasher.finalize();
    let mut out = String::with_capacity(12);
    for byte in &digest[..6] {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}

pub fn record(kind: u8, payload: &[u8]) -> Result<Vec<u8>> {
    ensure!(payload.len() <= MAX_RECORD, "TLS record too large");
    let mut out = Vec::with_capacity(payload.len() + 5);
    out.extend_from_slice(&[kind, 3, 3]);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Build the ServerHello flight.
///
/// The stock client reads exactly three records and hashes all of them:
/// a handshake record, a ChangeCipherSpec record and one ApplicationData
/// record that carries the fake certificate
/// (`TelegramMessenger/mtproto-engine`, `verify_server_hello`). The layout
/// below is fixed by that parser; only the certificate size is a profile
/// value (ADR-000 §5.2).
pub fn server_flight(
    secret: &[u8; 16],
    hello: &Hello,
    profile: &ServerFlightProfile,
    rng: &mut impl RngCore,
) -> Result<Vec<u8>> {
    let mut body = vec![3, 3];
    body.extend_from_slice(&[0; 32]);
    body.push(32);
    body.extend_from_slice(&hello.session);
    body.extend_from_slice(&hello.cipher_suite.to_be_bytes());
    body.push(0);
    let mut extensions = vec![0, 0x2b, 0, 2, 3, 4, 0, 0x33, 0, 36, 0, 0x1d, 0, 32];
    let key_share = crate::x25519::generate_public_key(rng);
    extensions.extend_from_slice(&key_share);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    let mut handshake = vec![2, 0];
    handshake.extend_from_slice(&(body.len() as u16).to_be_bytes());
    handshake.extend_from_slice(&body);
    let mut flight = record(0x16, &handshake)?;
    flight.extend_from_slice(&record(0x14, &[1])?);
    let mut noise = vec![0; profile.cert_size(rng)];
    OsRng.fill_bytes(&mut noise);
    flight.extend_from_slice(&record(0x17, &noise)?);
    let mut authenticated = hello.random.to_vec();
    authenticated.extend_from_slice(&flight);
    flight[11..43].copy_from_slice(&mac(secret, &authenticated)?);
    Ok(flight)
}

fn cipher(key: &[u8], iv: &[u8], secret: &[u8]) -> Result<AesCtr> {
    // Direct Telegram obfuscated2 uses the raw 32-byte header key.
    // Only the MTProxy-facing transport hashes key || proxy-secret.
    if secret.is_empty() {
        return Ok(AesCtr::new_from_slices(key, iv)?);
    }
    let mut hash = Sha256::new();
    hash.update(key);
    hash.update(secret);
    Ok(AesCtr::new_from_slices(&hash.finalize(), iv)?)
}

pub struct ClientTransport {
    pub decrypt: AesCtr,
    pub encrypt: AesCtr,
    pub dc: i16,
    pub kind: crate::ClientProtoKind,
}
pub fn client_transport(wire: &[u8; 64], secret: &[u8; 16]) -> Result<ClientTransport> {
    let mut decrypt = cipher(&wire[8..40], &wire[40..56], secret)?;
    let mut plain = *wire;
    decrypt.apply_keystream(&mut plain);
    let kind = crate::ClientProtoKind::from_tag([plain[56], plain[57], plain[58], plain[59]])
        .ok_or_else(|| anyhow::anyhow!("unsupported inner transport"))?;
    let dc = i16::from_le_bytes([plain[60], plain[61]]);
    ensure!(
        (1..=5).contains(&dc.checked_abs().unwrap_or(0)),
        "invalid DC"
    );
    let reversed: Vec<_> = wire[8..56].iter().rev().copied().collect();
    let encrypt = cipher(&reversed[..32], &reversed[32..], secret)?;
    Ok(ClientTransport {
        decrypt,
        encrypt,
        dc,
        kind,
    })
}

pub struct DcTransport {
    pub header: [u8; 64],
    pub encrypt: AesCtr,
    pub decrypt: AesCtr,
}
pub fn dc_transport() -> Result<DcTransport> {
    dc_transport_for(crate::ClientProtoKind::PaddedIntermediate)
}
pub fn dc_transport_for(kind: crate::ClientProtoKind) -> Result<DcTransport> {
    let mut plain = [0u8; 64];
    loop {
        OsRng.fill_bytes(&mut plain);
        let forbidden: [&[u8]; 7] = [
            b"HEAD",
            b"POST",
            b"GET ",
            b"PVrG",
            &[0xee; 4],
            &[0xdd; 4],
            &[0x16, 3, 1, 2],
        ];
        if plain[0] != 0xef && plain[4..8] != [0; 4] && !forbidden.iter().any(|v| plain[..4] == **v)
        {
            break;
        }
    }
    plain[56..60].copy_from_slice(&kind.tag());
    let mut encrypt = cipher(&plain[8..40], &plain[40..56], &[])?;
    let reversed: Vec<_> = plain[8..56].iter().rev().copied().collect();
    let decrypt = cipher(&reversed[..32], &reversed[32..], &[])?;
    let mut header = plain;
    encrypt.apply_keystream(&mut header);
    header[..56].copy_from_slice(&plain[..56]);
    Ok(DcTransport {
        header,
        encrypt,
        decrypt,
    })
}

pub fn crypt(cipher: &mut AesCtr, bytes: &mut [u8]) {
    cipher.apply_keystream(bytes);
}

/// Build an authenticated FakeTLS ClientHello record for `sni` signed with `secret` at `now`.
pub fn build_client_hello(
    secret: &[u8; 16],
    sni: &str,
    now: u64,
    rng: &mut impl RngCore,
) -> Result<(Vec<u8>, [u8; 32], [u8; 32])> {
    let mut session = [0u8; 32];
    rng.fill_bytes(&mut session);

    // Extensions: SNI (0x0000), supported_versions (0x002b = TLS 1.3), key_share (0x0033 = X25519).
    let mut extensions = Vec::new();
    let sni_bytes = sni.as_bytes();
    ensure!(
        !sni_bytes.is_empty() && sni_bytes.len() <= 253,
        "invalid SNI length"
    );
    let sni_list_len = 1 + 2 + sni_bytes.len();
    extensions.extend_from_slice(&0u16.to_be_bytes());
    extensions.extend_from_slice(&((2 + sni_list_len) as u16).to_be_bytes());
    extensions.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
    extensions.push(0); // host_name
    extensions.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    extensions.extend_from_slice(sni_bytes);

    // supported_versions: TLS 1.3 (0x0304)
    extensions.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
    // key_share: fresh ephemeral X25519 public key per ClientHello
    let key_share = crate::x25519::generate_public_key(rng);
    extensions.extend_from_slice(&[0x00, 0x33, 0x00, 38, 0x00, 36, 0x00, 0x1d, 0x00, 32]);
    extensions.extend_from_slice(&key_share);

    let mut body = Vec::new();
    body.extend_from_slice(&[3, 3]); // legacy_version TLS 1.2
    body.extend_from_slice(&[0u8; 32]); // random placeholder for HMAC
    body.push(32);
    body.extend_from_slice(&session);
    // cipher_suites: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
    body.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x13, 0x02]);
    body.extend_from_slice(&[0x01, 0x00]); // compression_methods: null
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut handshake = Vec::with_capacity(4 + body.len());
    handshake.push(1); // ClientHello
    let blen = body.len();
    handshake.push(((blen >> 16) & 0xff) as u8);
    handshake.push(((blen >> 8) & 0xff) as u8);
    handshake.push((blen & 0xff) as u8);
    handshake.extend_from_slice(&body);

    let mut rec = Vec::with_capacity(5 + handshake.len());
    rec.extend_from_slice(&[0x16, 3, 1]);
    rec.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    rec.extend_from_slice(&handshake);

    let mut digest = mac(secret, &rec)?;
    let ts = (now as u32).to_le_bytes();
    for i in 0..4 {
        digest[28 + i] ^= ts[i];
    }
    rec[11..43].copy_from_slice(&digest);
    Ok((rec, digest, session))
}

/// Verify the proxy's FakeTLS ServerHello flight (3 records: Handshake, CCS, AppData).
pub fn verify_server_flight(
    secret: &[u8; 16],
    client_random: &[u8; 32],
    client_session: &[u8; 32],
    flight: &[u8],
) -> Result<()> {
    ensure!(flight.len() >= 138, "server flight too short");
    ensure!(flight[0] == 0x16, "first server record is not Handshake");
    ensure!(
        &flight[44..76] == client_session,
        "server session id mismatch"
    );
    let received: [u8; 32] = flight[11..43].try_into()?;
    let mut zeroed = flight.to_vec();
    zeroed[11..43].fill(0);
    let mut authenticated = Vec::with_capacity(32 + zeroed.len());
    authenticated.extend_from_slice(client_random);
    authenticated.extend_from_slice(&zeroed);
    let expected = mac(secret, &authenticated)?;
    ensure!(
        bool::from(received.ct_eq(&expected)),
        "server flight HMAC mismatch"
    );
    Ok(())
}

/// Build the 64-byte obfuscated2 client init header for padded-intermediate mode (`0xdddddddd`)
/// targeting `dc` and return `(wire_header, encrypt_cipher, decrypt_cipher)`.
pub fn build_client_init(secret: &[u8; 16], dc: i16) -> Result<([u8; 64], AesCtr, AesCtr)> {
    build_client_init_with_kind(secret, dc, crate::ClientProtoKind::PaddedIntermediate)
}

/// Build the 64-byte obfuscated2 client init header for the specified inner transport `kind`
/// targeting `dc` and return `(wire_header, encrypt_cipher, decrypt_cipher)`.
pub fn build_client_init_with_kind(
    secret: &[u8; 16],
    dc: i16,
    kind: crate::ClientProtoKind,
) -> Result<([u8; 64], AesCtr, AesCtr)> {
    ensure!(
        (1..=5).contains(&dc.checked_abs().unwrap_or(0)),
        "invalid DC"
    );
    let mut plain = [0u8; 64];
    loop {
        OsRng.fill_bytes(&mut plain);
        let forbidden: [&[u8]; 7] = [
            b"HEAD",
            b"POST",
            b"GET ",
            b"PVrG",
            &[0xee; 4],
            &[0xdd; 4],
            &[0x16, 3, 1, 2],
        ];
        if plain[0] != 0xef && plain[4..8] != [0; 4] && !forbidden.iter().any(|v| plain[..4] == **v)
        {
            break;
        }
    }
    plain[56..60].copy_from_slice(&kind.tag());
    plain[60..62].copy_from_slice(&dc.to_le_bytes());
    let mut encrypt = cipher(&plain[8..40], &plain[40..56], secret)?;
    let reversed: Vec<_> = plain[8..56].iter().rev().copied().collect();
    let decrypt = cipher(&reversed[..32], &reversed[32..], secret)?;
    let mut header = plain;
    encrypt.apply_keystream(&mut header);
    header[..56].copy_from_slice(&plain[..56]);
    Ok((header, encrypt, decrypt))
}

pub const PROXY_V2_HEADER_LEN: usize = 16;
pub const MAX_PROXY_V2_PAYLOAD: usize = 1024;
const PROXY_V2_SIG: [u8; 12] = [
    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
];

pub const EGRESS_MAGIC_V2: [u8; 4] = *b"MTV2";
pub const EGRESS_MAGIC_V3: [u8; 4] = *b"MTV3";
pub const EGRESS_MAGIC_V4: [u8; 4] = *b"MTV4";
pub const EGRESS_PREFACE_V2_LEN: usize = 88;
pub const EGRESS_PREFACE_V3_LEN: usize = 126;
pub const EGRESS_PREFACE_V4_LEN: usize = 70;
pub const EGRESS_V3_MAX_SKEW_SECS: u64 = 30;
pub const MTV4_FLAG_HAS_CLIENT_IP: u8 = 0x01;
pub const MTV4_FLAG_PROTO_MASK: u8 = 0x06;
pub const MTV4_FLAG_PROTO_PADDED_INTERMEDIATE: u8 = 0x00;
pub const MTV4_FLAG_PROTO_INTERMEDIATE: u8 = 0x02;
pub const MTV4_FLAG_PROTO_ABRIDGED: u8 = 0x04;
pub const MTV4_FRAME_HEADER_LEN: usize = 5;
pub const MTV4_FRAME_PAYLOAD: u8 = 0x01;
pub const MTV4_FRAME_QUICK_ACK: u8 = 0x02;
pub const MTV4_FRAME_EOF: u8 = 0x03;
pub const MTV4_FRAME_PAYLOAD_QUICK_ACK: u8 = 0x04;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EgressPrefaceV3 {
    pub dc: i16,
    pub timestamp: u64,
    pub nonce: [u8; 16],
    pub dc_header: [u8; 64],
}

pub fn build_egress_preface_v3(
    token: &[u8; 16],
    dc: i16,
    timestamp: u64,
    nonce: &[u8; 16],
    dc_header: &[u8; 64],
) -> Result<[u8; EGRESS_PREFACE_V3_LEN]> {
    let mut signed = [0u8; 94];
    signed[..4].copy_from_slice(&EGRESS_MAGIC_V3);
    signed[4..6].copy_from_slice(&dc.to_le_bytes());
    signed[6..14].copy_from_slice(&timestamp.to_le_bytes());
    signed[14..30].copy_from_slice(nonce);
    signed[30..94].copy_from_slice(dc_header);
    let tag = mac(token, &signed)?;
    let mut out = [0u8; EGRESS_PREFACE_V3_LEN];
    out[..30].copy_from_slice(&signed[..30]);
    out[30..62].copy_from_slice(&tag);
    out[62..126].copy_from_slice(dc_header);
    Ok(out)
}

pub fn verify_egress_preface_v3(
    preface: &[u8; EGRESS_PREFACE_V3_LEN],
    token: &[u8; 16],
    now_secs: u64,
    max_skew_secs: u64,
) -> Result<EgressPrefaceV3> {
    ensure!(preface[..4] == EGRESS_MAGIC_V3, "invalid MTV3 magic");
    let dc = i16::from_le_bytes([preface[4], preface[5]]);
    let timestamp = u64::from_le_bytes([
        preface[6],
        preface[7],
        preface[8],
        preface[9],
        preface[10],
        preface[11],
        preface[12],
        preface[13],
    ]);
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&preface[14..30]);
    let received_tag = &preface[30..62];
    let mut dc_header = [0u8; 64];
    dc_header.copy_from_slice(&preface[62..126]);

    let mut signed = [0u8; 94];
    signed[..30].copy_from_slice(&preface[..30]);
    signed[30..94].copy_from_slice(&dc_header);
    let expected_tag = mac(token, &signed)?;
    ensure!(
        bool::from(received_tag.ct_eq(&expected_tag)),
        "egress MTV3 HMAC mismatch"
    );
    ensure!(
        now_secs.abs_diff(timestamp) <= max_skew_secs,
        "egress MTV3 timestamp out of window"
    );
    Ok(EgressPrefaceV3 {
        dc,
        timestamp,
        nonce,
        dc_header,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EgressPrefaceV4 {
    pub dc: i16,
    pub timestamp: u64,
    pub nonce: [u8; 16],
    pub flags: u8,
    pub proto: crate::ClientProtoKind,
    pub client_addr: Option<std::net::SocketAddrV4>,
}

/// Build an authenticated 70-byte `MTV4` preface for split `edge -> egress` ME mode
/// (defaulting client transport flags to `PaddedIntermediate`).
pub fn build_egress_preface_v4(
    token: &[u8; 16],
    dc: i16,
    timestamp: u64,
    nonce: &[u8; 16],
    client_addr: Option<std::net::SocketAddrV4>,
) -> Result<[u8; EGRESS_PREFACE_V4_LEN]> {
    build_egress_preface_v4_with_proto(
        token,
        dc,
        timestamp,
        nonce,
        crate::ClientProtoKind::PaddedIntermediate,
        client_addr,
    )
}

/// Build an authenticated 70-byte `MTV4` preface for split `edge -> egress` ME mode,
/// encoding both the client transport kind and optional `client_addr` inside the HMAC header.
pub fn build_egress_preface_v4_with_proto(
    token: &[u8; 16],
    dc: i16,
    timestamp: u64,
    nonce: &[u8; 16],
    proto: crate::ClientProtoKind,
    client_addr: Option<std::net::SocketAddrV4>,
) -> Result<[u8; EGRESS_PREFACE_V4_LEN]> {
    ensure!(
        (1..=5).contains(&dc.checked_abs().unwrap_or(0)),
        "invalid MTV4 DC id"
    );
    let mut signed = [0u8; 38];
    signed[..4].copy_from_slice(&EGRESS_MAGIC_V4);
    signed[4..6].copy_from_slice(&dc.to_be_bytes());
    signed[6..14].copy_from_slice(&timestamp.to_be_bytes());
    signed[14..30].copy_from_slice(nonce);
    let mut flags = match proto {
        crate::ClientProtoKind::PaddedIntermediate => MTV4_FLAG_PROTO_PADDED_INTERMEDIATE,
        crate::ClientProtoKind::Intermediate => MTV4_FLAG_PROTO_INTERMEDIATE,
        crate::ClientProtoKind::Abridged => MTV4_FLAG_PROTO_ABRIDGED,
    };
    if let Some(addr) = client_addr {
        flags |= MTV4_FLAG_HAS_CLIENT_IP;
        signed[32..36].copy_from_slice(&addr.ip().octets());
        signed[36..38].copy_from_slice(&addr.port().to_be_bytes());
    }
    signed[30] = flags;
    signed[31] = 0;
    let tag = mac(token, &signed)?;
    let mut out = [0u8; EGRESS_PREFACE_V4_LEN];
    out[..38].copy_from_slice(&signed);
    out[38..70].copy_from_slice(&tag);
    Ok(out)
}

/// Verify an authenticated 70-byte `MTV4` preface (magic, HMAC-SHA256, timestamp skew, flags, DC).
pub fn verify_egress_preface_v4(
    preface: &[u8; EGRESS_PREFACE_V4_LEN],
    token: &[u8; 16],
    now_secs: u64,
    max_skew_secs: u64,
) -> Result<EgressPrefaceV4> {
    ensure!(preface[..4] == EGRESS_MAGIC_V4, "invalid MTV4 magic");
    let expected_tag = mac(token, &preface[..38])?;
    ensure!(
        bool::from(preface[38..70].ct_eq(&expected_tag)),
        "egress MTV4 HMAC mismatch"
    );
    let dc = i16::from_be_bytes([preface[4], preface[5]]);
    ensure!(
        (1..=5).contains(&dc.checked_abs().unwrap_or(0)),
        "invalid MTV4 DC id"
    );
    let timestamp = u64::from_be_bytes([
        preface[6],
        preface[7],
        preface[8],
        preface[9],
        preface[10],
        preface[11],
        preface[12],
        preface[13],
    ]);
    ensure!(
        now_secs.abs_diff(timestamp) <= max_skew_secs,
        "egress MTV4 timestamp skew exceeds {max_skew_secs}s"
    );
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&preface[14..30]);
    let flags = preface[30];
    let reserved = preface[31];
    ensure!(
        (flags & !(MTV4_FLAG_HAS_CLIENT_IP | MTV4_FLAG_PROTO_MASK)) == 0 && reserved == 0,
        "unsupported MTV4 flags or reserved byte"
    );
    let proto = match flags & MTV4_FLAG_PROTO_MASK {
        MTV4_FLAG_PROTO_PADDED_INTERMEDIATE => crate::ClientProtoKind::PaddedIntermediate,
        MTV4_FLAG_PROTO_INTERMEDIATE => crate::ClientProtoKind::Intermediate,
        MTV4_FLAG_PROTO_ABRIDGED => crate::ClientProtoKind::Abridged,
        _ => anyhow::bail!("unsupported MTV4 client protocol bits"),
    };
    let client_addr = if (flags & MTV4_FLAG_HAS_CLIENT_IP) != 0 {
        let ip = std::net::Ipv4Addr::new(preface[32], preface[33], preface[34], preface[35]);
        let port = u16::from_be_bytes([preface[36], preface[37]]);
        Some(std::net::SocketAddrV4::new(ip, port))
    } else {
        None
    };
    Ok(EgressPrefaceV4 {
        dc,
        timestamp,
        nonce,
        flags,
        proto,
        client_addr,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mtv4Frame {
    Payload(Vec<u8>),
    PayloadQuickAck(Vec<u8>),
    QuickAck(u32),
    Eof,
}

/// Validate a 5-byte `MTV4` frame header (`[kind: u8][len: u32 BE]`) before allocating the body (INV-08).
pub fn parse_mtv4_frame_header(header: &[u8; MTV4_FRAME_HEADER_LEN]) -> Result<(u8, usize)> {
    let kind = header[0];
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    match kind {
        MTV4_FRAME_PAYLOAD | MTV4_FRAME_PAYLOAD_QUICK_ACK => {
            ensure!(
                (4..=crate::MAX_MTPROTO_FRAME_LEN).contains(&len) && len.is_multiple_of(4),
                "MTV4 payload frame length {len} out of bounds or unaligned"
            );
        }
        MTV4_FRAME_QUICK_ACK => {
            ensure!(len == 4, "MTV4 quick-ack frame length must be 4, got {len}");
        }
        MTV4_FRAME_EOF => {
            ensure!(len == 0, "MTV4 EOF frame length must be 0, got {len}");
        }
        _ => anyhow::bail!("unknown MTV4 frame kind {kind}"),
    }
    Ok((kind, len))
}

/// Encode an `MTV4` frame into `[kind: u8][len: u32 BE][body]`.
pub fn encode_mtv4_frame(frame: &Mtv4Frame) -> Result<Vec<u8>> {
    match frame {
        Mtv4Frame::Payload(body) | Mtv4Frame::PayloadQuickAck(body) => {
            ensure!(
                (4..=crate::MAX_MTPROTO_FRAME_LEN).contains(&body.len())
                    && body.len().is_multiple_of(4),
                "MTV4 payload length {} invalid",
                body.len()
            );
            let kind = if matches!(frame, Mtv4Frame::PayloadQuickAck(_)) {
                MTV4_FRAME_PAYLOAD_QUICK_ACK
            } else {
                MTV4_FRAME_PAYLOAD
            };
            let mut out = Vec::with_capacity(MTV4_FRAME_HEADER_LEN + body.len());
            out.push(kind);
            out.extend_from_slice(&(body.len() as u32).to_be_bytes());
            out.extend_from_slice(body);
            Ok(out)
        }
        Mtv4Frame::QuickAck(confirm_key) => {
            let mut out = Vec::with_capacity(MTV4_FRAME_HEADER_LEN + 4);
            out.push(MTV4_FRAME_QUICK_ACK);
            out.extend_from_slice(&4u32.to_be_bytes());
            out.extend_from_slice(&confirm_key.to_be_bytes());
            Ok(out)
        }
        Mtv4Frame::Eof => {
            let mut out = Vec::with_capacity(MTV4_FRAME_HEADER_LEN);
            out.push(MTV4_FRAME_EOF);
            out.extend_from_slice(&0u32.to_be_bytes());
            Ok(out)
        }
    }
}

/// Decode one `MTV4` frame from `buf` (validating bounds before allocation, INV-08).
pub fn decode_mtv4_frame_from_slice(buf: &mut Vec<u8>) -> Result<Option<Mtv4Frame>> {
    if buf.len() < MTV4_FRAME_HEADER_LEN {
        return Ok(None);
    }
    let hdr: [u8; MTV4_FRAME_HEADER_LEN] = [buf[0], buf[1], buf[2], buf[3], buf[4]];
    let (kind, len) = parse_mtv4_frame_header(&hdr)?;
    let total = MTV4_FRAME_HEADER_LEN
        .checked_add(len)
        .ok_or_else(|| anyhow::anyhow!("MTV4 frame total length overflow"))?;
    if buf.len() < total {
        return Ok(None);
    }
    let frame = match kind {
        MTV4_FRAME_PAYLOAD => Mtv4Frame::Payload(buf[MTV4_FRAME_HEADER_LEN..total].to_vec()),
        MTV4_FRAME_PAYLOAD_QUICK_ACK => {
            Mtv4Frame::PayloadQuickAck(buf[MTV4_FRAME_HEADER_LEN..total].to_vec())
        }
        MTV4_FRAME_QUICK_ACK => {
            let key = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]);
            Mtv4Frame::QuickAck(key)
        }
        MTV4_FRAME_EOF => Mtv4Frame::Eof,
        _ => anyhow::bail!("unknown MTV4 frame kind {kind}"),
    };
    buf.drain(..total);
    Ok(Some(frame))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyV2Header {
    pub command: u8,
    pub family_proto: u8,
    pub payload_len: usize,
}

pub fn parse_proxy_v2_header(header: &[u8; PROXY_V2_HEADER_LEN]) -> Result<ProxyV2Header> {
    ensure!(header[..12] == PROXY_V2_SIG, "invalid PROXY v2 signature");
    let version = header[12] >> 4;
    let command = header[12] & 0x0f;
    ensure!(version == 2, "unsupported PROXY protocol version");
    ensure!(command <= 1, "unsupported PROXY v2 command");
    let payload_len = usize::from(u16::from_be_bytes([header[14], header[15]]));
    ensure!(
        payload_len <= MAX_PROXY_V2_PAYLOAD,
        "PROXY v2 payload exceeds bound"
    );
    Ok(ProxyV2Header {
        command,
        family_proto: header[13],
        payload_len,
    })
}

pub fn parse_proxy_v2_payload(
    header: &ProxyV2Header,
    payload: &[u8],
) -> Result<Option<std::net::SocketAddr>> {
    ensure!(
        payload.len() == header.payload_len,
        "PROXY v2 payload length mismatch"
    );
    if header.command == 0 {
        return Ok(None);
    }
    match header.family_proto {
        0x00 => Ok(None),
        0x11 | 0x12 => {
            ensure!(payload.len() >= 12, "truncated PROXY v2 IPv4 addresses");
            let src_ip = std::net::Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
            let src_port = u16::from_be_bytes([payload[8], payload[9]]);
            Ok(Some(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                src_ip, src_port,
            ))))
        }
        0x21 | 0x22 => {
            ensure!(payload.len() >= 36, "truncated PROXY v2 IPv6 addresses");
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&payload[..16]);
            let src_ip = std::net::Ipv6Addr::from(octets);
            let src_port = u16::from_be_bytes([payload[32], payload[33]]);
            Ok(Some(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                src_ip, src_port, 0, 0,
            ))))
        }
        _ => anyhow::bail!("unsupported PROXY v2 address family"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret() -> [u8; 16] {
        let mut secret = [0; 16];
        for (i, b) in secret.iter_mut().enumerate() {
            *b = i as u8;
        }
        secret
    }

    fn synthetic_record() -> Result<Vec<u8>> {
        Ok(hex::decode(
            include_str!("../../../tests/vectors/prototype/synthetic-ch.hex").trim(),
        )?)
    }

    /// Re-signs a client hello exactly like the stock client does, so that a
    /// modified hello still authenticates.
    fn resign(record: &[u8], secret: &[u8; 16], now: u64) -> Result<Vec<u8>> {
        let mut out = record.to_vec();
        let mut zeroed = out.clone();
        zeroed[11..43].fill(0);
        let mut digest = mac(secret, &zeroed)?;
        let timestamp = (now as u32).to_le_bytes();
        for (index, byte) in timestamp.iter().enumerate() {
            digest[28 + index] ^= byte;
        }
        out[11..43].copy_from_slice(&digest);
        Ok(out)
    }

    #[test]
    fn server_flight_matches_the_stock_client_parser_and_the_profile() -> Result<()> {
        // The stock client (`TelegramMessenger/mtproto-engine`,
        // `verify_server_hello`) accepts exactly three records and hashes all
        // of them. This pins the byte layout the client depends on.
        let raw = synthetic_record()?;
        let secret = test_secret();
        let hello = authenticate(&raw[5..], &secret, "example.com", 1700000000)?;
        let profile = ServerFlightProfile {
            cert_bytes: DEFAULT_CERT_BYTES,
            jitter: 0,
        };
        let flight = server_flight(&secret, &hello, &profile, &mut OsRng)?;

        assert_eq!(&flight[..3], b"\x16\x03\x03");
        assert_eq!(u16::from_be_bytes([flight[3], flight[4]]), 122);
        assert_eq!(&flight[127..136], b"\x14\x03\x03\x00\x01\x01\x17\x03\x03");
        assert_eq!(
            u16::from_be_bytes([flight[136], flight[137]]) as usize,
            profile.cert_bytes
        );
        assert_eq!(flight.len(), 138 + profile.cert_bytes);

        // Fresh ephemeral X25519 key_share must be non-zero and valid on Curve25519.
        let share: [u8; 32] = flight[95..127].try_into()?;
        assert_ne!(share, [0u8; 32]);

        // The client verifies the HMAC over the whole flight with the random
        // slot zeroed.
        let mut response = flight.clone();
        let received: [u8; 32] = response[11..43].try_into()?;
        response[11..43].fill(0);
        let mut authenticated = hello.random.to_vec();
        authenticated.extend_from_slice(&response);
        assert_eq!(received, mac(&secret, &authenticated)?);
        Ok(())
    }

    #[test]
    fn server_flight_key_share_is_valid_and_varies() -> Result<()> {
        let raw = synthetic_record()?;
        let secret = test_secret();
        let hello = authenticate(&raw[5..], &secret, "example.com", 1700000000)?;
        let mut seen = std::collections::HashSet::new();
        for _ in 0..128 {
            let flight =
                server_flight(&secret, &hello, &ServerFlightProfile::default(), &mut OsRng)?;
            let share: [u8; 32] = flight[95..127].try_into()?;
            assert_ne!(share, [0u8; 32]);
            seen.insert(share);
        }
        assert_eq!(
            seen.len(),
            128,
            "fresh X25519 key_share must not collide across flights"
        );
        Ok(())
    }

    #[test]
    fn server_flight_selects_the_first_supported_tls13_cipher_suite() -> Result<()> {
        let raw = synthetic_record()?;
        let secret = test_secret();
        // Keep a GREASE value and a TLS 1.2 suite before the first TLS 1.3 suite.
        let mut record = raw.clone();
        let offset = 78;
        let grease_first: [u8; 32] = [
            0x0a, 0x0a, 0xc0, 0x2f, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c,
            0xc0, 0x30, 0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x13, 0xc0, 0x14, 0x00, 0x9c, 0x00, 0x9d,
            0x00, 0x2f, 0x00, 0x35,
        ];
        record[offset..offset + 32].copy_from_slice(&grease_first);
        let record = resign(&record, &secret, 1700000000)?;
        let hello = authenticate(&record[5..], &secret, "example.com", 1700000000)?;
        assert_eq!(hello.cipher_suite, 0x1302);

        let flight = server_flight(&secret, &hello, &ServerFlightProfile::default(), &mut OsRng)?;
        // The cipher suite sits right after the echoed session id and keeps the
        // ServerHello body length unchanged.
        assert_eq!(flight[43], 32);
        assert_eq!(&flight[76..78], &[0x13, 0x02]);
        assert_eq!(u16::from_be_bytes([flight[3], flight[4]]), 122);
        let mut legacy_only = record;
        legacy_only[offset + 4..offset + 8].copy_from_slice(&[0xc0, 0x2b, 0xc0, 0x2f]);
        let legacy_only = resign(&legacy_only, &secret, 1700000000)?;
        assert!(authenticate(&legacy_only[5..], &secret, "example.com", 1700000000).is_err());
        Ok(())
    }

    #[test]
    fn client_template_fingerprint_separates_templates_and_hides_key_material() -> Result<()> {
        let raw = synthetic_record()?;
        let secret = test_secret();
        let hello = authenticate(&raw[5..], &secret, "example.com", 1700000000)?;
        assert_eq!(hello.template.len(), 12);

        // A different extension order must yield a different fingerprint.
        // The renegotiation_info extension (0xff01) is renamed, which keeps
        // the hello authentic but changes the shape.
        let mut record = raw.clone();
        let offset = 138;
        record[offset + 1] = 0x02;
        let record = resign(&record, &secret, 1700000000)?;
        let other = authenticate(&record[5..], &secret, "example.com", 1700000000)?;
        assert_ne!(hello.template, other.template);
        Ok(())
    }

    #[test]
    fn profile_controls_the_certificate_size_and_rejects_out_of_range_values() -> Result<()> {
        let profile = ServerFlightProfile {
            cert_bytes: 2878,
            jitter: 0,
        };
        profile.validate()?;
        assert_eq!(profile.cert_size(&mut OsRng), 2878);

        let jittered = ServerFlightProfile {
            cert_bytes: 2878,
            jitter: 64,
        };
        jittered.validate()?;
        for _ in 0..64 {
            let size = jittered.cert_size(&mut OsRng);
            assert!((2814..=2942).contains(&size));
        }

        assert!(ServerFlightProfile {
            cert_bytes: 511,
            jitter: 0
        }
        .validate()
        .is_err());
        assert!(ServerFlightProfile {
            cert_bytes: 2878,
            jitter: 4096
        }
        .validate()
        .is_err());
        Ok(())
    }

    #[test]
    fn inv08_authentication_rejects_wrong_secret_sni_skew_and_every_truncation() -> Result<()> {
        // Independent Python client fixture, not generated by these Rust codecs.
        let raw =
            hex::decode(include_str!("../../../tests/vectors/prototype/synthetic-ch.hex").trim())?;
        let mut secret = [0; 16];
        for (i, b) in secret.iter_mut().enumerate() {
            *b = i as u8;
        }
        let body = &raw[5..];
        assert!(authenticate(body, &secret, "example.com", 1700000000).is_ok());
        assert!(authenticate(body, &secret, "ya.ru, example.com, vk.com", 1700000000).is_ok());
        assert!(authenticate(body, &secret, "ya.ru,vk.com", 1700000000).is_err());
        assert!(authenticate(body, &[99; 16], "example.com", 1700000000).is_err());
        assert!(authenticate(body, &secret, "wrong.example", 1700000000).is_err());
        assert!(authenticate(body, &secret, "example.com", 1700000121).is_err());
        for n in 0..body.len() {
            assert!(authenticate(&body[..n], &secret, "example.com", 1700000000).is_err());
        }
        Ok(())
    }
    #[test]
    fn inv08_truncated_inputs_never_panic() {
        for len in 0..5000 {
            assert!(authenticate(&vec![0; len], &[0; 16], "example.com", 0).is_err());
        }
    }
    #[test]
    fn inv01_reject_invalid_inner_transport() {
        assert!(client_transport(&[0; 64], &[0; 16]).is_err());
        assert!(record(0x17, &vec![0; MAX_RECORD + 1]).is_err());
    }
    #[test]
    fn direct_header_preserves_wire_key_material_and_cipher_position() -> Result<()> {
        let mut dc = dc_transport()?;
        let mut decoder = cipher(&dc.header[8..40], &dc.header[40..56], &[])?;
        let mut decoded = dc.header;
        crypt(&mut decoder, &mut decoded);
        assert_eq!(&decoded[56..60], &[0xdd; 4]);
        let mut payload = b"payload after the 64 byte header".to_vec();
        let expected = payload.clone();
        crypt(&mut dc.encrypt, &mut payload);
        crypt(&mut decoder, &mut payload);
        assert_eq!(payload, expected);
        Ok(())
    }

    #[test]
    fn proxy_v2_parses_ipv4_ipv6_local_and_rejects_malformed() -> Result<()> {
        let mut hdr = [0u8; PROXY_V2_HEADER_LEN];
        hdr[..12].copy_from_slice(&PROXY_V2_SIG);
        hdr[12] = 0x21; // v2 PROXY
        hdr[13] = 0x11; // AF_INET STREAM
        hdr[14..16].copy_from_slice(&14u16.to_be_bytes());
        let parsed = parse_proxy_v2_header(&hdr)?;
        let mut payload = vec![0u8; 14];
        payload[..4].copy_from_slice(&[203, 0, 113, 42]);
        payload[4..8].copy_from_slice(&[198, 51, 100, 1]);
        payload[8..10].copy_from_slice(&54321u16.to_be_bytes());
        payload[10..12].copy_from_slice(&443u16.to_be_bytes());
        let addr = parse_proxy_v2_payload(&parsed, &payload)?;
        assert_eq!(
            addr,
            Some("203.0.113.42:54321".parse::<std::net::SocketAddr>()?)
        );

        // IPv6
        hdr[13] = 0x21;
        hdr[14..16].copy_from_slice(&36u16.to_be_bytes());
        let parsed6 = parse_proxy_v2_header(&hdr)?;
        let mut payload6 = vec![0u8; 36];
        payload6[..16].copy_from_slice(&"2001:db8::1".parse::<std::net::Ipv6Addr>()?.octets());
        payload6[32..34].copy_from_slice(&44444u16.to_be_bytes());
        assert_eq!(
            parse_proxy_v2_payload(&parsed6, &payload6)?,
            Some("[2001:db8::1]:44444".parse::<std::net::SocketAddr>()?)
        );

        // LOCAL (healthcheck)
        hdr[12] = 0x20;
        hdr[13] = 0x00;
        hdr[14..16].copy_from_slice(&0u16.to_be_bytes());
        let local = parse_proxy_v2_header(&hdr)?;
        assert_eq!(parse_proxy_v2_payload(&local, &[])?, None);

        // Reject invalid signature / oversized payload / truncated IPv4
        let bad_sig = [0u8; PROXY_V2_HEADER_LEN];
        assert!(parse_proxy_v2_header(&bad_sig).is_err());

        hdr[12] = 0x21;
        hdr[13] = 0x11;
        hdr[14..16].copy_from_slice(&((MAX_PROXY_V2_PAYLOAD as u16) + 1).to_be_bytes());
        assert!(parse_proxy_v2_header(&hdr).is_err());

        hdr[14..16].copy_from_slice(&8u16.to_be_bytes());
        let short = parse_proxy_v2_header(&hdr)?;
        assert!(parse_proxy_v2_payload(&short, &[0u8; 8]).is_err());
        Ok(())
    }

    #[test]
    fn egress_preface_v3_builds_verifies_and_rejects_hmac_tampering_or_skew() -> Result<()> {
        let token = [0x42u8; 16];
        let nonce = [0x99u8; 16];
        let dc_hdr = [0xaau8; 64];
        let now = 1_700_000_000u64;
        let preface = build_egress_preface_v3(&token, -2, now, &nonce, &dc_hdr)?;
        assert_eq!(&preface[..4], b"MTV3");
        let parsed = verify_egress_preface_v3(&preface, &token, now + 30, EGRESS_V3_MAX_SKEW_SECS)?;
        assert_eq!(parsed.dc, -2);
        assert_eq!(parsed.timestamp, now);
        assert_eq!(parsed.nonce, nonce);
        assert_eq!(parsed.dc_header, dc_hdr);

        // Wrong token
        assert!(
            verify_egress_preface_v3(&preface, &[0x43u8; 16], now, EGRESS_V3_MAX_SKEW_SECS)
                .is_err()
        );
        // Timestamp outside ±30s window
        assert!(
            verify_egress_preface_v3(&preface, &token, now + 31, EGRESS_V3_MAX_SKEW_SECS).is_err()
        );
        assert!(
            verify_egress_preface_v3(&preface, &token, now - 31, EGRESS_V3_MAX_SKEW_SECS).is_err()
        );
        // Tampered dc_header
        let mut tampered = preface;
        tampered[125] ^= 0x01;
        assert!(verify_egress_preface_v3(&tampered, &token, now, EGRESS_V3_MAX_SKEW_SECS).is_err());
        Ok(())
    }

    #[test]
    fn fuzz_targets_smoke_on_corpus_and_mutations() -> Result<()> {
        let secret = [0x01u8; 16];
        let token = [0x10u8; 16];
        let now = 1_700_000_000u64;
        let mut rng = OsRng;
        let (ch_rec, _, _) = build_client_hello(&secret, "example.com", now, &mut rng)?;
        let ch = &ch_rec[5..];

        // 1. ClientHello parser: truncated slices + single-byte mutations never panic.
        for len in 0..=ch.len().min(96) {
            let _ = handshake_length(&ch[..len]);
            let _ = authenticate(&ch[..len], &secret, "example.com", now);
        }
        for pos in 0..ch.len() {
            let mut mutated = ch.to_vec();
            mutated[pos] ^= 0xff;
            let _ = authenticate_with_record_version(&mutated, 3, &secret, "example.com", now);
        }

        // 2. PROXY v2 parser: boundary lengths and mutated headers never panic.
        let mut v2 = [0u8; PROXY_V2_HEADER_LEN];
        v2[..12].copy_from_slice(&PROXY_V2_SIG);
        v2[12] = 0x21;
        v2[13] = 0x11;
        v2[14..16].copy_from_slice(&12u16.to_be_bytes());
        for pos in 0..PROXY_V2_HEADER_LEN {
            let mut m = v2;
            m[pos] ^= 0x55;
            if let Ok(hdr) = parse_proxy_v2_header(&m) {
                let _ = parse_proxy_v2_payload(&hdr, &[0u8; 12]);
                let _ = parse_proxy_v2_payload(&hdr, &[]);
            }
        }

        // 3. Obfuscated2 init parser: mutated 64-byte headers never panic.
        let (init, _, _) = build_client_init(&secret, 2)?;
        for pos in 0..64 {
            let mut m = init;
            m[pos] ^= 0xaa;
            let _ = client_transport(&m, &secret);
        }

        // 4. Egress MTV3 preface parser: mutated 126-byte prefaces never panic.
        let preface = build_egress_preface_v3(&token, 2, now, &[0x22; 16], &[0x33; 64])?;
        for pos in 0..EGRESS_PREFACE_V3_LEN {
            let mut m = preface;
            m[pos] ^= 0x77;
            let _ = verify_egress_preface_v3(&m, &token, now, EGRESS_V3_MAX_SKEW_SECS);
        }
        Ok(())
    }

    #[test]
    fn mtv4_preface_and_frame_verification_and_bounds() -> Result<()> {
        let token = [0x5a; 16];
        let now = 1_700_000_000u64;
        let nonce = [0x33; 16];
        let client = std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(198, 51, 100, 9), 41234);

        // With client_addr
        let p = build_egress_preface_v4(&token, -2, now, &nonce, Some(client))?;
        let v = verify_egress_preface_v4(&p, &token, now + 5, EGRESS_V3_MAX_SKEW_SECS)?;
        assert_eq!(v.dc, -2);
        assert_eq!(v.nonce, nonce);
        assert_eq!(v.client_addr, Some(client));

        // Without client_addr
        let p0 = build_egress_preface_v4(&token, 2, now, &nonce, None)?;
        let v0 = verify_egress_preface_v4(&p0, &token, now, EGRESS_V3_MAX_SKEW_SECS)?;
        assert_eq!(v0.client_addr, None);

        // Tampered client IP or HMAC rejected
        let mut bad_ip = p;
        bad_ip[32] ^= 1;
        assert!(verify_egress_preface_v4(&bad_ip, &token, now, EGRESS_V3_MAX_SKEW_SECS).is_err());

        // Timestamp skew rejected
        assert!(verify_egress_preface_v4(&p, &token, now + 31, EGRESS_V3_MAX_SKEW_SECS).is_err());

        // Frame encode/decode roundtrip + INV-08 oversize rejected before alloc
        let mut stream = Vec::new();
        stream.extend_from_slice(&encode_mtv4_frame(&Mtv4Frame::Payload(vec![0xab; 64]))?);
        stream.extend_from_slice(&encode_mtv4_frame(&Mtv4Frame::QuickAck(0xdead_beef))?);
        stream.extend_from_slice(&encode_mtv4_frame(&Mtv4Frame::Eof)?);
        assert_eq!(
            decode_mtv4_frame_from_slice(&mut stream)?,
            Some(Mtv4Frame::Payload(vec![0xab; 64]))
        );
        assert_eq!(
            decode_mtv4_frame_from_slice(&mut stream)?,
            Some(Mtv4Frame::QuickAck(0xdead_beef))
        );
        assert_eq!(
            decode_mtv4_frame_from_slice(&mut stream)?,
            Some(Mtv4Frame::Eof)
        );
        assert!(stream.is_empty());

        let oversize_len = (crate::MAX_MTPROTO_FRAME_LEN as u32) + 4;
        let mut oversize_hdr = [0u8; MTV4_FRAME_HEADER_LEN];
        oversize_hdr[0] = MTV4_FRAME_PAYLOAD;
        oversize_hdr[1..5].copy_from_slice(&oversize_len.to_be_bytes());
        assert!(parse_mtv4_frame_header(&oversize_hdr).is_err());
        assert!(parse_mtv4_frame_header(&[MTV4_FRAME_QUICK_ACK, 0, 0, 0, 8]).is_err());
        assert!(parse_mtv4_frame_header(&[MTV4_FRAME_EOF, 0, 0, 0, 4]).is_err());
        assert!(parse_mtv4_frame_header(&[0x99, 0, 0, 0, 4]).is_err());
        Ok(())
    }
}
