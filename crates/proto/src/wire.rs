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

/// Valid X25519 public keys (real scalar multiples of the base point,
/// generated offline). The stock client builds its own key_share with an
/// on-curve validity check (`mtproto-engine` `fake_x25519_key`); random
/// 32-byte strings are invalid curve points about half the time and are a
/// usable passive fingerprint. The pool keeps the share valid and varying.
pub const KEY_SHARE_POOL: [[u8; 32]; 64] = [
    [
        108, 141, 129, 113, 217, 68, 227, 48, 168, 125, 163, 233, 44, 224, 115, 137, 147, 34, 29,
        153, 118, 220, 175, 35, 75, 0, 208, 210, 62, 228, 83, 41,
    ],
    [
        62, 207, 103, 47, 6, 225, 154, 126, 198, 62, 158, 142, 27, 27, 87, 140, 82, 94, 144, 84, 3,
        171, 114, 225, 105, 181, 84, 179, 132, 44, 173, 95,
    ],
    [
        236, 89, 109, 200, 65, 176, 26, 48, 67, 82, 72, 172, 185, 142, 105, 177, 32, 3, 70, 208,
        206, 215, 21, 244, 87, 71, 115, 115, 71, 239, 185, 71,
    ],
    [
        251, 192, 174, 87, 84, 87, 7, 245, 222, 106, 49, 147, 97, 233, 230, 98, 18, 127, 179, 85,
        22, 149, 45, 121, 22, 239, 185, 151, 10, 171, 124, 32,
    ],
    [
        48, 10, 236, 160, 19, 113, 73, 26, 121, 167, 122, 144, 171, 134, 55, 245, 163, 54, 147, 62,
        172, 13, 222, 247, 192, 198, 87, 203, 194, 177, 34, 63,
    ],
    [
        195, 100, 37, 211, 58, 35, 255, 209, 172, 35, 235, 138, 147, 57, 200, 140, 9, 75, 120, 182,
        154, 133, 163, 31, 88, 244, 172, 125, 96, 40, 225, 98,
    ],
    [
        125, 27, 97, 254, 130, 72, 95, 238, 193, 76, 69, 180, 175, 54, 208, 201, 120, 172, 2, 195,
        225, 234, 253, 135, 117, 220, 241, 196, 136, 177, 132, 84,
    ],
    [
        77, 48, 186, 157, 58, 216, 83, 33, 101, 133, 143, 175, 253, 36, 144, 207, 59, 252, 46, 29,
        196, 220, 152, 223, 138, 49, 58, 252, 126, 79, 239, 113,
    ],
    [
        41, 80, 22, 197, 145, 35, 171, 76, 14, 21, 4, 68, 200, 9, 235, 135, 4, 218, 255, 66, 167,
        253, 45, 78, 188, 170, 120, 153, 73, 125, 66, 56,
    ],
    [
        199, 130, 196, 112, 110, 103, 241, 71, 122, 29, 15, 139, 81, 181, 197, 169, 125, 253, 68,
        225, 186, 227, 198, 9, 249, 68, 122, 202, 18, 251, 27, 37,
    ],
    [
        15, 212, 249, 127, 195, 99, 113, 0, 153, 108, 12, 255, 254, 102, 125, 155, 214, 50, 166,
        151, 93, 18, 137, 226, 251, 179, 240, 218, 169, 108, 16, 73,
    ],
    [
        167, 218, 250, 87, 218, 62, 136, 174, 160, 53, 149, 100, 142, 118, 54, 17, 156, 222, 235,
        111, 75, 158, 251, 119, 163, 159, 194, 159, 126, 196, 31, 69,
    ],
    [
        169, 154, 193, 88, 107, 213, 57, 174, 109, 196, 163, 22, 204, 150, 174, 15, 64, 16, 166,
        41, 10, 85, 206, 78, 52, 143, 173, 198, 79, 164, 110, 98,
    ],
    [
        169, 44, 70, 188, 103, 16, 204, 214, 188, 221, 236, 161, 92, 86, 25, 231, 50, 174, 54, 146,
        119, 82, 58, 119, 149, 109, 223, 200, 220, 146, 25, 122,
    ],
    [
        44, 35, 23, 89, 59, 108, 211, 92, 131, 248, 251, 240, 4, 38, 22, 209, 251, 97, 156, 81,
        221, 68, 197, 134, 18, 107, 53, 57, 153, 6, 208, 91,
    ],
    [
        9, 67, 185, 168, 69, 226, 25, 90, 188, 40, 179, 113, 166, 153, 148, 157, 43, 153, 1, 187,
        117, 126, 135, 44, 33, 103, 61, 144, 152, 26, 112, 96,
    ],
    [
        70, 135, 103, 240, 100, 40, 138, 21, 98, 155, 102, 216, 31, 105, 89, 68, 89, 183, 172, 149,
        143, 243, 164, 79, 18, 62, 253, 56, 170, 98, 92, 63,
    ],
    [
        12, 100, 142, 106, 165, 179, 89, 247, 212, 75, 38, 0, 16, 95, 244, 46, 155, 159, 25, 51,
        127, 51, 105, 76, 85, 144, 93, 219, 142, 51, 146, 83,
    ],
    [
        6, 81, 94, 81, 14, 143, 192, 72, 117, 35, 179, 162, 255, 111, 156, 33, 170, 85, 109, 5, 49,
        90, 154, 99, 216, 150, 164, 109, 86, 93, 193, 72,
    ],
    [
        195, 58, 183, 80, 109, 46, 156, 2, 177, 170, 176, 77, 15, 242, 249, 237, 51, 150, 24, 184,
        147, 241, 175, 37, 167, 52, 244, 182, 55, 71, 127, 114,
    ],
    [
        53, 216, 254, 208, 226, 110, 2, 16, 97, 160, 114, 157, 178, 106, 44, 67, 218, 124, 216,
        116, 243, 82, 245, 88, 87, 188, 1, 79, 151, 3, 72, 36,
    ],
    [
        176, 172, 172, 16, 3, 252, 109, 64, 11, 136, 136, 123, 44, 87, 92, 215, 4, 68, 72, 38, 184,
        122, 241, 33, 221, 207, 133, 210, 30, 6, 6, 42,
    ],
    [
        10, 127, 204, 134, 5, 42, 72, 166, 157, 231, 31, 180, 173, 87, 240, 87, 146, 227, 74, 40,
        10, 30, 180, 242, 120, 224, 154, 89, 104, 78, 210, 31,
    ],
    [
        170, 136, 37, 198, 230, 46, 219, 57, 50, 255, 183, 252, 191, 177, 1, 67, 112, 45, 247, 154,
        38, 98, 9, 176, 194, 162, 72, 185, 191, 160, 16, 39,
    ],
    [
        5, 215, 239, 232, 113, 61, 242, 78, 96, 220, 182, 65, 72, 139, 63, 16, 23, 219, 128, 67,
        210, 3, 38, 24, 213, 237, 226, 225, 37, 104, 133, 8,
    ],
    [
        196, 236, 105, 143, 182, 31, 96, 55, 193, 117, 47, 2, 150, 221, 236, 97, 71, 254, 89, 254,
        155, 188, 127, 97, 254, 55, 55, 58, 221, 197, 147, 43,
    ],
    [
        44, 78, 65, 183, 161, 140, 220, 202, 84, 155, 156, 143, 34, 233, 84, 81, 180, 241, 7, 111,
        90, 232, 54, 178, 185, 102, 27, 111, 206, 26, 38, 48,
    ],
    [
        138, 58, 116, 82, 225, 237, 223, 91, 34, 255, 23, 239, 92, 9, 39, 236, 61, 7, 82, 21, 131,
        19, 232, 85, 128, 41, 186, 53, 14, 248, 47, 32,
    ],
    [
        86, 29, 23, 129, 211, 119, 188, 181, 255, 125, 220, 223, 241, 252, 1, 113, 64, 198, 219,
        168, 219, 208, 15, 87, 172, 195, 186, 242, 15, 172, 168, 57,
    ],
    [
        201, 153, 222, 185, 28, 133, 141, 243, 84, 157, 87, 66, 34, 205, 131, 193, 92, 85, 78, 128,
        69, 97, 170, 195, 250, 147, 107, 91, 119, 210, 110, 3,
    ],
    [
        94, 12, 166, 27, 148, 68, 83, 249, 82, 139, 252, 215, 138, 124, 238, 229, 73, 51, 6, 113,
        92, 28, 248, 6, 27, 46, 82, 74, 98, 229, 165, 78,
    ],
    [
        19, 253, 188, 252, 221, 66, 207, 142, 67, 130, 14, 191, 40, 165, 148, 79, 73, 197, 120,
        122, 151, 118, 184, 189, 135, 169, 15, 127, 112, 233, 91, 126,
    ],
    [
        110, 133, 2, 68, 181, 247, 212, 142, 85, 143, 150, 87, 229, 203, 226, 145, 135, 103, 235,
        29, 51, 120, 117, 158, 30, 235, 15, 23, 34, 227, 165, 80,
    ],
    [
        190, 189, 151, 196, 190, 129, 237, 105, 29, 24, 150, 24, 178, 252, 252, 98, 212, 209, 252,
        219, 248, 17, 136, 144, 8, 83, 45, 129, 156, 104, 251, 84,
    ],
    [
        7, 7, 136, 14, 158, 241, 120, 90, 12, 96, 212, 205, 154, 96, 214, 11, 75, 82, 156, 3, 22,
        132, 194, 152, 161, 147, 165, 70, 32, 99, 85, 47,
    ],
    [
        175, 213, 18, 188, 23, 69, 160, 21, 249, 70, 87, 211, 170, 249, 6, 19, 163, 20, 139, 96,
        131, 36, 4, 47, 194, 29, 48, 84, 115, 32, 57, 24,
    ],
    [
        188, 79, 107, 174, 254, 247, 24, 243, 243, 187, 27, 126, 57, 30, 126, 223, 2, 243, 130,
        233, 249, 137, 157, 20, 157, 225, 245, 71, 224, 116, 10, 85,
    ],
    [
        115, 42, 119, 80, 126, 53, 49, 22, 134, 243, 18, 244, 170, 235, 70, 228, 55, 29, 30, 113,
        83, 245, 216, 98, 20, 126, 233, 38, 184, 46, 131, 7,
    ],
    [
        202, 173, 26, 125, 158, 86, 112, 188, 66, 55, 251, 198, 61, 58, 166, 126, 114, 151, 8, 35,
        174, 128, 109, 95, 177, 225, 193, 74, 201, 190, 189, 41,
    ],
    [
        103, 53, 109, 200, 189, 119, 173, 206, 40, 73, 123, 101, 134, 224, 105, 101, 33, 110, 195,
        26, 74, 248, 104, 39, 131, 179, 81, 229, 187, 85, 21, 36,
    ],
    [
        237, 185, 181, 62, 179, 212, 63, 62, 8, 42, 173, 151, 101, 184, 107, 111, 88, 123, 101,
        132, 17, 240, 66, 251, 93, 11, 216, 238, 104, 51, 38, 1,
    ],
    [
        253, 145, 163, 39, 1, 107, 172, 115, 110, 28, 58, 8, 217, 159, 227, 199, 132, 34, 237, 115,
        26, 193, 180, 36, 188, 165, 20, 19, 152, 159, 67, 124,
    ],
    [
        199, 35, 48, 225, 51, 96, 184, 120, 237, 127, 144, 170, 60, 54, 146, 125, 211, 100, 212,
        217, 228, 160, 24, 216, 150, 13, 14, 89, 157, 146, 244, 34,
    ],
    [
        134, 49, 166, 194, 15, 32, 76, 122, 194, 250, 124, 3, 132, 30, 206, 150, 79, 222, 1, 94, 9,
        135, 3, 14, 230, 90, 160, 218, 39, 190, 167, 120,
    ],
    [
        222, 96, 244, 58, 149, 72, 187, 67, 39, 239, 82, 105, 105, 57, 29, 214, 244, 126, 74, 247,
        44, 162, 86, 12, 17, 44, 59, 115, 71, 73, 228, 49,
    ],
    [
        31, 237, 90, 224, 59, 177, 14, 131, 142, 148, 173, 139, 155, 43, 146, 251, 182, 239, 58,
        234, 250, 53, 98, 127, 134, 66, 149, 95, 22, 130, 162, 58,
    ],
    [
        3, 139, 149, 30, 91, 200, 66, 220, 24, 216, 175, 130, 37, 143, 100, 242, 225, 123, 16, 31,
        126, 94, 90, 242, 141, 210, 33, 200, 129, 63, 121, 31,
    ],
    [
        107, 103, 27, 169, 123, 209, 153, 12, 161, 114, 17, 242, 148, 140, 71, 211, 216, 54, 192,
        10, 133, 71, 106, 139, 47, 254, 5, 215, 18, 157, 69, 85,
    ],
    [
        11, 168, 187, 53, 212, 187, 77, 131, 79, 87, 110, 86, 240, 226, 14, 126, 15, 183, 186, 79,
        171, 196, 121, 59, 239, 210, 201, 255, 168, 153, 224, 43,
    ],
    [
        117, 12, 8, 117, 164, 225, 85, 113, 10, 50, 35, 135, 68, 251, 82, 189, 93, 1, 94, 97, 224,
        20, 205, 92, 246, 171, 171, 70, 237, 181, 154, 67,
    ],
    [
        252, 143, 35, 146, 90, 198, 31, 113, 65, 140, 253, 47, 129, 157, 190, 15, 150, 248, 65,
        114, 85, 141, 254, 201, 58, 107, 193, 4, 221, 15, 145, 120,
    ],
    [
        180, 98, 26, 162, 137, 241, 9, 61, 249, 62, 199, 92, 38, 67, 16, 5, 196, 122, 99, 174, 88,
        236, 113, 21, 241, 255, 203, 124, 118, 26, 162, 90,
    ],
    [
        53, 156, 21, 26, 179, 78, 10, 40, 239, 74, 169, 183, 225, 29, 94, 177, 37, 56, 191, 244,
        171, 232, 87, 90, 224, 40, 80, 8, 152, 77, 5, 38,
    ],
    [
        80, 225, 144, 89, 224, 176, 137, 133, 66, 233, 213, 242, 55, 22, 233, 200, 58, 32, 14, 69,
        139, 101, 253, 10, 182, 174, 121, 45, 152, 208, 183, 101,
    ],
    [
        146, 213, 124, 136, 41, 21, 111, 76, 232, 147, 251, 35, 228, 240, 243, 50, 153, 103, 236,
        174, 197, 225, 181, 60, 179, 44, 80, 29, 34, 241, 166, 122,
    ],
    [
        31, 133, 114, 86, 200, 153, 42, 168, 208, 93, 141, 5, 170, 149, 49, 48, 61, 109, 158, 35,
        186, 188, 82, 141, 159, 164, 217, 169, 167, 244, 208, 101,
    ],
    [
        252, 107, 233, 111, 111, 210, 111, 117, 93, 194, 164, 157, 139, 185, 152, 79, 178, 242,
        176, 88, 86, 171, 28, 232, 193, 26, 135, 236, 35, 3, 21, 35,
    ],
    [
        38, 72, 183, 3, 157, 212, 177, 152, 67, 182, 23, 65, 153, 93, 214, 70, 247, 166, 88, 32,
        23, 245, 102, 38, 246, 6, 212, 57, 2, 47, 79, 55,
    ],
    [
        94, 153, 92, 11, 213, 186, 123, 255, 34, 232, 168, 223, 238, 186, 28, 166, 222, 136, 161,
        215, 95, 70, 101, 246, 158, 107, 178, 126, 159, 22, 127, 46,
    ],
    [
        103, 159, 166, 96, 36, 199, 233, 35, 115, 54, 38, 53, 137, 123, 225, 91, 196, 210, 103,
        165, 228, 141, 234, 160, 32, 217, 7, 209, 194, 7, 133, 43,
    ],
    [
        11, 177, 221, 45, 84, 53, 114, 137, 244, 9, 0, 108, 66, 145, 127, 99, 163, 138, 165, 124,
        169, 13, 79, 11, 11, 23, 229, 177, 156, 167, 52, 11,
    ],
    [
        174, 92, 58, 64, 55, 236, 241, 205, 51, 73, 173, 239, 213, 230, 60, 25, 15, 130, 246, 73,
        241, 117, 222, 31, 199, 212, 188, 92, 48, 218, 31, 11,
    ],
    [
        183, 26, 90, 77, 240, 183, 227, 160, 216, 121, 178, 120, 150, 66, 88, 103, 177, 147, 89,
        213, 204, 71, 150, 23, 138, 98, 69, 232, 200, 31, 101, 86,
    ],
    [
        173, 237, 215, 187, 80, 74, 145, 179, 89, 18, 62, 246, 31, 51, 217, 174, 17, 138, 72, 77,
        76, 91, 236, 13, 236, 179, 126, 74, 225, 4, 78, 65,
    ],
];
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
            jitter: 0,
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
                    sni_ok = name.eq_ignore_ascii_case(sni.as_bytes());
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
    let key_share = KEY_SHARE_POOL[(rng.next_u32() % KEY_SHARE_POOL.len() as u32) as usize];
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
}
pub fn client_transport(wire: &[u8; 64], secret: &[u8; 16]) -> Result<ClientTransport> {
    let mut decrypt = cipher(&wire[8..40], &wire[40..56], secret)?;
    let mut plain = *wire;
    decrypt.apply_keystream(&mut plain);
    ensure!(
        plain[56..60] == [0xdd; 4],
        "only padded intermediate supported"
    );
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
    })
}

pub struct DcTransport {
    pub header: [u8; 64],
    pub encrypt: AesCtr,
    pub decrypt: AesCtr,
}
pub fn dc_transport() -> Result<DcTransport> {
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
    plain[56..60].fill(0xdd);
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
    // key_share: X25519 valid point from KEY_SHARE_POOL
    let key_share = KEY_SHARE_POOL[(rng.next_u32() % KEY_SHARE_POOL.len() as u32) as usize];
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
    ensure!(&flight[44..76] == client_session, "server session id mismatch");
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
        if plain[0] != 0xef
            && plain[4..8] != [0; 4]
            && !forbidden.iter().any(|v| plain[..4] == **v)
        {
            break;
        }
    }
    plain[56..60].fill(0xdd);
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
        let profile = ServerFlightProfile::default();
        let flight = server_flight(&secret, &hello, &profile, &mut OsRng)?;

        assert_eq!(&flight[..3], b"\x16\x03\x03");
        assert_eq!(u16::from_be_bytes([flight[3], flight[4]]), 122);
        assert_eq!(&flight[127..136], b"\x14\x03\x03\x00\x01\x01\x17\x03\x03");
        assert_eq!(
            u16::from_be_bytes([flight[136], flight[137]]) as usize,
            profile.cert_bytes
        );
        assert_eq!(flight.len(), 138 + profile.cert_bytes);

        // The key_share must be a valid X25519 point from the pool, not random
        // bytes (passive fingerprint resistance).
        let share: [u8; 32] = flight[95..127].try_into()?;
        assert!(KEY_SHARE_POOL.contains(&share));

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
        for _ in 0..32 {
            let flight =
                server_flight(&secret, &hello, &ServerFlightProfile::default(), &mut OsRng)?;
            let share: [u8; 32] = flight[95..127].try_into()?;
            assert!(KEY_SHARE_POOL.contains(&share));
            seen.insert(share);
        }
        assert!(seen.len() > 1, "key_share must vary between flights");
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
}
