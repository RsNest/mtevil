use aes::cipher::{generic_array::GenericArray, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use anyhow::{ensure, Result};
use md5::{Digest as _, Md5};
use sha1::Sha1;
use std::net::Ipv4Addr;
use zeroize::Zeroizing;

pub type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
pub type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Purpose tag for Telegram ME KDF.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KdfPurpose {
    Client,
    Server,
}

impl KdfPurpose {
    fn as_bytes(self) -> &'static [u8] {
        match self {
            KdfPurpose::Client => b"CLIENT",
            KdfPurpose::Server => b"SERVER",
        }
    }
}

/// Derive Telegram ME AES-256-CBC key (32 bytes) and IV (16 bytes).
///
/// NOTE: MD5 and SHA-1 are used strictly here because the Telegram ME wire KDF
/// mandates `key = MD5(s[1:])[..12] || SHA1(s)` and `iv = MD5(s[2:])`.
#[allow(clippy::too_many_arguments)]
pub fn derive_me_aes_key_iv(
    srv_nonce: &[u8; 16],
    clt_nonce: &[u8; 16],
    clt_ts: u32,
    srv_ip: Ipv4Addr,
    clt_port: u16,
    purpose: KdfPurpose,
    clt_ip: Ipv4Addr,
    srv_port: u16,
    proxy_secret: &[u8],
) -> ([u8; 32], [u8; 16]) {
    let srv_ip_le = u32::from(srv_ip).to_le_bytes();
    let clt_ip_le = u32::from(clt_ip).to_le_bytes();
    let cap = 16 + 16 + 4 + 4 + 2 + 6 + 4 + 2 + proxy_secret.len() + 16 + 16;
    let mut s = Zeroizing::new(Vec::with_capacity(cap));
    s.extend_from_slice(srv_nonce);
    s.extend_from_slice(clt_nonce);
    s.extend_from_slice(&clt_ts.to_le_bytes());
    s.extend_from_slice(&srv_ip_le);
    s.extend_from_slice(&clt_port.to_le_bytes());
    s.extend_from_slice(purpose.as_bytes());
    s.extend_from_slice(&clt_ip_le);
    s.extend_from_slice(&srv_port.to_le_bytes());
    s.extend_from_slice(proxy_secret);
    s.extend_from_slice(srv_nonce);
    s.extend_from_slice(clt_nonce);

    let md5_key = Md5::digest(&s[1..]);
    let sha1_key = Sha1::digest(&s[..]);
    let md5_iv = Md5::digest(&s[2..]);

    let mut key = [0u8; 32];
    key[..12].copy_from_slice(&md5_key[..12]);
    key[12..32].copy_from_slice(&sha1_key[..20]);

    let mut iv = [0u8; 16];
    iv.copy_from_slice(&md5_iv[..16]);
    (key, iv)
}

/// Stateful continuous AES-256-CBC stream encryptor (chaining IV across RPC frames).
pub struct MeCbcEncryptor {
    inner: Aes256CbcEnc,
}

impl MeCbcEncryptor {
    pub fn new(key: &[u8; 32], iv: &[u8; 16]) -> Self {
        Self {
            inner: Aes256CbcEnc::new(key.into(), iv.into()),
        }
    }

    pub fn encrypt_in_place(&mut self, data: &mut [u8]) -> Result<()> {
        ensure!(
            data.len().is_multiple_of(16),
            "AES-CBC encrypt input length {} is not a multiple of 16",
            data.len()
        );
        let (blocks, _) = data.as_chunks_mut::<16>();
        for chunk in blocks {
            let block = GenericArray::from_mut_slice(chunk);
            self.inner.encrypt_block_mut(block);
        }
        Ok(())
    }
}

/// Stateful continuous AES-256-CBC stream decryptor (chaining IV across RPC frames).
pub struct MeCbcDecryptor {
    inner: Aes256CbcDec,
}

impl MeCbcDecryptor {
    pub fn new(key: &[u8; 32], iv: &[u8; 16]) -> Self {
        Self {
            inner: Aes256CbcDec::new(key.into(), iv.into()),
        }
    }

    pub fn decrypt_in_place(&mut self, data: &mut [u8]) -> Result<()> {
        ensure!(
            data.len().is_multiple_of(16),
            "AES-CBC decrypt input length {} is not a multiple of 16",
            data.len()
        );
        let (blocks, _) = data.as_chunks_mut::<16>();
        for chunk in blocks {
            let block = GenericArray::from_mut_slice(chunk);
            self.inner.decrypt_block_mut(block);
        }
        Ok(())
    }
}
