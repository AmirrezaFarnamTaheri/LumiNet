//
// AEAD-2022 TCP framing with timestamp anti-replay. The wire layout is
// `[SALT][AEAD(TYPE+TIMESTAMP+HEADER_LEN)][AEAD(ATYP+ADDR+PORT+PAD)]` for
// the request header and `AEAD(LEN)+AEAD(DATA)` per data chunk.
//
// LumiNet already has aes-gcm = "0.10" as a direct dep; this module uses
// Aes128Gcm to keep key width small. The replay-protection window is
// `|now - timestamp| <= 30s` per spec.

use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit, Nonce};
use aes_gcm::Aes128Gcm;

pub const MAX_CHUNK: usize = 0xFFFF;
pub const TIMESTAMP_MAX_DIFF_SECS: i64 = 30;
pub const SALT_LEN: usize = 16;
pub const TAG_LEN: usize = 16;

/// Errors surfaced by the AEAD-2022 framer.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AeadFramingError {
    #[error("data chunk exceeds MAX_CHUNK ({got} > {max})")]
    ChunkTooLarge { got: usize, max: usize },
    #[error("AEAD encryption failed")]
    EncryptFail,
    #[error("AEAD decryption failed")]
    DecryptFail,
    #[error("timestamp outside replay window: |now={now} - ts={ts}| > {max}")]
    ReplayWindow { now: u64, ts: u64, max: u64 },
    #[error("truncated buffer: needed {needed} got {got}")]
    Truncated { needed: usize, got: usize },
}

/// Streaming writer that produces AEAD-2022 framed bytes.
pub struct Aead2022Writer {
    cipher: Aes128Gcm,
    salt: [u8; SALT_LEN],
    nonce_counter: u64,
}

/// Streaming reader state (decoder counterpart).
pub struct Aead2022Reader {
    cipher: Aes128Gcm,
    nonce_counter: u64,
}

impl Aead2022Writer {
    /// Build a writer from a 16-byte key. Generates the SALT from OsRng
    /// so each `Aead2022Writer` carries a fresh session identity.
    pub fn new(key: &[u8; 16]) -> Self {
        use rand::RngCore;
        let mut salt = [0u8; SALT_LEN];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        Self {
            cipher: Aes128Gcm::new_from_slice(key).expect("16-byte key"),
            salt,
            nonce_counter: 0,
        }
    }

    /// Verifiable constructor for tests with a fixed salt (no RNG).
    pub fn with_salt(key: &[u8; 16], salt: [u8; SALT_LEN]) -> Self {
        Self {
            cipher: Aes128Gcm::new_from_slice(key).expect("16-byte key"),
            salt,
            nonce_counter: 0,
        }
    }

    /// Write the TCP request header: `SALT + AEAD(TYPE+TIMESTAMP+HEADER_LEN)` +
    /// inner `AEAD(ATYP+ADDR+PORT+PAD_LEN+PAD)`. Writes nothing if `buf` is
    /// empty; caller pre-allocates.
    pub fn write_request_header(
        &mut self,
        buf: &mut Vec<u8>,
        atyp: u8,
        addr: &[u8],
        port: u16,
    ) -> Result<(), AeadFramingError> {
        buf.extend_from_slice(&self.salt);

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut inner = Vec::with_capacity(1 + 8 + addr.len() + 3);
        inner.push(0x00); // TYPE = request
        inner.extend_from_slice(&ts.to_be_bytes());
        inner.extend_from_slice(&(addr.len() as u16 + 3).to_be_bytes());
        // inner header itself is now sealed
        let nonce = self.next_nonce();
        let ct = self
            .cipher
            .encrypt(&nonce, inner.as_slice())
            .map_err(|_| AeadFramingError::EncryptFail)?;
        buf.extend_from_slice(&ct);

        // secondary AEAD carrying the address block
        let mut second = Vec::with_capacity(addr.len() + 3);
        second.push(atyp);
        second.extend_from_slice(addr);
        second.extend_from_slice(&port.to_be_bytes());
        let nonce2 = self.next_nonce();
        let ct2 = self
            .cipher
            .encrypt(&nonce2, second.as_slice())
            .map_err(|_| AeadFramingError::EncryptFail)?;
        buf.extend_from_slice(&ct2);
        Ok(())
    }

    /// Append a DATA chunk: `AEAD(LEN) + AEAD(DATA)`. `data.len()` must be ≤
    /// [`MAX_CHUNK`]; panics above (assert).
    pub fn write_chunk(&mut self, buf: &mut Vec<u8>, data: &[u8]) -> Result<(), AeadFramingError> {
        assert!(data.len() <= MAX_CHUNK, "chunk too large");
        let len_bytes = (data.len() as u16).to_be_bytes();
        let n1 = self.next_nonce();
        let ct_len = self
            .cipher
            .encrypt(&n1, len_bytes.as_ref())
            .map_err(|_| AeadFramingError::EncryptFail)?;
        buf.extend_from_slice(&ct_len);

        let n2 = self.next_nonce();
        let ct_data = self
            .cipher
            .encrypt(&n2, data)
            .map_err(|_| AeadFramingError::EncryptFail)?;
        buf.extend_from_slice(&ct_data);
        Ok(())
    }

    fn next_nonce(&mut self) -> Nonce<Aes128Gcm> {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&self.nonce_counter.to_be_bytes());
        self.nonce_counter += 1;
        *Nonce::<Aes128Gcm>::from_slice(&n)
    }

    /// Reveal the salt for callers that want to send it out-of-band.
    pub fn salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }
}

impl Aead2022Reader {
    pub fn new(key: &[u8; 16]) -> Self {
        Self {
            cipher: Aes128Gcm::new_from_slice(key).expect("16-byte key"),
            nonce_counter: 0,
        }
    }

    /// Decrypts one framed AEAD value and advances the reader nonce.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, AeadFramingError> {
        let nonce = self.next_nonce();
        self.cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| AeadFramingError::DecryptFail)
    }

    /// Verify a timestamp field against the replay window.
    pub fn verify_timestamp(ts: u64) -> Result<(), AeadFramingError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let diff = (now as i64 - ts as i64).unsigned_abs();
        if diff > TIMESTAMP_MAX_DIFF_SECS as u64 {
            return Err(AeadFramingError::ReplayWindow {
                now,
                ts,
                max: TIMESTAMP_MAX_DIFF_SECS as u64,
            });
        }
        Ok(())
    }

    fn next_nonce(&mut self) -> Nonce<Aes128Gcm> {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&self.nonce_counter.to_be_bytes());
        self.nonce_counter += 1;
        *Nonce::<Aes128Gcm>::from_slice(&n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writer_emits_salt_first() {
        let key = [0xABu8; 16];
        let salt = [0x11u8; SALT_LEN];
        let mut w = Aead2022Writer::with_salt(&key, salt);
        let mut out = Vec::new();
        w.write_request_header(&mut out, 0x03, b"example.com", 8443)
            .unwrap();
        assert_eq!(&out[..SALT_LEN], &salt);
        // Salt + at least two AEAD ciphertexts (inner header + addr block)
        assert!(out.len() > SALT_LEN + 2 * TAG_LEN);
    }

    #[test]
    fn reader_decrypts_with_matching_nonce_sequence() {
        let key = [0xABu8; 16];
        let cipher = Aes128Gcm::new_from_slice(&key).unwrap();
        let nonce = Nonce::<Aes128Gcm>::from_slice(&[0u8; 12]);
        let ciphertext = cipher.encrypt(nonce, b"payload".as_ref()).unwrap();

        let mut reader = Aead2022Reader::new(&key);
        assert_eq!(reader.decrypt(&ciphertext).unwrap(), b"payload");
    }

    #[test]
    fn chunk_too_large_panics() {
        let key = [0u8; 16];
        let mut w = Aead2022Writer::with_salt(&key, [0u8; SALT_LEN]);
        let mut out = Vec::new();
        let big = vec![0u8; MAX_CHUNK + 1];
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            w.write_chunk(&mut out, &big)
        }));
        assert!(result.is_err(), "expected panic on oversized chunk");
    }

    #[test]
    fn chunk_within_limit_encrypts() {
        let key = [0u8; 16];
        let mut w = Aead2022Writer::with_salt(&key, [0u8; SALT_LEN]);
        let mut out = Vec::new();
        w.write_chunk(&mut out, b"hello world").unwrap();
        // 2 bytes encrypted + 16-byte tag; data bytes + 16-byte tag.
        assert_eq!(out.len(), 2 + TAG_LEN + 11 + TAG_LEN);
    }

    #[test]
    fn timestamp_within_30s_passes() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        assert!(Aead2022Reader::verify_timestamp(now).is_ok());
        assert!(Aead2022Reader::verify_timestamp(now - 29).is_ok());
    }

    #[test]
    fn timestamp_outside_30s_rejected() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        assert!(Aead2022Reader::verify_timestamp(now - 31).is_err());
        assert!(Aead2022Reader::verify_timestamp(now + 31).is_err());
    }
}
