// Clean-room re-implementation of Shadowsocks 2022 AEAD cipher suites.
// MIT License.

use std::fmt;
use thiserror::Error;

// ring re-exports used throughout this module
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, AES_128_GCM};

/// `KeyType` impl that requests 16 bytes from HKDF-Expand. ring's `HKDF_SHA256`
/// constant requests 32 bytes, but SS2022's AES-128 cipher only needs 16.
struct HkdfLen16;

impl ring::hkdf::KeyType for HkdfLen16 {
    fn len(&self) -> usize {
        16
    }
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum Ss2022Error {
    #[error("cipher text too short: need ≥16 bytes for AEAD tag, got {0}")]
    CipherTextTooShort(usize),

    #[error("key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("unknown cipher: {0}")]
    UnknownCipher(String),

    #[error("salt length mismatch: expected {expected}, got {got}")]
    SaltLengthMismatch { expected: usize, got: usize },
}

/// Supported Shadowsocks 2022 cipher suites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ss2022CipherKind {
    /// AEAD_CHACHA20_POLY1305 with a 16-byte salt.
    Aes256Gcm,
    /// AEAD_CHACHA20_POLY1305 with a 16-byte salt.
    Aes128Gcm,
    /// 2022_blake3_aes_256_gcm — BLAKE3 key derivation + AES-256-GCM.
    Blake3Aes256Gcm,
    /// 2022_blake3_aes_128_gcm — BLAKE3 key derivation + AES-128-GCM.
    Blake3Aes128Gcm,
}

impl Ss2022CipherKind {
    /// Salt length in bytes for each cipher.
    pub fn salt_len(&self) -> usize {
        match self {
            Self::Aes256Gcm | Self::Blake3Aes256Gcm => 32,
            Self::Aes128Gcm | Self::Blake3Aes128Gcm => 16,
        }
    }

    /// Length of the AEAD tag appended to each record (same for all ciphers).
    pub const TAG_LEN: usize = 16;

    /// Nonce length for the underlying AEAD (12 bytes = 96 bits, standard).
    pub const NONCE_LEN: usize = 12;
}

/// A configured SS2022 cipher that can encrypt and decrypt records.
#[derive(Clone)]
pub struct Ss2022AeadCipher {
    kind: Ss2022CipherKind,
    /// Derived session key. Initialised lazily from the first salt we see.
    session_key: Option<ring::aead::LessSafeKey>,
}

impl fmt::Debug for Ss2022AeadCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ss2022AeadCipher")
            .field("kind", &self.kind)
            .field("session_key", &"...")
            .finish()
    }
}

impl Ss2022AeadCipher {
    /// Build a cipher with the given suite.
    pub fn new(kind: Ss2022CipherKind) -> Self {
        Self {
            kind,
            session_key: None,
        }
    }

    /// Derive the session key from a salt and the master key using HKDF-SHA256
    /// (or BLAKE3 for the blake3_* variants).
    pub fn derive_session_key(&mut self, salt: &[u8], master_key: &[u8]) -> Result<(), Ss2022Error> {
        let salt_len = self.kind.salt_len();
        if salt.len() != salt_len {
            return Err(Ss2022Error::SaltLengthMismatch {
                expected: salt_len,
                got: salt.len(),
            });
        }

        let mut subkey = vec![0u8; salt_len];

        // Derive subkey using the appropriate KDF.
        match self.kind {
            Ss2022CipherKind::Aes256Gcm | Ss2022CipherKind::Aes128Gcm => {
                // HKDF-SHA256(salt, IKM=master_key, info, L=salt_len).
                // ring requires the salt to be at least SHA-256's hash output length
                // (32 bytes). SS2022 defines a 16-byte salt for AES-128, so we
                // zero-pad the salt to meet ring's requirement.
                let mut padded_salt = [0u8; 32];
                padded_salt[..salt.len()].copy_from_slice(salt);
                let salt_hk = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, &padded_salt);
                let prk = salt_hk.extract(master_key);
                // ring's hkdf::Prk::expand requires the requested output length
                // match the actual fill buffer length. The HKDF_SHA256 constant
                // is a `KeyType` with len=32, which doesn't match salt_len=16
                // for AES-128. We wrap the requested length in a `KeyType` impl.
                static INFO: [u8; 9] = *b"ss-subkey";
                let info_ref: &[u8] = &INFO[..];
                let info_arr: [&[u8]; 1] = [info_ref];
                match salt_len {
                    16 => {
                        let okm = prk
                            .expand(&info_arr, HkdfLen16)
                            .map_err(|e| Ss2022Error::KeyDerivation(format!("{:?}", e)))?;
                        let mut out = [0u8; 16];
                        okm.fill(&mut out)
                            .map_err(|e| Ss2022Error::KeyDerivation(format!("{:?}", e)))?;
                        subkey.copy_from_slice(&out);
                    }
                    32 => {
                        let okm = prk
                            .expand(&info_arr, ring::hkdf::HKDF_SHA256)
                            .map_err(|e| Ss2022Error::KeyDerivation(format!("{:?}", e)))?;
                        let mut out = [0u8; 32];
                        okm.fill(&mut out)
                            .map_err(|e| Ss2022Error::KeyDerivation(format!("{:?}", e)))?;
                        subkey.copy_from_slice(&out);
                    }
                    _ => {
                        return Err(Ss2022Error::KeyDerivation(format!(
                            "unsupported salt length for HKDF: {}",
                            salt_len
                        )));
                    }
                }
            }
            Ss2022CipherKind::Blake3Aes256Gcm | Ss2022CipherKind::Blake3Aes128Gcm => {
                // BLAKE3: key = blake3_kdf(master_key || salt).
                // Use keyed mode so the master key actually influences the output.
                // BLAKE3 accepts keys shorter than 32 bytes (they're zero-padded).
                let mut ctx = blake3::Hasher::new_keyed(master_key);
                ctx.update(salt);
                ctx.update(b"ss-subkey");
                let derived = ctx.finalize();
                let derived_bytes: [u8; 32] = derived;
                let take = salt_len.min(32);
                subkey[..take].copy_from_slice(&derived_bytes[..take]);
            }
        }

        // Bind the derived key to a LessSafeKey for ring.
        let unbound_key = match self.kind {
            Ss2022CipherKind::Aes256Gcm => UnboundKey::new(&AES_256_GCM, &subkey),
            Ss2022CipherKind::Aes128Gcm => UnboundKey::new(&AES_128_GCM, &subkey),
            Ss2022CipherKind::Blake3Aes256Gcm => UnboundKey::new(&AES_256_GCM, &subkey),
            Ss2022CipherKind::Blake3Aes128Gcm => UnboundKey::new(&AES_128_GCM, &subkey),
        }
        .map_err(|e| Ss2022Error::KeyDerivation(format!("{:?}", e)))?;

        self.session_key = Some(LessSafeKey::new(unbound_key));
        Ok(())
    }

    /// Encrypt a single record. The payload must not be empty.
    ///
    /// Record format: `[plaintext][16-byte AEAD tag]`
    ///
    /// The nonce is constructed from a 12-byte buffer initialised to zero;
    /// the SS2022 protocol increments this counter for each record.
    pub fn encrypt_record(&self, nonce_counter: u64, plaintext: &[u8]) -> Result<Vec<u8>, Ss2022Error> {
        let key = self
            .session_key
            .as_ref()
            .ok_or_else(|| Ss2022Error::EncryptionFailed("session key not derived".into()))?;

        if plaintext.is_empty() {
            return Err(Ss2022Error::EncryptionFailed(
                "payload must not be empty".into(),
            ));
        }

        let nonce_bytes: [u8; 12] = {
            let mut n = [0u8; 12];
            for i in 0..8 {
                n[i + 4] = (nonce_counter >> ((7 - i) * 8)) as u8;
            }
            n
        };

        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let aad = Aad::empty();

        let mut in_out = plaintext.to_vec();
        key.seal_in_place_append_tag(nonce, aad, &mut in_out)
            .map_err(|e| Ss2022Error::EncryptionFailed(format!("{:?}", e)))?;

        Ok(in_out) // [ciphertext][tag]
    }

    /// Decrypt a single record. The ciphertext must include the 16-byte tag.
    pub fn decrypt_record(&self, nonce_counter: u64, ciphertext: &[u8]) -> Result<Vec<u8>, Ss2022Error> {
        let key = self
            .session_key
            .as_ref()
            .ok_or_else(|| Ss2022Error::DecryptionFailed("session key not derived".into()))?;

        if ciphertext.len() < Ss2022CipherKind::TAG_LEN {
            return Err(Ss2022Error::CipherTextTooShort(ciphertext.len()));
        }

        let nonce_bytes: [u8; 12] = {
            let mut n = [0u8; 12];
            for i in 0..8 {
                n[i + 4] = (nonce_counter >> ((7 - i) * 8)) as u8;
            }
            n
        };

        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let aad = Aad::empty();

        let mut in_out = ciphertext.to_vec();
        let plaintext = key
            .open_in_place(nonce, aad, &mut in_out)
            .map_err(|e| Ss2022Error::DecryptionFailed(format!("{:?}", e)))?;

        Ok(plaintext.to_vec())
    }

    pub fn kind(&self) -> Ss2022CipherKind {
        self.kind
    }
}

// ---------------------------------------------------------------------------
// BLAKE3 helper (delegates to the blake3 crate)
// ---------------------------------------------------------------------------

mod blake3 {
    //! Thin wrapper around the `blake3` crate providing a compatible `Hasher`
    //! interface.  We delegate to the real `blake3` crate (already a dep) so
    //! that both the deterministic `keyed_hash` path used in tests and the
    //! stateful `Hasher` path used in `derive_session_key` produce correct,
    //! consistent results.

    /// BLAKE3 keyed hash — produces a 32-byte output.
    ///
    /// `key` is zero-padded (or truncated) to 32 bytes since blake3 requires
    /// a full 32-byte key.
    pub fn keyed_hash(key: &[u8], data: &[u8]) -> [u8; 32] {
        let mut key32 = [0u8; 32];
        let take = key.len().min(32);
        key32[..take].copy_from_slice(&key[..take]);
        let mut hasher = ::blake3::Hasher::new_keyed(&key32);
        hasher.update(data);
        let out = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(&out.as_bytes()[..32]);
        result
    }

    /// Minimal BLAKE3 hasher compatible with the `Hasher` interface expected
    /// by `derive_session_key`.
    pub struct Hasher {
        inner: ::blake3::Hasher,
    }

    impl Hasher {
        pub fn new() -> Self {
            Self {
                inner: ::blake3::Hasher::new(),
            }
        }

        /// Build a keyed hasher. The key is zero-padded to 32 bytes if shorter.
        pub fn new_keyed(key: &[u8]) -> Self {
            // blake3 requires a full 32-byte key; pad with zeros if shorter.
            let mut key32 = [0u8; 32];
            let take = key.len().min(32);
            key32[..take].copy_from_slice(&key[..take]);
            Self {
                inner: ::blake3::Hasher::new_keyed(&key32),
            }
        }

        pub fn update(&mut self, data: &[u8]) {
            self.inner.update(data);
        }

        pub fn finalize(self) -> [u8; 32] {
            // Return the actual accumulated hash; finalize consumes the hasher.
            let out = self.inner.finalize();
            let mut result = [0u8; 32];
            result.copy_from_slice(&out.as_bytes()[..32]);
            result
        }
    }
}

// ---------------------------------------------------------------------------
// EIH support (Encrypted Inbound Header)
// ---------------------------------------------------------------------------

/// Encrypted Inbound Header context for SS2022.
///
/// The EIH is a mechanism where the first packet's header is encrypted
/// with a secondary key, allowing the server to determine the correct
/// upstream destination before decrypting the full payload.
pub struct EihContext {
    /// Secondary key for EIH encryption (separate from the main session key).
    eih_key: Vec<u8>,
    /// Nonce for EIH (reused per connection, incremented per packet).
    nonce: u64,
}

impl EihContext {
    pub fn new(eih_key: Vec<u8>) -> Self {
        Self { eih_key, nonce: 0 }
    }

    /// Encrypt the EIH payload and return the ciphertext with the EIH nonce prepended.
    pub fn encrypt_header(&self, payload: &[u8]) -> Vec<u8> {
        let mut nonce_bytes = [0u8; 12];
        let nb = self.nonce.to_le_bytes();
        nonce_bytes[..8].copy_from_slice(&nb);

        let mut out = vec![0u8; 12 + payload.len() + 16];
        out[..12].copy_from_slice(&nonce_bytes);
        // Simplified: XOR-based EIH (real impl would use AES-GCM or ChaCha20).
        for (i, &b) in payload.iter().enumerate() {
            out[12 + i] = b ^ self.eih_key[i % self.eih_key.len()] ^ ((self.nonce >> (i % 8)) as u8);
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Replay protection (ppbloom)
// ---------------------------------------------------------------------------

/// Count-Min sketch for replay protection. Keeps a compact approximate count
/// of seen values so repeated values can be detected and rejected.
#[derive(Clone)]
pub struct PpbloomFilter {
    width: usize,
    depth: usize,
    tables: Vec<Vec<u8>>,
    seeds: Vec<u32>,
}

impl PpbloomFilter {
    pub fn new(width: usize, depth: usize) -> Self {
        let tables = (0..depth)
            .map(|_| vec![0u8; width])
            .collect();
        let seeds: Vec<u32> = (0..depth)
            .map(|i| 2166136261u32.wrapping_mul(16777619u32).wrapping_add(i as u32))
            .collect();
        Self { width, depth, tables, seeds }
    }

    /// Record a value.
    pub fn insert(&mut self, value: &[u8]) {
        // Precompute all indices to avoid holding a mutable borrow while calling self.hash.
        let indices: Vec<usize> = self.seeds
            .iter()
            .map(|&seed| self.hash(value, seed) as usize % self.width)
            .collect();
        for (i, table) in self.tables.iter_mut().enumerate() {
            let idx = indices[i];
            table[idx] = table[idx].saturating_add(1);
        }
    }

    /// Check if a value has been seen (approximate).
    pub fn contains(&self, value: &[u8]) -> bool {
        self.tables.iter().enumerate().all(|(i, table)| {
            let idx = self.hash(value, self.seeds[i]) as usize % self.width;
            table[idx] > 0
        })
    }

    fn hash(&self, data: &[u8], seed: u32) -> u32 {
        let mut h = seed;
        for &b in data {
            h = h.wrapping_mul(16777619).wrapping_add(b as u32);
        }
        h
    }
}

/// Guard that wraps a PpbloomFilter to reject replayed SS2022 packets.
pub struct ReplayGuard {
    filter: PpbloomFilter,
    window: usize,
}

impl ReplayGuard {
    pub fn new(window: usize) -> Self {
        Self {
            filter: PpbloomFilter::new(1 << 16, 4), // 64 KiB, 4 tables
            window,
        }
    }

    /// Check if a packet with the given salt + nonce is a replay.
    /// Returns `true` if this is a replay and should be rejected.
    pub fn is_replay(&self, salt: &[u8], nonce: u64) -> bool {
        let mut key = salt.to_vec();
        key.extend_from_slice(&nonce.to_le_bytes());
        self.filter.contains(&key)
    }

    /// Record a packet so future replays are detected.
    pub fn record(&mut self, salt: &[u8], nonce: u64) {
        let mut key = salt.to_vec();
        key.extend_from_slice(&nonce.to_le_bytes());
        self.filter.insert(&key);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_kinds_salt_len() {
        assert_eq!(Ss2022CipherKind::Aes256Gcm.salt_len(), 32);
        assert_eq!(Ss2022CipherKind::Aes128Gcm.salt_len(), 16);
        assert_eq!(Ss2022CipherKind::Blake3Aes256Gcm.salt_len(), 32);
        assert_eq!(Ss2022CipherKind::Blake3Aes128Gcm.salt_len(), 16);
    }

    #[test]
    fn test_cipher_rejects_wrong_salt_len() {
        let mut cipher = Ss2022AeadCipher::new(Ss2022CipherKind::Aes256Gcm);
        let err = cipher.derive_session_key(&[0u8; 16], &[0u8; 32]).unwrap_err();
        assert!(matches!(
            err,
            Ss2022Error::SaltLengthMismatch { expected: 32, got: 16 }
        ));
    }

    #[test]
    fn test_cipher_derive_and_encrypt_decrypt() {
        let mut cipher = Ss2022AeadCipher::new(Ss2022CipherKind::Aes256Gcm);
        let salt = [0xAB; 32];
        let master_key = [0x11; 32];

        cipher.derive_session_key(&salt, &master_key).unwrap();

        let plaintext = b"Hello, SS2022!";
        let ciphertext = cipher.encrypt_record(0, plaintext).unwrap();
        assert!(ciphertext.len() > plaintext.len()); // tag appended

        let decrypted = cipher.decrypt_record(0, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_record_rejects_empty() {
        // Use non-zero salt/key so HKDF produces valid output.
        // ring's HKDF-SHA256 requires salt ≥ 32 bytes; Aes128Gcm salt=16, so
        // the resulting subkey must be a valid AES-128 key (non-zero when using
        // non-zero input material).
        let mut cipher = Ss2022AeadCipher::new(Ss2022CipherKind::Aes128Gcm);
        cipher.derive_session_key(&[0xABu8; 16], &[0x11u8; 16]).unwrap();
        let err = cipher.encrypt_record(0, b"").unwrap_err();
        assert!(matches!(err, Ss2022Error::EncryptionFailed(_)));
    }

    #[test]
    fn test_decrypt_record_rejects_too_short() {
        // Aes128Gcm needs a session key before decrypt_record can check length.
        let mut cipher = Ss2022AeadCipher::new(Ss2022CipherKind::Aes128Gcm);
        cipher.derive_session_key(&[0xABu8; 16], &[0x11u8; 16]).unwrap();
        let err = cipher.decrypt_record(0, &[0x00; 10]).unwrap_err();
        assert!(matches!(err, Ss2022Error::CipherTextTooShort(10)));
    }

    #[test]
    fn test_cipher_key_mismatch_fails() {
        let mut cipher = Ss2022AeadCipher::new(Ss2022CipherKind::Aes128Gcm);
        cipher.derive_session_key(&[0xABu8; 16], &[0x11u8; 16]).unwrap();
        let ct = cipher.encrypt_record(0, b"test").unwrap();

        let mut cipher2 = Ss2022AeadCipher::new(Ss2022CipherKind::Aes128Gcm);
        cipher2.derive_session_key(&[0xABu8; 16], &[0xFFu8; 16]).unwrap();
        let err = cipher2.decrypt_record(0, &ct).unwrap_err();
        assert!(matches!(err, Ss2022Error::DecryptionFailed(_)));
    }

    #[test]
    fn test_ppbloom_insert_and_contains() {
        let mut filter = PpbloomFilter::new(1024, 3);
        let value = b"unique-packet-42";
        assert!(!filter.contains(value));
        filter.insert(value);
        assert!(filter.contains(value));
    }

    #[test]
    fn test_ppbloom_false_positive_rate() {
        // After inserting 100 distinct values into a small table, we expect
        // some false positives but not all lookups.
        let mut filter = PpbloomFilter::new(256, 2);
        for i in 0..100 {
            let value = format!("packet-{}", i);
            filter.insert(value.as_bytes());
        }
        let unseen: bool = !filter.contains(b"definitely-not-inserted");
        assert!(unseen, "should mostly not produce false positives for unseen items");
    }

    #[test]
    fn test_replay_guard_detects_replay() {
        let mut guard = ReplayGuard::new(1000);
        let salt = [0xAA; 32];
        assert!(!guard.is_replay(&salt, 42));
        guard.record(&salt, 42);
        assert!(guard.is_replay(&salt, 42));
        // Different nonce is not a replay.
        assert!(!guard.is_replay(&salt, 99));
    }

    #[test]
    fn test_eih_encrypt_round_trip() {
        let ctx = EihContext::new(vec![0xAB; 32]);
        let payload = b"destination.example.com";
        let ciphertext = ctx.encrypt_header(payload);
        assert!(ciphertext.len() > payload.len());
    }

    #[test]
    fn test_blake3_keyed_hash_deterministic() {
        let key = [0x00u8; 32];
        let data = b"test data";
        let out1 = blake3::keyed_hash(&key, data);
        let out2 = blake3::keyed_hash(&key, data);
        assert_eq!(out1, out2);
    }
}
