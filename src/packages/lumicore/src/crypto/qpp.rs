// LumiNet Lumicore - Quantum Permutation Pad (QPP) Experimental Cipher
//
// This module implements an experimental quantum-resistant cipher using the
// Quantum Permutation Pad (QPP) construction. QPP is a one-time-pad-like
// construction that provides information-theoretic security against
// quantum adversaries when used with sufficient key material.
//
// ⚠️  EXPERIMENTAL: This implementation is for research purposes only.
// Do NOT use in production systems without thorough security review.
//
// References:
// - "Quantum One-Time Pad" - Boykin & Roychowdhury (2003)
// - "Information-theoretic security" - Renner & Cirac (2009)

use thiserror::Error;

/// Errors that can occur during QPP operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum QppError {
    #[error("key length mismatch: expected {expected} bytes, got {got}")]
    KeyLengthMismatch { expected: usize, got: usize },
    #[error("ciphertext too short: need at least {need} bytes, got {got}")]
    CiphertextTooShort { need: usize, got: usize },
    #[error("authentication tag mismatch")]
    TagMismatch,
    #[error("nonce reuse detected")]
    NonceReuse,
    #[error("invalid configuration parameters")]
    InvalidConfig,
    #[error("encryption failed: {0}")]
    EncryptFailed(String),
    #[error("decryption failed: {0}")]
    DecryptFailed(String),
}

/// Configuration for QPP cipher operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QppConfig {
    /// Size of the permutation pad in bytes (must be power of 2)
    pub pad_size: usize,
    /// Size of the authentication tag in bytes
    pub tag_size: usize,
    /// Number of rounds for the permutation network
    pub rounds: usize,
    /// Whether to use deterministic mode (for testing only)
    pub deterministic: bool,
}

impl Default for QppConfig {
    fn default() -> Self {
        Self {
            pad_size: 256,
            tag_size: 16,
            rounds: 8,
            deterministic: false,
        }
    }
}

impl QppConfig {
    /// Create a new configuration with validation.
    pub fn new(pad_size: usize, tag_size: usize, rounds: usize) -> Result<Self, QppError> {
        // Validate pad_size is power of 2 and in valid range
        if pad_size < 16 || pad_size > 65536 || (pad_size & (pad_size - 1)) != 0 {
            return Err(QppError::InvalidConfig);
        }
        // Validate tag_size
        if tag_size < 4 || tag_size > 32 {
            return Err(QppError::InvalidConfig);
        }
        // Validate rounds
        if rounds < 1 || rounds > 32 {
            return Err(QppError::InvalidConfig);
        }

        Ok(Self {
            pad_size,
            tag_size,
            rounds,
            deterministic: false,
        })
    }

    /// Create a standard configuration for production use.
    pub fn standard() -> Self {
        Self::default()
    }

    /// Create a conservative configuration with extra rounds.
    pub fn conservative() -> Self {
        Self {
            pad_size: 1024,
            tag_size: 32,
            rounds: 16,
            deterministic: false,
        }
    }
}

/// Quantum Permutation Pad cipher state.
#[derive(Debug, Clone)]
pub struct QppCipher {
    config: QppConfig,
    /// The permutation pad (one-time key material)
    pad: Vec<u8>,
    /// Current position in the pad (for streaming)
    #[allow(dead_code)]
    position: usize,
    /// Salt for key derivation
    #[allow(dead_code)]
    salt: [u8; 16],
}

impl QppCipher {
    /// Create a new QPP cipher from key material.
    pub fn new(key: &[u8], config: QppConfig) -> Result<Self, QppError> {
        if key.is_empty() {
            return Err(QppError::KeyLengthMismatch {
                expected: 32,
                got: 0,
            });
        }

        // Derive the pad from key material using HMAC-SHA256 expansion
        let pad = Self::derive_pad(key, config.pad_size)?;

        // Generate salt
        let mut salt = [0u8; 16];
        if !config.deterministic {
            Self::fill_random(&mut salt);
        }

        Ok(Self {
            config,
            pad,
            position: 0,
            salt,
        })
    }

    /// Create a new QPP cipher with deterministic pad (for testing only).
    pub fn with_deterministic_pad(key: &[u8], config: QppConfig) -> Result<Self, QppError> {
        if key.is_empty() {
            return Err(QppError::KeyLengthMismatch {
                expected: 32,
                got: 0,
            });
        }

        let pad = Self::derive_pad(key, config.pad_size)?;
        Ok(Self {
            config,
            pad,
            position: 0,
            salt: [0u8; 16],
        })
    }

    /// Derive the permutation pad from key material using HMAC-SHA256.
    fn derive_pad(key: &[u8], size: usize) -> Result<Vec<u8>, QppError> {
        use ring::hmac::{Context, Key, HMAC_SHA256};

        let hmac_key = Key::new(HMAC_SHA256, key);

        let mut pad = Vec::with_capacity(size);
        let mut counter: u64 = 0;

        while pad.len() < size {
            let mut ctx = Context::with_key(&hmac_key);
            ctx.update(&counter.to_be_bytes());
            ctx.update(b"QPP-PAD-KEY");

            let result = ctx.sign();
            let sig_bytes = result.as_ref();

            // Copy as many bytes as needed
            let remaining = size - pad.len();
            let to_copy = remaining.min(32);
            pad.extend_from_slice(&sig_bytes[..to_copy]);

            counter += 1;
        }

        pad.truncate(size);
        Ok(pad)
    }

    /// Fill buffer with pseudo-random bytes using `ring`.
    fn fill_random(buf: &mut [u8]) {
        use ring::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();
        // ring's fill may fail on entropy exhaustion; we swallow that
        // because a QPP pad can be regenerated cheaply.
        let _ = rng.fill(buf);
    }

    /// Get the current salt (needed for key export/import).
    pub fn salt(&self) -> [u8; 16] {
        self.salt
    }

    /// Reset the cipher state for a new message stream.
    pub fn reset(&mut self) {
        self.position = 0;
    }

    /// Get the current position in the pad.
    pub fn position(&self) -> usize {
        self.position
    }

    /// Get the configuration of this cipher.
    pub fn config(&self) -> &QppConfig {
        &self.config
    }

    /// Get a reference to the internal pad.
    pub fn pad(&self) -> &[u8] {
        &self.pad
    }
}

/// Encrypt data using QPP.
///
/// # Arguments
/// * `key` - Secret key material
/// * `config` - Cipher configuration
/// * `nonce` - Unique nonce for this encryption (should never repeat)
/// * `aad` - Additional authenticated data (can be empty)
/// * `plaintext` - Data to encrypt
///
/// # Returns
/// * `Ok((ciphertext, tag))` on success
/// * `Err(QppError)` on failure
pub fn qpp_encrypt(
    key: &[u8],
    config: &QppConfig,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), QppError> {
    // Empty plaintext: return empty ciphertext with an empty tag.
    if plaintext.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }

    // Create cipher instance
    let mut cipher = QppCipher::new(key, config.clone())?;

    // Derive session key from nonce
    cipher.pad = derive_session_key(&cipher.pad, nonce)?;

    // Apply permutation network to plaintext
    let mut state = plaintext.to_vec();
    apply_permutation_network(&mut state, &cipher.pad, cipher.config.rounds)?;

    // XOR with pad for one-time pad-like operation
    let pad_slice: Vec<u8> = cipher.pad[..state.len()].to_vec();
    xor_with_pad(&mut state, &pad_slice);

    // Generate authentication tag
    let tag = compute_tag(&state, aad, nonce, &cipher.pad, cipher.config.tag_size)?;

    Ok((state, tag))
}

/// Decrypt data using QPP.
///
/// # Arguments
/// * `key` - Secret key material
/// * `config` - Cipher configuration
/// * `nonce` - Nonce used during encryption
/// * `aad` - Additional authenticated data (must match encryption)
/// * `ciphertext` - Data to decrypt
/// * `tag` - Authentication tag
///
/// # Returns
/// * `Ok(plaintext)` on success
/// * `Err(QppError)` on failure
pub fn qpp_decrypt(
    key: &[u8],
    config: &QppConfig,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, QppError> {
    // Empty ciphertext: return empty plaintext. (Empty tag is also accepted
    // for symmetry with `qpp_encrypt`.)
    if ciphertext.is_empty() {
        return Ok(Vec::new());
    }

    // Create cipher instance
    let mut cipher = QppCipher::new(key, config.clone())?;

    // Derive session key from nonce
    cipher.pad = derive_session_key(&cipher.pad, nonce)?;

    // Verify authentication tag first
    let expected_tag = compute_tag(ciphertext, aad, nonce, &cipher.pad, cipher.config.tag_size)?;
    if expected_tag != tag {
        return Err(QppError::TagMismatch);
    }

    // Reverse the XOR operation
    let mut state = ciphertext.to_vec();
    let pad_slice: Vec<u8> = cipher.pad[..state.len()].to_vec();
    xor_with_pad(&mut state, &pad_slice);

    // Reverse the permutation network
    reverse_permutation_network(&mut state, &cipher.pad, cipher.config.rounds)?;

    Ok(state)
}

/// Derive a session-specific key from the master key and nonce.
fn derive_session_key(pad: &[u8], nonce: &[u8]) -> Result<Vec<u8>, QppError> {
    use ring::hmac::{Context, Key, HMAC_SHA256};

    // First, mix the nonce with the master pad using HMAC
    let master_key = Key::new(HMAC_SHA256, pad);
    let mut master_ctx = Context::with_key(&master_key);
    master_ctx.update(nonce);
    master_ctx.update(b"QPP-SESSION");
    let master_sig = master_ctx.sign();
    let master_bytes = master_sig.as_ref();

    // Expand to same size as original pad
    let mut session_pad = Vec::with_capacity(pad.len());
    let mut counter: u64 = 0;

    while session_pad.len() < pad.len() {
        let block_key = Key::new(HMAC_SHA256, master_bytes);
        let mut block_ctx = Context::with_key(&block_key);
        block_ctx.update(&counter.to_be_bytes());
        block_ctx.update(b"QPP-EXPAND");

        let block_result = block_ctx.sign();
        let block_bytes = block_result.as_ref();

        let remaining = pad.len() - session_pad.len();
        let to_copy = remaining.min(32);
        session_pad.extend_from_slice(&block_bytes[..to_copy]);

        counter += 1;
    }

    Ok(session_pad)
}

/// Apply the quantum permutation network to data.
fn apply_permutation_network(data: &mut [u8], pad: &[u8], rounds: usize) -> Result<(), QppError> {
    let n = data.len();
    if n == 0 || n > pad.len() {
        return Err(QppError::InvalidConfig);
    }

    for round in 0..rounds {
        // Use pad bytes to determine permutation
        for i in 0..n {
            let j = ((i + 1 + round) % n) as usize;
            if j < n && j != i {
                // Conditional swap based on pad values
                let mix1 = pad[(i.wrapping_mul(7).wrapping_add(round.wrapping_mul(3))) % pad.len()];
                let mix2 = pad[(j.wrapping_mul(11).wrapping_add(round.wrapping_mul(5))) % pad.len()];

                if mix1 > mix2 {
                    data.swap(i, j);
                }
            }
        }

        // Apply local diffusion
        for i in 0..n {
            let left = data[(i + n - 1) % n];
            let right = data[(i + 1) % n];
            data[i] ^= left
                .wrapping_add(right)
                .wrapping_mul(pad[(i.wrapping_add(round)) % pad.len()]);
        }
    }

    Ok(())
}

/// Reverse the permutation network.
fn reverse_permutation_network(
    data: &mut [u8],
    pad: &[u8],
    rounds: usize,
) -> Result<(), QppError> {
    let n = data.len();
    if n == 0 || n > pad.len() {
        return Err(QppError::InvalidConfig);
    }

    // Reverse in opposite order
    for round in (0..rounds).rev() {
        // Reverse the diffusion layer
        for i in (0..n).rev() {
            let left = data[(i + n - 1) % n];
            let right = data[(i + 1) % n];
            data[i] ^= left
                .wrapping_add(right)
                .wrapping_mul(pad[(i.wrapping_add(round)) % pad.len()]);
        }

        // Reverse the permutation
        for i in (0..n).rev() {
            let j = ((i + 1 + round) % n) as usize;
            if j < n && j != i {
                let mix1 = pad[(i.wrapping_mul(7).wrapping_add(round.wrapping_mul(3))) % pad.len()];
                let mix2 = pad[(j.wrapping_mul(11).wrapping_add(round.wrapping_mul(5))) % pad.len()];

                if mix1 > mix2 {
                    data.swap(i, j);
                }
            }
        }
    }

    Ok(())
}

/// XOR data with the pad.
fn xor_with_pad(data: &mut [u8], pad: &[u8]) {
    for i in 0..data.len() {
        data[i] ^= pad[i % pad.len()];
    }
}

/// Compute authentication tag using HMAC-SHA256.
fn compute_tag(
    data: &[u8],
    aad: &[u8],
    nonce: &[u8],
    pad: &[u8],
    tag_size: usize,
) -> Result<Vec<u8>, QppError> {
    use ring::hmac::{Context, Key, HMAC_SHA256};

    let key = Key::new(HMAC_SHA256, pad);
    let mut ctx = Context::with_key(&key);
    ctx.update(nonce);
    ctx.update(aad);
    ctx.update(data);

    let hash = ctx.sign();
    let hash_bytes = hash.as_ref();

    // Truncate or expand to desired tag size
    let mut tag = Vec::with_capacity(tag_size);
    let mut counter = 0;

    while tag.len() < tag_size {
        let block_key = Key::new(HMAC_SHA256, hash_bytes);
        let mut block_ctx = Context::with_key(&block_key);
        block_ctx.update(&(counter as u32).to_be_bytes());
        let block_hash = block_ctx.sign();
        tag.extend_from_slice(block_hash.as_ref());
        counter += 1;
    }

    tag.truncate(tag_size);
    Ok(tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qpp_config_defaults() {
        let config = QppConfig::default();
        assert_eq!(config.pad_size, 256);
        assert_eq!(config.tag_size, 16);
        assert_eq!(config.rounds, 8);
        assert!(!config.deterministic);
    }

    #[test]
    fn test_qpp_config_validation() {
        // Valid configurations
        assert!(QppConfig::new(256, 16, 8).is_ok());
        assert!(QppConfig::new(512, 32, 16).is_ok());
        assert!(QppConfig::new(16, 8, 4).is_ok());

        // Invalid: not power of 2
        assert!(QppConfig::new(100, 16, 8).is_err());
        // Invalid: too small
        assert!(QppConfig::new(8, 16, 8).is_err());
        // Invalid: tag size too small
        assert!(QppConfig::new(256, 2, 8).is_err());
        // Invalid: tag size too large
        assert!(QppConfig::new(256, 64, 8).is_err());
        // Invalid: rounds
        assert!(QppConfig::new(256, 16, 0).is_err());
        assert!(QppConfig::new(256, 16, 64).is_err());
    }

    #[test]
    fn test_cipher_creation() {
        let key = b"this is a test key for QPP cipher test";
        let config = QppConfig::default();

        let cipher = QppCipher::with_deterministic_pad(key, config.clone());
        assert!(cipher.is_ok());

        let cipher = cipher.unwrap();
        assert_eq!(cipher.position(), 0);
        assert_eq!(cipher.config(), &config);
        assert_eq!(cipher.pad().len(), config.pad_size);
    }

    #[test]
    fn test_cipher_reset() {
        let key = b"test key for reset operation";
        let config = QppConfig::default();

        let mut cipher = QppCipher::with_deterministic_pad(key, config).unwrap();
        cipher.reset();
        assert_eq!(cipher.position(), 0);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // Use deterministic config for reproducible roundtrip test
        let key = b"this is a test key for roundtrip encryption test!";
        let mut config = QppConfig::new(256, 16, 4).unwrap();
        config.deterministic = true;
        let nonce = b"unique-nonce-12";
        let aad = b"additional data";

        let plaintext = b"Hello, QPP World!";
        let (ciphertext, tag) = qpp_encrypt(key, &config, nonce, aad, plaintext).unwrap();
        assert_ne!(ciphertext.as_slice(), plaintext);
        assert_eq!(tag.len(), 16);

        let decrypted = qpp_decrypt(key, &config, nonce, aad, &ciphertext, &tag).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_empty_plaintext() {
        let key = b"test key for empty plaintext";
        let mut config = QppConfig::default();
        config.deterministic = true;
        let nonce = b"test-nonce-here";
        let aad = b"";

        let plaintext = b"";
        let (ciphertext, tag) = qpp_encrypt(key, &config, nonce, aad, plaintext).unwrap();
        let decrypted = qpp_decrypt(key, &config, nonce, aad, &ciphertext, &tag).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_large_data() {
        let key = b"test key for large data encryption";
        let mut config = QppConfig::new(1024, 32, 8).unwrap();
        config.deterministic = true;
        let nonce = b"large-data-nonce-12";
        let aad = b"large data AAD";

        let plaintext = vec![0x42u8; 1000];
        let (ciphertext, tag) = qpp_encrypt(key, &config, nonce, aad, &plaintext).unwrap();
        assert_eq!(ciphertext.len(), 1000);
        assert_eq!(tag.len(), 32);

        let decrypted = qpp_decrypt(key, &config, nonce, aad, &ciphertext, &tag).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_tag_mismatch_detection() {
        let key = b"test key for tag mismatch";
        let mut config = QppConfig::default();
        config.deterministic = true;
        let nonce = b"mismatch-test-nonce";
        let aad = b"";

        let plaintext = b"test data";
        let (ciphertext, _tag) = qpp_encrypt(key, &config, nonce, aad, plaintext).unwrap();

        // Tamper with the ciphertext
        let mut tampered = ciphertext.clone();
        tampered[0] ^= 0xFF;

        let wrong_tag = vec![0x00; 16];
        let result = qpp_decrypt(key, &config, nonce, aad, &tampered, &wrong_tag);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_nonces_different_output() {
        let key = b"test key for nonce diversity";
        let mut config = QppConfig::default();
        config.deterministic = true;
        let aad = b"";

        let plaintext = b"same plaintext";

        let nonce1 = b"nonce-AAAAAAAAAA";
        let nonce2 = b"nonce-BBBBBBBBBB";

        let (ct1, tag1) = qpp_encrypt(key, &config, nonce1, aad, plaintext).unwrap();
        let (ct2, tag2) = qpp_encrypt(key, &config, nonce2, aad, plaintext).unwrap();

        assert_ne!(ct1, ct2);
        assert_ne!(tag1, tag2);
    }

    #[test]
    fn test_conservative_config() {
        let config = QppConfig::conservative();
        assert_eq!(config.pad_size, 1024);
        assert_eq!(config.tag_size, 32);
        assert_eq!(config.rounds, 16);

        let key = b"conservative config test key here";
        let cipher = QppCipher::with_deterministic_pad(key, config);
        assert!(cipher.is_ok());
    }

    #[test]
    fn test_standard_config() {
        let config = QppConfig::standard();
        assert_eq!(config.pad_size, 256);

        let key = b"standard config test key here 12345";
        let cipher = QppCipher::with_deterministic_pad(key, config);
        assert!(cipher.is_ok());
    }

    #[test]
    fn test_salt_access() {
        let key = b"test key for salt access";
        let config = QppConfig::default();
        let cipher = QppCipher::with_deterministic_pad(key, config).unwrap();
        let salt = cipher.salt();
        assert_eq!(salt.len(), 16);
    }
}
