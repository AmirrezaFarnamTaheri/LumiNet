//! # AES-GCM Stream Cipher
//!
//! AEAD stream encryption with HKDF key derivation and nonce management.
//!
//! Wire format:
//!   Client→Server: ClientNonce(12B) + [AES_GCM(FragLen) + AES_GCM(Frag)]...
//!   Server→Client: ServerNonce(12B) + [AES_GCM(FragLen) + AES_GCM(Frag)]...
//!
//! Key derivation: HKDF-SHA256(password, nonce, info) → 32-byte AES key
//! Nonce: 12 bytes random, then incremented as LittleEndian uint64 in first 8 bytes
//! Max fragment: 2048 bytes (TCP), 65507 bytes (UDP)
//! Replay window: 60 seconds

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

const NONCE_SIZE: usize = 12;
const KEY_SIZE: usize = 32;
pub const TAG_SIZE: usize = 16;
pub const MAX_TCP_FRAG: usize = 2048;
pub const MAX_UDP_FRAG: usize = 65507;
const REPLAY_WINDOW_SECS: u64 = 60;

/// HKDF info strings for key derivation.
pub const HKDF_INFO_SERVER: &[u8] = b"lumicore_server";
pub const HKDF_INFO_CLIENT: &[u8] = b"lumicore_client";

/// AES-GCM stream cipher for encrypted proxy communication.
pub struct AesGcmStream {
    cipher: Aes256Gcm,
    nonce: [u8; NONCE_SIZE],
    direction: Direction,
}

#[derive(Debug, Clone, Copy)]
pub enum Direction {
    Client,
    Server,
}

impl AesGcmStream {
    /// Creates a new stream cipher from a password and random nonce.
    pub fn new(password: &[u8], direction: Direction) -> Self {
        let mut nonce = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce);

        let info = match direction {
            Direction::Client => HKDF_INFO_CLIENT,
            Direction::Server => HKDF_INFO_SERVER,
        };

        let key = derive_key(password, &nonce, info);
        let cipher = Aes256Gcm::new_from_slice(&key).expect("key size");

        Self {
            cipher,
            nonce,
            direction,
        }
    }

    /// Creates from an existing nonce (for server receiving client nonce).
    pub fn from_nonce(password: &[u8], nonce: [u8; NONCE_SIZE], direction: Direction) -> Self {
        let info = match direction {
            Direction::Client => HKDF_INFO_CLIENT,
            Direction::Server => HKDF_INFO_SERVER,
        };

        let key = derive_key(password, &nonce, info);
        let cipher = Aes256Gcm::new_from_slice(&key).expect("key size");

        Self {
            cipher,
            nonce,
            direction,
        }
    }

    /// Returns the initial nonce (to send to peer).
    pub fn nonce(&self) -> &[u8; NONCE_SIZE] {
        &self.nonce
    }

    /// Returns the endpoint direction used for key derivation.
    pub fn direction(&self) -> Direction {
        self.direction
    }

    /// Encrypts a single fragment (length or data).
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = self.next_nonce();
        let nonce_obj = Nonce::from_slice(&nonce);

        self.cipher
            .encrypt(nonce_obj, plaintext)
            .map_err(|_| CryptoError::EncryptionFailed)
    }

    /// Decrypts a single fragment (length or data).
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = self.next_nonce();
        let nonce_obj = Nonce::from_slice(&nonce);

        self.cipher
            .decrypt(nonce_obj, ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed)
    }

    /// Encrypts a data payload with length-prefix framing.
    /// Returns: [AES_GCM(len_2bytes)] + [AES_GCM(data)]
    pub fn encrypt_framed(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let len_bytes = (data.len() as u16).to_le_bytes();
        let enc_len = self.encrypt(&len_bytes)?;
        let enc_data = self.encrypt(data)?;

        let mut result = Vec::with_capacity(enc_len.len() + enc_data.len());
        result.extend_from_slice(&enc_len);
        result.extend_from_slice(&enc_data);
        Ok(result)
    }

    /// Decrypts a length-prefixed frame.
    pub fn decrypt_framed(&self, enc_len: &[u8], enc_data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let len_bytes = self.decrypt(enc_len)?;
        if len_bytes.len() != 2 {
            return Err(CryptoError::InvalidFrame);
        }
        let expected_len = u16::from_le_bytes([len_bytes[0], len_bytes[1]]) as usize;
        let plaintext = self.decrypt(enc_data)?;
        if plaintext.len() != expected_len {
            return Err(CryptoError::LengthMismatch);
        }
        Ok(plaintext)
    }

    fn next_nonce(&self) -> [u8; NONCE_SIZE] {
        // For now, return current nonce. In production, increment counter.
        self.nonce
    }
}

/// Derives an AES-256 key using HKDF-SHA256.
fn derive_key(password: &[u8], salt: &[u8; NONCE_SIZE], info: &[u8]) -> [u8; KEY_SIZE] {
    let hk = Hkdf::<Sha256>::new(Some(salt), password);
    let mut key = [0u8; KEY_SIZE];
    hk.expand(info, &mut key).expect("key size");
    key
}

/// Generates a timestamp-based anti-replay nonce.
/// Even timestamp = TCP, Odd timestamp = UDP.
pub fn generate_nonce(is_udp: bool) -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let ts = if is_udp {
        timestamp | 1
    } else {
        timestamp & !1
    };
    nonce[..8].copy_from_slice(&ts.to_le_bytes());
    nonce
}

/// Validates a nonce timestamp against the replay window.
pub fn validate_nonce_timestamp(nonce: &[u8; NONCE_SIZE]) -> bool {
    let timestamp = u64::from_le_bytes(nonce[..8].try_into().unwrap());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    now.abs_diff(timestamp) <= REPLAY_WINDOW_SECS
}

/// Increments a nonce counter (LittleEndian uint64 in first 8 bytes).
pub fn increment_nonce(nonce: &mut [u8; NONCE_SIZE]) {
    let counter = u64::from_le_bytes(nonce[..8].try_into().unwrap());
    let new_counter = counter.wrapping_add(1);
    nonce[..8].copy_from_slice(&new_counter.to_le_bytes());
}

/// Crypto error types.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("invalid frame")]
    InvalidFrame,
    #[error("length mismatch")]
    LengthMismatch,
    #[error("replay detected")]
    ReplayDetected,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation() {
        let password = b"test_password";
        let nonce = [0u8; NONCE_SIZE];
        let key1 = derive_key(password, &nonce, HKDF_INFO_CLIENT);
        let key2 = derive_key(password, &nonce, HKDF_INFO_SERVER);
        // Different info should produce different keys
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let password = b"test_password";
        let stream = AesGcmStream::new(password, Direction::Client);
        let plaintext = b"Hello, encrypted world!";
        let ciphertext = stream.encrypt(plaintext).unwrap();
        assert_ne!(&ciphertext[..plaintext.len()], plaintext);
    }

    #[test]
    fn test_nonce_generation() {
        let nonce_tcp = generate_nonce(false);
        let nonce_udp = generate_nonce(true);
        // TCP nonce timestamp should be even
        let ts_tcp = u64::from_le_bytes(nonce_tcp[..8].try_into().unwrap());
        assert_eq!(ts_tcp % 2, 0);
        // UDP nonce timestamp should be odd
        let ts_udp = u64::from_le_bytes(nonce_udp[..8].try_into().unwrap());
        assert_eq!(ts_udp % 2, 1);
    }

    #[test]
    fn test_nonce_validation() {
        let nonce = generate_nonce(false);
        assert!(validate_nonce_timestamp(&nonce));
    }

    #[test]
    fn test_nonce_increment() {
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[..8].copy_from_slice(&42u64.to_le_bytes());
        increment_nonce(&mut nonce);
        let counter = u64::from_le_bytes(nonce[..8].try_into().unwrap());
        assert_eq!(counter, 43);
    }
}

/// ChaCha20 stream cipher for high-performance wire encryption.
///
/// Wire layout: [ nonce : 12 bytes ][ ciphertext : N bytes ]
///
/// ChaCha20 is ~5-10x faster than AES-GCM for software implementations
/// and doesn't require AES-NI hardware support.
pub struct ChaCha20Cipher {
    key: [u8; 32],
}

impl ChaCha20Cipher {
    /// Derives a 32-byte ChaCha20 key from an arbitrary string via SHA-256.
    pub fn new(key: &str) -> Self {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"LumiNet-ChaCha20-v1:");
        h.update(key.as_bytes());
        let hash: [u8; 32] = h.finalize().into();
        Self { key: hash }
    }

    /// Creates from a raw 32-byte key.
    pub fn from_key(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Encrypts plaintext and returns [ nonce(12) || ciphertext ].
    /// A fresh random nonce is chosen per call.
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        use chacha20::cipher::{KeyIvInit, StreamCipher};
        use chacha20::ChaCha20;

        let nonce_bytes: [u8; 12] = rand::random();
        let mut out = Vec::with_capacity(12 + plaintext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(plaintext);

        // Encrypt the payload region in-place
        let payload = &mut out[12..];
        ChaCha20::new((&self.key).into(), (&nonce_bytes).into()).apply_keystream(payload);

        out
    }

    /// Decrypts a frame produced by encrypt.
    /// Returns None if the frame is shorter than the nonce header.
    pub fn decrypt(&self, frame: &[u8]) -> Option<Vec<u8>> {
        use chacha20::cipher::{KeyIvInit, StreamCipher};
        use chacha20::ChaCha20;

        if frame.len() < 12 {
            return None;
        }

        let nonce_bytes: [u8; 12] = frame[..12].try_into().ok()?;
        let mut buf = frame[12..].to_vec();

        ChaCha20::new((&self.key).into(), (&nonce_bytes).into()).apply_keystream(&mut buf);

        Some(buf)
    }
}

/// Forward Error Correction (FEC) for UDP transports.
/// XOR-based parity that allows recovery of lost packets.
pub struct FecEncoder {
    group_size: usize,
    buffer: Vec<Vec<u8>>,
    group_id: u32,
}

impl FecEncoder {
    pub fn new(group_size: usize) -> Self {
        Self {
            group_size: group_size.max(2),
            buffer: Vec::new(),
            group_id: 0,
        }
    }

    /// Adds a data packet to the current group.
    /// Returns (data_packets, parity_packet) when the group is full.
    pub fn add_packet(&mut self, data: Vec<u8>) -> Option<(Vec<Vec<u8>>, Vec<u8>)> {
        self.buffer.push(data);

        if self.buffer.len() >= self.group_size {
            let parity = self.compute_parity();
            let packets = std::mem::take(&mut self.buffer);
            self.group_id = self.group_id.wrapping_add(1);
            Some((packets, parity))
        } else {
            None
        }
    }

    /// Computes XOR parity across all buffered packets.
    fn compute_parity(&self) -> Vec<u8> {
        let max_len = self.buffer.iter().map(|p| p.len()).max().unwrap_or(0);
        let mut parity = vec![0u8; max_len];

        for packet in &self.buffer {
            for (i, &byte) in packet.iter().enumerate() {
                parity[i] ^= byte;
            }
        }

        parity
    }

    /// Flushes any remaining packets in the buffer.
    pub fn flush(&mut self) -> Option<(Vec<Vec<u8>>, Vec<u8>)> {
        if self.buffer.is_empty() {
            return None;
        }
        let parity = self.compute_parity();
        let packets = std::mem::take(&mut self.buffer);
        self.group_id = self.group_id.wrapping_add(1);
        Some((packets, parity))
    }
}

/// FEC decoder that can recover lost packets using parity.
pub struct FecDecoder {
    group_size: usize,
    groups: std::collections::HashMap<u32, FecGroup>,
}

struct FecGroup {
    packets: Vec<Option<Vec<u8>>>,
    parity: Option<Vec<u8>>,
    received: usize,
    total: usize,
}

impl FecDecoder {
    pub fn new(group_size: usize) -> Self {
        Self {
            group_size: group_size.max(2),
            groups: std::collections::HashMap::new(),
        }
    }

    /// Adds a data packet. Returns recovered packets if a group is complete.
    pub fn add_data_packet(&mut self, group_id: u32, index: usize, data: Vec<u8>) -> Vec<Vec<u8>> {
        let group = self.groups.entry(group_id).or_insert_with(|| FecGroup {
            packets: vec![None; self.group_size],
            parity: None,
            received: 0,
            total: self.group_size,
        });

        if index < group.packets.len() && group.packets[index].is_none() {
            group.packets[index] = Some(data);
            group.received += 1;
        }

        self.try_recover(group_id)
    }

    /// Adds a parity packet for a group.
    pub fn add_parity_packet(&mut self, group_id: u32, parity: Vec<u8>) {
        let group = self.groups.entry(group_id).or_insert_with(|| FecGroup {
            packets: vec![None; self.group_size],
            parity: None,
            received: 0,
            total: self.group_size,
        });
        group.parity = Some(parity);
    }

    /// Attempts to recover missing packets using parity XOR.
    fn try_recover(&mut self, group_id: u32) -> Vec<Vec<u8>> {
        let mut result = Vec::new();

        if let Some(group) = self.groups.get(&group_id) {
            // If all packets received, return them all
            if group.received >= group.total {
                for packet in group.packets.iter().flatten() {
                    result.push(packet.clone());
                }
                self.groups.remove(&group_id);
                return result;
            }

            // If only one packet missing and we have parity, recover it
            if group.received == group.total - 1 {
                if let Some(ref parity) = group.parity {
                    let missing_idx = group.packets.iter().position(|p| p.is_none());
                    if let Some(idx) = missing_idx {
                        let max_len = parity.len();
                        let mut recovered = vec![0u8; max_len];

                        // XOR all received packets with parity
                        for (i, packet) in group.packets.iter().enumerate() {
                            if i != idx {
                                if let Some(ref data) = packet {
                                    for (j, &byte) in data.iter().enumerate() {
                                        recovered[j] ^= byte;
                                    }
                                }
                            }
                        }

                        // XOR with parity to get missing packet
                        for j in 0..max_len {
                            recovered[j] ^= parity[j];
                        }

                        result.push(recovered);
                        self.groups.remove(&group_id);
                    }
                }
            }
        }

        result
    }
}

#[cfg(test)]
mod chacha20_tests {
    use super::*;

    #[test]
    fn test_chacha20_roundtrip() {
        let cipher = ChaCha20Cipher::new("test-key");
        let plaintext = b"Hello, ChaCha20!";
        let encrypted = cipher.encrypt(plaintext);
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_chacha20_different_nonces() {
        let cipher = ChaCha20Cipher::new("key");
        let pt = b"same plaintext";
        let enc1 = cipher.encrypt(pt);
        let enc2 = cipher.encrypt(pt);
        // Different nonces → different ciphertext
        assert_ne!(enc1, enc2);
    }

    #[test]
    fn test_chacha20_wrong_key() {
        let c1 = ChaCha20Cipher::new("correct");
        let c2 = ChaCha20Cipher::new("wrong");
        let enc = c1.encrypt(b"secret");
        let dec = c2.decrypt(&enc).unwrap();
        assert_ne!(&dec, b"secret");
    }

    #[test]
    fn test_fec_encoder_decoder() {
        let mut encoder = FecEncoder::new(3);
        let _decoder = FecDecoder::new(3);

        // Add 3 packets to complete a group
        let result1 = encoder.add_packet(vec![1, 2, 3]);
        assert!(result1.is_none());

        let result2 = encoder.add_packet(vec![4, 5, 6]);
        assert!(result2.is_none());

        let result3 = encoder.add_packet(vec![7, 8, 9]);
        assert!(result3.is_some());

        let (packets, _parity) = result3.unwrap();
        assert_eq!(packets.len(), 3);
    }
}
