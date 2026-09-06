//! # Covert Blob-Queue AEAD & Asynchronous Dead-Drop Multiplexer
//!
//! Implements authenticated encryption envelope framing (SKB1) and multi-lane
//! key derivation for asynchronous covert dead-drop relays and blob storage queues.
//!

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::Engine;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::time::Duration;
use thiserror::Error;

/// Protocol constants for covert blob-queue envelopes.
pub const BLOB_MAGIC: &[u8; 4] = b"SKB1";
pub const BLOB_VERSION: u8 = 1;
pub const SESSION_ID_LEN: usize = 16;
pub const KEY_LEN: usize = 32;
pub const HEADER_LEN: usize = 39;
pub const MAX_SEQUENCE: u64 = (1 << 56) - 1;

pub const DIRECTION_UP: u8 = 1;
pub const DIRECTION_DOWN: u8 = 2;
pub const FLAG_DATA: u8 = 0;
pub const FLAG_FINAL: u8 = 1;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum BlobError {
    #[error("envelope data is too short: {0} < 39")]
    TooShort(usize),
    #[error("bad envelope magic")]
    BadMagic,
    #[error("unsupported envelope version: {0}")]
    UnsupportedVersion(u8),
    #[error("ciphertext length mismatch")]
    CiphertextLengthMismatch,
    #[error("plaintext length mismatch")]
    PlaintextLengthMismatch,
    #[error("sequence out of supported nonce range")]
    SequenceOutOfRange,
    #[error("invalid key length")]
    InvalidKeyLength,
    #[error("crypto operation failed: {0}")]
    CryptoError(String),
    #[error("key decoding failed: {0}")]
    KeyDecodeError(String),
}

/// Parsed covert blob envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobEnvelope {
    pub session_id: [u8; 16],
    pub direction: u8,
    pub sequence: u64,
    pub flags: u8,
    pub plaintext_len: u32,
    pub ciphertext: Vec<u8>,
}

/// Computes the 12-byte nonce for AES-GCM:
/// Bytes 0..4: session_id[0..4]
/// Byte 4: direction
/// Bytes 5..12: 7 bytes of sequence (big-endian)
pub fn compute_nonce(sid: &[u8; 16], direction: u8, sequence: u64) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[0..4].copy_from_slice(&sid[0..4]);
    out[4] = direction;
    for i in 0..7 {
        out[11 - i] = (sequence >> (8 * i)) as u8;
    }
    out
}

/// Derives a 32-byte master key from a secret string.
/// Supports "hex:<hex>", "base64:<b64>", or standard string with HKDF-SHA256.
pub fn derive_blob_key(secret: &str) -> Result<[u8; 32], BlobError> {
    let value = secret.trim();
    if let Some(hex_val) = value.strip_prefix("hex:") {
        let mut key = [0u8; 32];
        let bytes = hex_decode(hex_val).map_err(|e| BlobError::KeyDecodeError(e))?;
        if bytes.len() != 32 {
            return Err(BlobError::InvalidKeyLength);
        }
        key.copy_from_slice(&bytes);
        Ok(key)
    } else if let Some(b64_val) = value.strip_prefix("base64:") {
        let mut key = [0u8; 32];
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64_val)
            .map_err(|e| BlobError::KeyDecodeError(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(BlobError::InvalidKeyLength);
        }
        key.copy_from_slice(&bytes);
        Ok(key)
    } else {
        let hk = Hkdf::<Sha256>::new(Some(b"skirk-v1-static-salt"), value.as_bytes());
        let mut key = [0u8; 32];
        hk.expand(b"skirk-blobq-aead-key", &mut key)
            .map_err(|_| BlobError::CryptoError("HKDF expand failed".to_string()))?;
        Ok(key)
    }
}

/// Derives a multi-lane subkey for a session and multiplexing lane.
pub fn derive_mux_lane_key_v4(
    secret: &str,
    sid: &[u8; 16],
    direction: u8,
    client_id: &str,
    run_id: &str,
    lane: u8,
) -> Result<[u8; 32], BlobError> {
    let base_key = derive_blob_key(secret)?;
    let client_id = client_id.trim();
    let run_id = run_id.trim();
    if client_id.is_empty() || run_id.is_empty() {
        return Err(BlobError::CryptoError("client_id and run_id required".to_string()));
    }

    let mut info = Vec::with_capacity(32 + 16 + client_id.len() + run_id.len() + 6);
    info.extend_from_slice(b"skirk-mux-lane-aead-v4");
    info.extend_from_slice(sid);
    info.push(direction);
    info.extend_from_slice(client_id.as_bytes());
    info.push(0);
    info.extend_from_slice(run_id.as_bytes());
    info.push(0);
    info.push(lane);

    let hk = Hkdf::<Sha256>::new(Some(b"skirk-v4-mux-lane-salt"), &base_key);
    let mut lane_key = [0u8; 32];
    hk.expand(&info, &mut lane_key)
        .map_err(|_| BlobError::CryptoError("Mux lane HKDF expand failed".to_string()))?;

    Ok(lane_key)
}

/// Encrypts and frames a plaintext buffer into an authenticated SKB1 envelope.
pub fn seal_blob_envelope(
    key: &[u8; 32],
    sid: &[u8; 16],
    direction: u8,
    sequence: u64,
    plaintext: &[u8],
    is_final: bool,
) -> Result<Vec<u8>, BlobError> {
    if sequence > MAX_SEQUENCE {
        return Err(BlobError::SequenceOutOfRange);
    }

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce_bytes = compute_nonce(sid, direction, sequence);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let flags = if is_final { FLAG_FINAL } else { FLAG_DATA };
    let overhead = 16usize; // AES-GCM tag length
    let ciphertext_len = (plaintext.len() + overhead) as u32;

    let mut header = [0u8; HEADER_LEN];
    header[0..4].copy_from_slice(BLOB_MAGIC);
    header[4] = BLOB_VERSION;
    header[5..21].copy_from_slice(sid);
    header[21] = direction;
    header[22] = flags;
    header[23..31].copy_from_slice(&sequence.to_be_bytes());
    header[31..35].copy_from_slice(&(plaintext.len() as u32).to_be_bytes());
    header[35..39].copy_from_slice(&ciphertext_len.to_be_bytes());

    let payload = Payload {
        msg: plaintext,
        aad: &header,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|e| BlobError::CryptoError(e.to_string()))?;

    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&ciphertext);

    Ok(out)
}

/// Parses and decrypts an SKB1 authenticated envelope.
pub fn open_blob_envelope(
    key: &[u8; 32],
    data: &[u8],
) -> Result<(BlobEnvelope, Vec<u8>), BlobError> {
    if data.len() < HEADER_LEN {
        return Err(BlobError::TooShort(data.len()));
    }

    let header = &data[..HEADER_LEN];
    if &header[0..4] != BLOB_MAGIC {
        return Err(BlobError::BadMagic);
    }
    if header[4] != BLOB_VERSION {
        return Err(BlobError::UnsupportedVersion(header[4]));
    }

    let mut sid = [0u8; 16];
    sid.copy_from_slice(&header[5..21]);
    let direction = header[21];
    let flags = header[22];

    let sequence = u64::from_be_bytes(header[23..31].try_into().unwrap());
    let plaintext_len = u32::from_be_bytes(header[31..35].try_into().unwrap());
    let ciphertext_len = u32::from_be_bytes(header[35..39].try_into().unwrap());

    if (ciphertext_len as usize) != data.len() - HEADER_LEN {
        return Err(BlobError::CiphertextLengthMismatch);
    }

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce_bytes = compute_nonce(&sid, direction, sequence);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = &data[HEADER_LEN..];
    let payload = Payload {
        msg: ciphertext,
        aad: header,
    };

    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|e| BlobError::CryptoError(e.to_string()))?;

    if plaintext.len() != (plaintext_len as usize) {
        return Err(BlobError::PlaintextLengthMismatch);
    }

    let envelope = BlobEnvelope {
        session_id: sid,
        direction,
        sequence,
        flags,
        plaintext_len,
        ciphertext: ciphertext.to_vec(),
    };

    Ok((envelope, plaintext))
}

/// Helper hex decoder without external dependencies.
fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("Odd hex string length".to_string());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_val(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("Invalid hex character: {}", c as char)),
    }
}

/// Stream coalescing tier based on pending payload size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoalesceTier {
    Interactive,
    Medium,
    Bulk,
    ForcedBulk,
}

impl CoalesceTier {
    pub fn delay(&self) -> Duration {
        match self {
            CoalesceTier::Interactive => Duration::from_millis(5),
            CoalesceTier::Medium => Duration::from_millis(50),
            CoalesceTier::Bulk => Duration::from_millis(75),
            CoalesceTier::ForcedBulk => Duration::from_millis(100),
        }
    }

    pub fn max_age(&self) -> Duration {
        match self {
            CoalesceTier::Interactive => Duration::from_millis(15),
            CoalesceTier::Medium => Duration::from_millis(75),
            CoalesceTier::Bulk => Duration::from_millis(250),
            CoalesceTier::ForcedBulk => Duration::from_millis(1000),
        }
    }
}

/// Adaptive stream coalescer determining optimal packet batching to balance latency and throughput.
pub struct AdaptiveStreamCoalescer;

impl AdaptiveStreamCoalescer {
    pub const INTERACTIVE_THRESHOLD: usize = 8 * 1024;
    pub const BULK_THRESHOLD: usize = 64 * 1024;
    pub const FORCED_BULK_THRESHOLD: usize = 256 * 1024;

    /// Evaluates accumulated buffer size to select the active coalescing tier.
    pub fn evaluate_tier(buffered_bytes: usize) -> CoalesceTier {
        if buffered_bytes < Self::INTERACTIVE_THRESHOLD {
            CoalesceTier::Interactive
        } else if buffered_bytes < Self::BULK_THRESHOLD {
            CoalesceTier::Medium
        } else if buffered_bytes < Self::FORCED_BULK_THRESHOLD {
            CoalesceTier::Bulk
        } else {
            CoalesceTier::ForcedBulk
        }
    }

    /// Determines whether the buffered data should be flushed immediately.
    pub fn should_flush(buffered_bytes: usize, age: Duration) -> bool {
        if buffered_bytes == 0 {
            return false;
        }
        let tier = Self::evaluate_tier(buffered_bytes);
        age >= tier.max_age() || buffered_bytes >= Self::FORCED_BULK_THRESHOLD
    }
}
