//! Single-Seal AES-256-GCM Batch Envelope and Multiplexed Frame Codec.
//!
//! Provides the wire-format frame serialization and AES-256-GCM batch envelope
//! Enforces O(1) crypto overhead per HTTP batch with zero-copy unmarshaling.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;
use rand::RngCore;
use thiserror::Error;

pub const FLAG_SYN: u8 = 1 << 0; // First frame for session, carries target
pub const FLAG_FIN: u8 = 1 << 1; // Sender closing write side
pub const FLAG_ACK: u8 = 1 << 2; // ACK / keepalive probe
pub const FLAG_RST: u8 = 1 << 3; // Session reset

pub const SESSION_ID_LEN: usize = 16;
pub const CLIENT_ID_LEN: usize = 16;
pub const MAX_TARGET_LEN: usize = 255;
pub const MAX_PAYLOAD_SIZE: usize = 10 * 1024 * 1024; // 10 MB sanity cap

pub const BATCH_FLAG_RAW: u8 = 0x00;
pub const BATCH_FLAG_FLATE: u8 = 0x01;
pub const BATCH_FLAG_ZSTD: u8 = 0x02;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FrameCodecError {
    #[error("Target length exceeds {MAX_TARGET_LEN}: {0}")]
    TargetTooLong(usize),
    #[error("Payload length exceeds {MAX_PAYLOAD_SIZE}: {0}")]
    PayloadTooLarge(usize),
    #[error("Frame data too short for header")]
    ShortHeader,
    #[error("Frame data too short for target")]
    ShortTarget,
    #[error("Frame data too short for payload")]
    ShortPayload,
    #[error("Batch envelope too short for AEAD nonce and tag")]
    EnvelopeTooShort,
    #[error("AEAD encryption failed")]
    EncryptionFailed,
    #[error("AEAD authentication/decryption failed")]
    DecryptionFailed,
    #[error("Base64 decoding failed: {0}")]
    Base64Error(String),
    #[error("Batch contains too many frames: {0}")]
    TooManyFrames(usize),
    #[error("Empty batch plaintext")]
    EmptyPlaintext,
    #[error("Unknown batch flag: 0x{0:02x}")]
    UnknownBatchFlag(u8),
    #[error("Batch header too short for client ID and count")]
    ShortBatchHeader,
    #[error("Batch frame length truncated")]
    TruncatedBatchFrame,
}

/// Logical message exchanged between client and relay server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub session_id: [u8; SESSION_ID_LEN],
    pub seq: u64,
    pub flags: u8,
    pub target: String,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(session_id: [u8; SESSION_ID_LEN], seq: u64, flags: u8) -> Self {
        Self {
            session_id,
            seq,
            flags,
            target: String::new(),
            payload: Vec::new(),
        }
    }

    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = target.into();
        self.flags |= FLAG_SYN;
        self
    }

    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = payload;
        self
    }

    pub fn has_flag(&self, flag: u8) -> bool {
        (self.flags & flag) != 0
    }

    pub fn encoded_len(&self) -> usize {
        SESSION_ID_LEN + 8 + 1 + 1 + self.target.len() + 4 + self.payload.len()
    }

    /// Serializes the frame into byte format:
    /// - `session_id`: 16 bytes
    /// - `seq`: u64 BE (8 bytes)
    /// - `flags`: u8 (1 byte)
    /// - `target_len`: u8 (1 byte)
    /// - `target`: N bytes
    /// - `payload_len`: u32 BE (4 bytes)
    /// - `payload`: N bytes
    pub fn marshal(&self) -> Result<Vec<u8>, FrameCodecError> {
        let mut buf = Vec::with_capacity(self.encoded_len());
        self.append_marshal(&mut buf)?;
        Ok(buf)
    }

    pub fn append_marshal(&self, dst: &mut Vec<u8>) -> Result<(), FrameCodecError> {
        if self.target.len() > MAX_TARGET_LEN {
            return Err(FrameCodecError::TargetTooLong(self.target.len()));
        }
        if self.payload.len() > MAX_PAYLOAD_SIZE {
            return Err(FrameCodecError::PayloadTooLarge(self.payload.len()));
        }

        dst.extend_from_slice(&self.session_id);
        dst.extend_from_slice(&self.seq.to_be_bytes());
        dst.push(self.flags);
        dst.push(self.target.len() as u8);
        dst.extend_from_slice(self.target.as_bytes());
        dst.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        dst.extend_from_slice(&self.payload);
        Ok(())
    }

    /// Deserializes a frame from bytes. Returns (Frame, consumed_bytes).
    pub fn unmarshal(data: &[u8]) -> Result<(Self, usize), FrameCodecError> {
        const MIN_HEADER: usize = SESSION_ID_LEN + 8 + 1 + 1 + 4;
        if data.len() < MIN_HEADER {
            return Err(FrameCodecError::ShortHeader);
        }

        let mut off = 0;
        let mut session_id = [0u8; SESSION_ID_LEN];
        session_id.copy_from_slice(&data[off..off + SESSION_ID_LEN]);
        off += SESSION_ID_LEN;

        let seq = u64::from_be_bytes(data[off..off + 8].try_into().unwrap());
        off += 8;

        let flags = data[off];
        off += 1;

        let tlen = data[off] as usize;
        off += 1;

        if data.len() < off + tlen + 4 {
            return Err(FrameCodecError::ShortTarget);
        }

        let target = if tlen > 0 {
            String::from_utf8_lossy(&data[off..off + tlen]).to_string()
        } else {
            String::new()
        };
        off += tlen;

        let plen = u32::from_be_bytes(data[off..off + 4].try_into().unwrap()) as usize;
        off += 4;

        if plen > MAX_PAYLOAD_SIZE {
            return Err(FrameCodecError::PayloadTooLarge(plen));
        }
        if data.len() < off + plen {
            return Err(FrameCodecError::ShortPayload);
        }

        let payload = if plen > 0 {
            data[off..off + plen].to_vec()
        } else {
            Vec::new()
        };
        off += plen;

        Ok((
            Frame {
                session_id,
                seq,
                flags,
                target,
                payload,
            },
            off,
        ))
    }
}

/// AES-256-GCM Single-Seal Batch Codec.
pub struct BatchCodec {
    cipher: Aes256Gcm,
}

impl BatchCodec {
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher = Aes256Gcm::new(key.into());
        Self { cipher }
    }

    /// Packs frames into an authenticated Base64 batch payload:
    /// - Nonce: 12 bytes
    /// - AEAD Sealed Ciphertext + Tag over:
    ///   - flags: 1 byte (0x00 raw)
    ///   - client_id: 16 bytes
    ///   - frame_count: u16 BE
    ///   - per frame: u32 BE length + marshaled frame bytes
    pub fn encode_batch(
        &self,
        client_id: &[u8; CLIENT_ID_LEN],
        frames: &[Frame],
    ) -> Result<String, FrameCodecError> {
        if frames.len() > 0xFFFF {
            return Err(FrameCodecError::TooManyFrames(frames.len()));
        }

        let mut plain = Vec::new();
        plain.push(BATCH_FLAG_RAW);
        plain.extend_from_slice(client_id);
        plain.extend_from_slice(&(frames.len() as u16).to_be_bytes());

        for f in frames {
            let encoded_len = f.encoded_len() as u32;
            plain.extend_from_slice(&encoded_len.to_be_bytes());
            f.append_marshal(&mut plain)?;
        }

        // Random 12-byte nonce
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plain.as_ref())
            .map_err(|_| FrameCodecError::EncryptionFailed)?;

        let mut envelope = Vec::with_capacity(12 + ciphertext.len());
        envelope.extend_from_slice(&nonce_bytes);
        envelope.extend_from_slice(&ciphertext);

        Ok(STANDARD_NO_PAD.encode(&envelope))
    }

    /// Decodes an authenticated Base64 batch payload, returning client_id and frames.
    pub fn decode_batch(&self, body: &str) -> Result<([u8; CLIENT_ID_LEN], Vec<Frame>), FrameCodecError> {
        let trimmed = body.trim().trim_end_matches('=');
        if trimmed.is_empty() {
            return Ok(([0u8; CLIENT_ID_LEN], Vec::new()));
        }

        let envelope = STANDARD_NO_PAD
            .decode(trimmed)
            .or_else(|_| STANDARD.decode(body.trim()))
            .map_err(|e| FrameCodecError::Base64Error(e.to_string()))?;

        if envelope.len() < 12 + 16 {
            return Err(FrameCodecError::EnvelopeTooShort);
        }

        let nonce = Nonce::from_slice(&envelope[..12]);
        let ciphertext = &envelope[12..];

        let plain = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| FrameCodecError::DecryptionFailed)?;

        if plain.is_empty() {
            return Err(FrameCodecError::EmptyPlaintext);
        }

        let flag = plain[0];
        if flag != BATCH_FLAG_RAW {
            return Err(FrameCodecError::UnknownBatchFlag(flag));
        }

        let mut off = 1;
        if plain.len() < off + CLIENT_ID_LEN + 2 {
            return Err(FrameCodecError::ShortBatchHeader);
        }

        let mut client_id = [0u8; CLIENT_ID_LEN];
        client_id.copy_from_slice(&plain[off..off + CLIENT_ID_LEN]);
        off += CLIENT_ID_LEN;

        let frame_count = u16::from_be_bytes(plain[off..off + 2].try_into().unwrap()) as usize;
        off += 2;

        let mut frames = Vec::with_capacity(frame_count);
        for _ in 0..frame_count {
            if plain.len() < off + 4 {
                return Err(FrameCodecError::TruncatedBatchFrame);
            }
            let flen = u32::from_be_bytes(plain[off..off + 4].try_into().unwrap()) as usize;
            off += 4;

            if plain.len() < off + flen {
                return Err(FrameCodecError::TruncatedBatchFrame);
            }

            let (f, consumed) = Frame::unmarshal(&plain[off..off + flen])?;
            if consumed != flen {
                return Err(FrameCodecError::TruncatedBatchFrame);
            }
            frames.push(f);
            off += flen;
        }

        Ok((client_id, frames))
    }
}
