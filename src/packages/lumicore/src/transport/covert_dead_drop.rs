//! Covert Dead-Drop Cloud Storage Protocol & Wire Cryptography
//!
//! Ported and unified from `rahgozar-main` (`drive-wire` and `drive_crypto`).
//! Implements a dead-drop storage transport protocol:
//! 1. Structured RFC 4648 Base32 filename grammar for asynchronous cloud object polling
//! 2. 30-byte binary wire frame protocol with strict payload limits (4 MiB)
//! 3. X25519 key agreement, HKDF-SHA256 directional key derivation, and ChaCha20-Poly1305 AEAD
//! 4. Nonce binding with sequence numbers and AAD session verification
//! 5. 64-bit sliding anti-replay window

use std::fmt;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

/// Wire version for covert dead-drop frames.
pub const WIRE_VERSION: u8 = 1;

/// Fixed-size header length: 1 (ver) + 1 (kind) + 16 (sid) + 8 (seq) + 4 (len) = 30 bytes.
pub const HEADER_LEN: usize = 30;

/// Soft RAM payload limit for storage objects (4 MiB).
pub const MAX_PAYLOAD: u32 = 4 * 1024 * 1024;

/// 16-byte random session identifier.
pub type SessionId = [u8; 16];

/// Filename prefixes for dead-drop objects.
pub const PREFIX_HELLO: &str = "h_";
pub const PREFIX_C2R: &str = "c2r_";
pub const PREFIX_R2C: &str = "r2c_";

/// Transmission direction between client and relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// `c2r_*` — uploaded by client, polled by relay.
    ClientToRelay,
    /// `r2c_*` — uploaded by relay, polled by client.
    RelayToClient,
}

/// Category of storage filename.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilenameKind {
    Hello,
    Frame(Direction),
}

/// Structured filename representation for covert cloud storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CovertDeadDropFilename {
    pub kind: FilenameKind,
    pub sid: SessionId,
    /// Always 0 for Hello; strictly monotonic for data frames.
    pub seq: u64,
}

impl CovertDeadDropFilename {
    /// Renders filename to storage string: `<prefix><sid_b32>_<seq>`.
    pub fn format(&self) -> String {
        let prefix = match self.kind {
            FilenameKind::Hello => PREFIX_HELLO,
            FilenameKind::Frame(Direction::ClientToRelay) => PREFIX_C2R,
            FilenameKind::Frame(Direction::RelayToClient) => PREFIX_R2C,
        };
        format!("{}{}_{}", prefix, encode_sid_b32(&self.sid), self.seq)
    }

    /// Parses a storage filename into structured format.
    pub fn parse(name: &str) -> Option<Self> {
        let (kind, rest) = if let Some(r) = name.strip_prefix(PREFIX_C2R) {
            (FilenameKind::Frame(Direction::ClientToRelay), r)
        } else if let Some(r) = name.strip_prefix(PREFIX_R2C) {
            (FilenameKind::Frame(Direction::RelayToClient), r)
        } else if let Some(r) = name.strip_prefix(PREFIX_HELLO) {
            (FilenameKind::Hello, r)
        } else {
            return None;
        };

        let (sid_b32, seq_str) = rest.rsplit_once('_')?;
        let sid = decode_sid_b32(sid_b32)?;
        let seq: u64 = seq_str.parse().ok()?;
        if matches!(kind, FilenameKind::Hello) && seq != 0 {
            return None;
        }
        Some(CovertDeadDropFilename { kind, sid, seq })
    }
}

// ---- Base32 Encoding / Decoding (RFC 4648 lowercase, unpadded) ----
const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Encodes a 16-byte SessionId into 26 lowercase Base32 characters.
pub fn encode_sid_b32(sid: &SessionId) -> String {
    let mut out = String::with_capacity(26);
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;
    for &byte in sid {
        buffer = (buffer << 8) | (byte as u64);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1f) as usize;
            out.push(ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(ALPHABET[idx] as char);
    }
    out
}

/// Decodes a 26-character Base32 string into a 16-byte SessionId.
pub fn decode_sid_b32(s: &str) -> Option<SessionId> {
    if s.len() != 26 {
        return None;
    }
    let mut out: SessionId = [0u8; 16];
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;
    let mut out_idx: usize = 0;
    for c in s.bytes() {
        let v = match c {
            b'a'..=b'z' => c - b'a',
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        };
        buffer = (buffer << 5) | (v as u64);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            if out_idx >= 16 {
                return None;
            }
            out[out_idx] = ((buffer >> bits) & 0xff) as u8;
            out_idx += 1;
        }
    }
    if out_idx != 16 {
        return None;
    }
    Some(out)
}

/// Wire frame types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameKind {
    Hello = 0x01,
    Dial = 0x02,
    Data = 0x03,
    Close = 0x04,
    Ack = 0x05,
}

impl TryFrom<u8> for FrameKind {
    type Error = CovertWireError;

    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            0x01 => Ok(FrameKind::Hello),
            0x02 => Ok(FrameKind::Dial),
            0x03 => Ok(FrameKind::Data),
            0x04 => Ok(FrameKind::Close),
            0x05 => Ok(FrameKind::Ack),
            other => Err(CovertWireError::UnknownFrameKind(other)),
        }
    }
}

/// Binary frame exchanged via storage objects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CovertWireFrame {
    pub ver: u8,
    pub kind: FrameKind,
    pub sid: SessionId,
    pub seq: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CovertWireError {
    BufferTooShort { needed: usize, found: usize },
    UnsupportedVersion(u8),
    UnknownFrameKind(u8),
    PayloadTooLarge { max: u32, found: u32 },
    LengthMismatch { expected: usize, found: usize },
}

impl fmt::Display for CovertWireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooShort { needed, found } => {
                write!(f, "buffer too short: needed {} bytes, found {}", needed, found)
            }
            Self::UnsupportedVersion(v) => write!(f, "unsupported wire version {}", v),
            Self::UnknownFrameKind(k) => write!(f, "unknown frame kind 0x{:02X}", k),
            Self::PayloadTooLarge { max, found } => {
                write!(f, "payload exceeds max {} bytes, found {}", max, found)
            }
            Self::LengthMismatch { expected, found } => {
                write!(f, "length mismatch: expected {} bytes, found {}", expected, found)
            }
        }
    }
}

impl std::error::Error for CovertWireError {}

impl CovertWireFrame {
    /// Creates a new wire frame with default version.
    pub fn new(kind: FrameKind, sid: SessionId, seq: u64, payload: Vec<u8>) -> Self {
        Self {
            ver: WIRE_VERSION,
            kind,
            sid,
            seq,
            payload,
        }
    }

    /// Serializes wire frame to binary buffer.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_LEN + self.payload.len());
        buf.push(self.ver);
        buf.push(self.kind as u8);
        buf.extend_from_slice(&self.sid);
        buf.extend_from_slice(&self.seq.to_be_bytes());
        buf.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Deserializes wire frame from binary buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, CovertWireError> {
        if buf.len() < HEADER_LEN {
            return Err(CovertWireError::BufferTooShort {
                needed: HEADER_LEN,
                found: buf.len(),
            });
        }

        let ver = buf[0];
        if ver != WIRE_VERSION {
            return Err(CovertWireError::UnsupportedVersion(ver));
        }

        let kind = FrameKind::try_from(buf[1])?;
        let mut sid: SessionId = [0u8; 16];
        sid.copy_from_slice(&buf[2..18]);

        let seq = u64::from_be_bytes(buf[18..26].try_into().unwrap());
        let payload_len = u32::from_be_bytes(buf[26..30].try_into().unwrap());

        if payload_len > MAX_PAYLOAD {
            return Err(CovertWireError::PayloadTooLarge {
                max: MAX_PAYLOAD,
                found: payload_len,
            });
        }

        let expected_total = HEADER_LEN + payload_len as usize;
        if buf.len() < expected_total {
            return Err(CovertWireError::LengthMismatch {
                expected: expected_total,
                found: buf.len(),
            });
        }

        let payload = buf[HEADER_LEN..expected_total].to_vec();
        Ok(Self {
            ver,
            kind,
            sid,
            seq,
            payload,
        })
    }
}

/// 64-bit sliding anti-replay window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayWindow {
    max_seq: u64,
    bitmap: u64,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            max_seq: 0,
            bitmap: 0,
        }
    }

    /// Verifies if sequence number is valid and not replayed, and updates window.
    pub fn check_and_update(&mut self, seq: u64) -> bool {
        if seq > self.max_seq {
            let diff = seq - self.max_seq;
            if diff >= 64 {
                self.bitmap = 1;
            } else {
                self.bitmap = (self.bitmap << diff) | 1;
            }
            self.max_seq = seq;
            true
        } else {
            let diff = self.max_seq - seq;
            if diff >= 64 {
                false
            } else {
                let mask = 1u64 << diff;
                if (self.bitmap & mask) != 0 {
                    false // Replay detected
                } else {
                    self.bitmap |= mask;
                    true
                }
            }
        }
    }
}

/// Cryptographic errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CovertCryptoError {
    AeadError,
    SerializationError(CovertWireError),
}

impl fmt::Display for CovertCryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AeadError => write!(f, "aead encrypt/decrypt authentication failed"),
            Self::SerializationError(e) => write!(f, "wire serialization error: {}", e),
        }
    }
}

impl std::error::Error for CovertCryptoError {}

/// Directional cryptographic session using ChaCha20-Poly1305 and HKDF-SHA256.
pub struct CovertCryptoSession {
    c2r_cipher: ChaCha20Poly1305,
    r2c_cipher: ChaCha20Poly1305,
}

impl CovertCryptoSession {
    /// Derives directional c2r and r2c keys from shared secret and session salt.
    pub fn new(shared_secret: &[u8; 32], sid: &SessionId, salt: &[u8; 16]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);

        let mut c2r_info = Vec::with_capacity(4 + 16);
        c2r_info.extend_from_slice(b"c2r|");
        c2r_info.extend_from_slice(sid);

        let mut r2c_info = Vec::with_capacity(4 + 16);
        r2c_info.extend_from_slice(b"r2c|");
        r2c_info.extend_from_slice(sid);

        let mut k_c2r = [0u8; 32];
        let mut k_r2c = [0u8; 32];
        hk.expand(&c2r_info, &mut k_c2r).expect("32-byte ok");
        hk.expand(&r2c_info, &mut k_r2c).expect("32-byte ok");

        Self {
            c2r_cipher: ChaCha20Poly1305::new(Key::from_slice(&k_c2r)),
            r2c_cipher: ChaCha20Poly1305::new(Key::from_slice(&k_r2c)),
        }
    }

    /// Constructs nonce: `seq.to_le_bytes() || [0u8; 4]` (12 bytes).
    fn make_nonce(seq: u64) -> Nonce {
        let mut nonce = [0u8; 12];
        nonce[0..8].copy_from_slice(&seq.to_le_bytes());
        *Nonce::from_slice(&nonce)
    }

    /// Constructs bound AAD: `sid || seq.to_be_bytes()` (24 bytes).
    fn make_aad(sid: &SessionId, seq: u64) -> [u8; 24] {
        let mut aad = [0u8; 24];
        aad[0..16].copy_from_slice(sid);
        aad[16..24].copy_from_slice(&seq.to_be_bytes());
        aad
    }

    /// Seals a wire frame into AEAD ciphertext.
    pub fn seal(
        &self,
        frame: &CovertWireFrame,
        direction: Direction,
    ) -> Result<Vec<u8>, CovertCryptoError> {
        let plain = frame.encode();
        let nonce = Self::make_nonce(frame.seq);
        let aad = Self::make_aad(&frame.sid, frame.seq);

        let cipher = match direction {
            Direction::ClientToRelay => &self.c2r_cipher,
            Direction::RelayToClient => &self.r2c_cipher,
        };

        let payload = Payload {
            msg: &plain,
            aad: &aad,
        };

        cipher
            .encrypt(&nonce, payload)
            .map_err(|_| CovertCryptoError::AeadError)
    }

    /// Opens AEAD ciphertext and reconstructs the authenticated wire frame.
    pub fn open(
        &self,
        ciphertext: &[u8],
        sid: &SessionId,
        seq: u64,
        direction: Direction,
    ) -> Result<CovertWireFrame, CovertCryptoError> {
        let nonce = Self::make_nonce(seq);
        let aad = Self::make_aad(sid, seq);

        let cipher = match direction {
            Direction::ClientToRelay => &self.c2r_cipher,
            Direction::RelayToClient => &self.r2c_cipher,
        };

        let payload = Payload {
            msg: ciphertext,
            aad: &aad,
        };

        let decrypted = cipher
            .decrypt(&nonce, payload)
            .map_err(|_| CovertCryptoError::AeadError)?;

        CovertWireFrame::decode(&decrypted).map_err(CovertCryptoError::SerializationError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_b32_roundtrip() {
        let sid: SessionId = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let encoded = encode_sid_b32(&sid);
        assert_eq!(encoded.len(), 26);
        let decoded = decode_sid_b32(&encoded).expect("b32 decode");
        assert_eq!(decoded, sid);
    }

    #[test]
    fn test_filename_parse_and_format() {
        let sid: SessionId = [0xAA; 16];
        let fn1 = CovertDeadDropFilename {
            kind: FilenameKind::Hello,
            sid,
            seq: 0,
        };
        let s1 = fn1.format();
        assert!(s1.starts_with("h_"));
        assert!(s1.ends_with("_0"));
        assert_eq!(CovertDeadDropFilename::parse(&s1), Some(fn1));

        let fn2 = CovertDeadDropFilename {
            kind: FilenameKind::Frame(Direction::ClientToRelay),
            sid,
            seq: 42,
        };
        let s2 = fn2.format();
        assert!(s2.starts_with("c2r_"));
        assert!(s2.ends_with("_42"));
        assert_eq!(CovertDeadDropFilename::parse(&s2), Some(fn2));

        let fn3 = CovertDeadDropFilename {
            kind: FilenameKind::Frame(Direction::RelayToClient),
            sid,
            seq: 999,
        };
        let s3 = fn3.format();
        assert!(s3.starts_with("r2c_"));
        assert!(s3.ends_with("_999"));
        assert_eq!(CovertDeadDropFilename::parse(&s3), Some(fn3));
    }

    #[test]
    fn test_wire_frame_encode_decode() {
        let sid = [0x55; 16];
        let frame = CovertWireFrame::new(
            FrameKind::Data,
            sid,
            123,
            b"secret dead drop payload".to_vec(),
        );
        let encoded = frame.encode();
        assert_eq!(encoded.len(), HEADER_LEN + frame.payload.len());
        let decoded = CovertWireFrame::decode(&encoded).expect("decode");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn test_replay_window() {
        let mut rw = ReplayWindow::new();
        assert!(rw.check_and_update(1));
        assert!(rw.check_and_update(2));
        assert!(rw.check_and_update(5));
        // Replays
        assert!(!rw.check_and_update(1));
        assert!(!rw.check_and_update(5));
        // Valid out-of-order within window
        assert!(rw.check_and_update(3));
        assert!(rw.check_and_update(4));
        // Replays
        assert!(!rw.check_and_update(3));
        // Far ahead
        assert!(rw.check_and_update(100));
        // Past the 64-bit window
        assert!(!rw.check_and_update(1));
    }

    #[test]
    fn test_crypto_session_seal_open() {
        let shared_secret = [0x42; 32];
        let sid = [0x11; 16];
        let salt = [0x77; 16];

        let session = CovertCryptoSession::new(&shared_secret, &sid, &salt);
        let frame = CovertWireFrame::new(
            FrameKind::Data,
            sid,
            1,
            b"top secret payload".to_vec(),
        );

        let sealed = session
            .seal(&frame, Direction::ClientToRelay)
            .expect("seal");

        let opened = session
            .open(&sealed, &sid, 1, Direction::ClientToRelay)
            .expect("open");

        assert_eq!(opened, frame);

        // AAD mismatch test (wrong sid or wrong seq)
        let wrong_sid = [0x22; 16];
        assert!(session
            .open(&sealed, &wrong_sid, 1, Direction::ClientToRelay)
            .is_err());
        assert!(session
            .open(&sealed, &sid, 2, Direction::ClientToRelay)
            .is_err());
    }
}
