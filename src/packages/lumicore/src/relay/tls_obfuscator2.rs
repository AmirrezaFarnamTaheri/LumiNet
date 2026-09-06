// Copyright 2024 LumiNet. Use of this source code is governed by the MIT license.

//! # TLS Obfuscator v2 — TLS-record-camouflaged framing (FPTN "tls2" method)
//!
//! Wraps arbitrary payload bytes in frames that mimic TLS 1.2 application-data
//! records (`0x17 0x03 0x03 <len>`). Each frame carries a random nonce, a Unix
//! timestamp (rejected beyond a ±10 s window by the receiver), a per-frame XOR
//! key applied to the payload, and a random 4095..=8192-byte padding tail so
//! frame sizes and timing signatures resist DPI classification.
//!
//! Wire layout (22-byte header, all integers big-endian):
//!
//! ```text
//! offset  size  field
//! 0       1     record type       0x17 (TLS application data)
//! 1       1     record major      0x03
//! 2       1     record minor      0x03
//! 3       2     content_length    FPTN_TRAILER_LEN + payload + padding (<= 16384)
//! 5       8     random_data       random u64 >= 1024 (nonce)
//! 13      4     timestamp         Unix seconds
//! 17      1     xor_key           per-frame payload XOR key
//! 18      2     payload_length
//! 20      2     padding_length
//! 22      ..    payload (XORed)   then padding (random bytes)
//! ```

use rand::rngs::SmallRng;
use rand::{Rng, RngCore, SeedableRng};

/// Size of the fixed frame header (TLS record header + FPTN fields).
pub const HEADER_LEN: usize = 22;
/// Header fields after `content_length` (random + ts + key + payload_len + padding_len).
pub const FPTN_TRAILER_LEN: usize = 17;
/// TLS application-data record type byte.
pub const RECORD_TYPE: u8 = 0x17;
/// TLS record major version byte.
pub const RECORD_MAJOR: u8 = 0x03;
/// TLS record minor version byte.
pub const RECORD_MINOR: u8 = 0x03;
/// Upper bound for `content_length`, matching the upstream decoder.
pub const MAX_CONTENT_LENGTH: usize = 16384;
/// Minimum random padding per frame.
pub const PADDING_MIN: usize = 4095;
/// Maximum random padding per frame.
pub const PADDING_MAX: usize = 8192;
/// Largest encodable payload: content cap minus trailer minus minimum padding.
pub const MAX_PAYLOAD: usize = MAX_CONTENT_LENGTH - FPTN_TRAILER_LEN - PADDING_MIN;
/// Buffered-ingest ceiling (matches upstream `kMmaxBufferSize`).
pub const MAX_INPUT_BUFFER: usize = 1024 * 256;
/// Timestamp accept window in seconds (±) used by the upstream decoder.
pub const TIME_SHIFT_SECONDS: u32 = 10;

/// Injectable Unix-seconds clock so timestamp validation is testable.
pub trait UnixTime: Send {
    fn now(&self) -> u32;
}

/// System-clock implementation of [`UnixTime`].
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemUnixTime;

impl UnixTime for SystemUnixTime {
    fn now(&self) -> u32 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0)
    }
}

/// One decoded tls2 frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedFrame {
    /// De-XORed payload bytes.
    pub payload: Vec<u8>,
    /// Random nonce copied from the header.
    pub random: u64,
    /// Unix timestamp declared by the sender.
    pub timestamp: u32,
    /// Declared padding length (padding bytes are consumed and discarded).
    pub padding_len: usize,
}

/// Failure modes of the tls2 codec.
#[derive(Debug, thiserror::Error)]
pub enum TlsObfuscator2Error {
    #[error("payload of {0} bytes exceeds the maximum frame payload of {MAX_PAYLOAD} bytes")]
    PayloadTooLarge(usize),
    #[error("input buffer overflow: buffered ingest is capped at {MAX_INPUT_BUFFER} bytes")]
    BufferOverflow,
    #[error("frame shorter than the {HEADER_LEN}-byte header")]
    FrameTooShort,
    #[error("not a tls2 frame: record type/version bytes mismatch")]
    NotATls2Frame,
    #[error("frame timestamp {0} is outside the ±{TIME_SHIFT_SECONDS}s accept window")]
    StaleTimestamp(u32),
    #[error("frame content_length {declared} conflicts with the header payload/padding lengths or the {MAX_CONTENT_LENGTH}-byte cap")]
    BadContentLength { declared: usize },
    #[error("frame truncated: need {need} bytes, have {have}")]
    Truncated { need: usize, have: usize },
}

/// Streaming tls2 codec. `encode` builds frames, `decode` validates and
/// unwraps them, and the buffered `add_data`/`encode_pending` pair mirrors the
/// upstream streaming ingest with the same 256 KiB ceiling.
pub struct TlsObfuscator2 {
    time: Box<dyn UnixTime>,
    rng: SmallRng,
    input_buffer: Vec<u8>,
}

impl Default for TlsObfuscator2 {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsObfuscator2 {
    /// Construct a codec using the system clock and entropy-seeded RNG.
    pub fn new() -> Self {
        Self::with_time(Box::new(SystemUnixTime))
    }

    /// Construct a codec with an explicit clock (for deterministic tests).
    pub fn with_time(time: Box<dyn UnixTime>) -> Self {
        Self {
            time,
            rng: SmallRng::from_entropy(),
            input_buffer: Vec::new(),
        }
    }

    /// Encode one payload as a single tls2 frame. Padding is clamped so the
    /// frame's `content_length` always stays within [`MAX_CONTENT_LENGTH`].
    pub fn encode(&mut self, payload: &[u8]) -> Result<Vec<u8>, TlsObfuscator2Error> {
        if payload.len() > MAX_PAYLOAD {
            return Err(TlsObfuscator2Error::PayloadTooLarge(payload.len()));
        }
        // Upper padding bound that keeps content within the wire-format cap.
        let padding_cap = (MAX_CONTENT_LENGTH - FPTN_TRAILER_LEN - payload.len()).min(PADDING_MAX);
        let padding_len: usize = self.rng.gen_range(PADDING_MIN..=padding_cap);
        let xor_key: u8 = self.rng.gen();
        let random: u64 = self.rng.gen_range(1024..=u64::MAX);
        let timestamp = self.time.now();
        let content_len = FPTN_TRAILER_LEN + payload.len() + padding_len;
        debug_assert!(content_len <= u16::MAX as usize);

        let mut out = Vec::with_capacity(HEADER_LEN + payload.len() + padding_len);
        out.push(RECORD_TYPE);
        out.push(RECORD_MAJOR);
        out.push(RECORD_MINOR);
        out.extend_from_slice(&(content_len as u16).to_be_bytes());
        out.extend_from_slice(&random.to_be_bytes());
        out.extend_from_slice(&timestamp.to_be_bytes());
        out.push(xor_key);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&(padding_len as u16).to_be_bytes());
        out.extend(payload.iter().map(|b| b ^ xor_key));
        let mut padding = vec![0u8; padding_len];
        self.rng.fill_bytes(&mut padding);
        out.extend_from_slice(&padding);
        Ok(out)
    }

    /// Buffered ingest: appends bytes to the pending buffer, mirroring the
    /// upstream `AddData`. Returns `false` (dropping all buffered bytes) when
    /// the append would exceed [`MAX_INPUT_BUFFER`].
    pub fn add_data(&mut self, data: &[u8]) -> bool {
        if self.input_buffer.len() + data.len() > MAX_INPUT_BUFFER {
            self.input_buffer.clear();
            return false;
        }
        self.input_buffer.extend_from_slice(data);
        true
    }

    /// Drain the pending buffer into tls2 frames, oldest first. The final
    /// partial chunk below [`MAX_PAYLOAD`] is flushed as one smaller frame so
    /// no buffered byte is ever left behind.
    pub fn encode_pending(&mut self) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        while self.input_buffer.len() >= MAX_PAYLOAD {
            let chunk: Vec<u8> = self.input_buffer.drain(..MAX_PAYLOAD).collect();
            if let Ok(frame) = self.encode(&chunk) {
                frames.push(frame);
            }
        }
        if !self.input_buffer.is_empty() {
            let tail = std::mem::take(&mut self.input_buffer);
            if let Ok(frame) = self.encode(&tail) {
                frames.push(frame);
            }
        }
        frames
    }

    /// Reports whether buffered ingest data is waiting to be framed.
    pub fn has_pending_data(&self) -> bool {
        !self.input_buffer.is_empty()
    }

    /// Structurally validate a frame without decoding the payload.
    /// Mirrors the upstream `CheckProtocol` including the timestamp window.
    pub fn check_protocol(&self, frame: &[u8]) -> bool {
        self.parse_header(frame).is_ok()
    }

    /// Validate a frame and return its decoded payload (padding discarded).
    pub fn decode(&self, frame: &[u8]) -> Result<DecodedFrame, TlsObfuscator2Error> {
        let (random, timestamp, xor_key, payload_len, padding_len) = self.parse_header(frame)?;
        let need = HEADER_LEN + payload_len + padding_len;
        if frame.len() < need {
            return Err(TlsObfuscator2Error::Truncated {
                need,
                have: frame.len(),
            });
        }
        let payload: Vec<u8> = frame[HEADER_LEN..HEADER_LEN + payload_len]
            .iter()
            .map(|b| b ^ xor_key)
            .collect();
        Ok(DecodedFrame {
            payload,
            random,
            timestamp,
            padding_len,
        })
    }

    /// Drop all buffered ingest state.
    pub fn reset(&mut self) {
        self.input_buffer.clear();
    }

    /// Parse and validate the fixed header. Returns the decoded trailer fields.
    fn parse_header(
        &self,
        frame: &[u8],
    ) -> Result<(u64, u32, u8, usize, usize), TlsObfuscator2Error> {
        if frame.len() < HEADER_LEN {
            return Err(TlsObfuscator2Error::FrameTooShort);
        }
        if frame[0] != RECORD_TYPE || frame[1] != RECORD_MAJOR || frame[2] != RECORD_MINOR {
            return Err(TlsObfuscator2Error::NotATls2Frame);
        }
        let content_len = u16::from_be_bytes([frame[3], frame[4]]) as usize;
        let random = u64::from_be_bytes(frame[5..13].try_into().expect("8 bytes"));
        let timestamp = u32::from_be_bytes(frame[13..17].try_into().expect("4 bytes"));
        let xor_key = frame[17];
        let payload_len = u16::from_be_bytes(frame[18..20].try_into().expect("2 bytes")) as usize;
        let padding_len = u16::from_be_bytes(frame[20..22].try_into().expect("2 bytes")) as usize;

        if !self.timestamp_valid(timestamp) {
            return Err(TlsObfuscator2Error::StaleTimestamp(timestamp));
        }
        let min_content = FPTN_TRAILER_LEN + payload_len + padding_len;
        if content_len < min_content || content_len > MAX_CONTENT_LENGTH {
            return Err(TlsObfuscator2Error::BadContentLength { declared: content_len });
        }
        Ok((random, timestamp, xor_key, payload_len, padding_len))
    }

    /// Upstream rule: `ts <= now + shift && ts + shift >= now`.
    fn timestamp_valid(&self, ts: u32) -> bool {
        let now = self.time.now();
        ts <= now.saturating_add(TIME_SHIFT_SECONDS) && ts.wrapping_add(TIME_SHIFT_SECONDS) >= now
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedClock(u32);

    impl UnixTime for FixedClock {
        fn now(&self) -> u32 {
            self.0
        }
    }

    fn codec_at(now: u32) -> TlsObfuscator2 {
        TlsObfuscator2::with_time(Box::new(FixedClock(now)))
    }

    #[test]
    fn roundtrip_recovers_payload() {
        let now = 1_000_000_000;
        let mut enc = codec_at(now);
        let frame = enc.encode(b"hello tls2").expect("encode");
        assert!(enc.check_protocol(&frame), "frame must self-validate");
        let dec = codec_at(now);
        let decoded = dec.decode(&frame).expect("decode");
        assert_eq!(decoded.payload, b"hello tls2");
        assert_eq!(decoded.timestamp, now);
    }

    #[test]
    fn roundtrip_empty_payload() {
        let now = 1_000_000_000;
        let mut enc = codec_at(now);
        let frame = enc.encode(b"").expect("encode");
        let dec = codec_at(now);
        assert!(dec.decode(&frame).expect("decode").payload.is_empty());
    }

    #[test]
    fn header_layout_matches_upstream_wire_format() {
        let now = 1_700_000_000;
        let mut enc = codec_at(now);
        let frame = enc.encode(b"AB").expect("encode");
        assert_eq!(frame[0], 0x17);
        assert_eq!(frame[1], 0x03);
        assert_eq!(frame[2], 0x03);
        let content = u16::from_be_bytes([frame[3], frame[4]]) as usize;
        let padding = u16::from_be_bytes([frame[20], frame[21]]) as usize;
        assert_eq!(content, FPTN_TRAILER_LEN + 2 + padding);
        assert!((PADDING_MIN..=PADDING_MAX).contains(&padding));
        assert!(u64::from_be_bytes(frame[5..13].try_into().unwrap()) >= 1024);
        assert_eq!(u32::from_be_bytes(frame[13..17].try_into().unwrap()), now);
        assert_eq!(u16::from_be_bytes([frame[18], frame[19]]) as usize, 2);
        assert_eq!(frame.len(), HEADER_LEN + 2 + padding);
    }

    #[test]
    fn xor_key_is_applied_and_reverted() {
        let now = 1_000_000_000;
        let mut enc = codec_at(now);
        let frame = enc.encode(b"\x00\xff\x42").expect("encode");
        let xor_key = frame[17];
        assert_ne!(&frame[HEADER_LEN..HEADER_LEN + 3], b"\x00\xff\x42");
        let dec = codec_at(now);
        let decoded = dec.decode(&frame).expect("decode");
        assert_eq!(decoded.payload, b"\x00\xff\x42");
        assert_eq!(decoded.payload[0], 0u8 ^ xor_key ^ xor_key);
    }

    #[test]
    fn stale_timestamp_is_rejected() {
        let now = 1_000_000_000;
        let mut enc = codec_at(now);
        let frame = enc.encode(b"data").expect("encode");
        let dec_late = codec_at(now + TIME_SHIFT_SECONDS + 1);
        assert!(matches!(
            dec_late.decode(&frame),
            Err(TlsObfuscator2Error::StaleTimestamp(_))
        ));
        let dec_early = codec_at(now - TIME_SHIFT_SECONDS - 1);
        assert!(matches!(
            dec_early.decode(&frame),
            Err(TlsObfuscator2Error::StaleTimestamp(_))
        ));
        let dec_edge = codec_at(now + TIME_SHIFT_SECONDS);
        assert!(dec_edge.decode(&frame).is_ok());
    }

    #[test]
    fn oversized_payload_is_rejected() {
        let mut enc = codec_at(1_000_000_000);
        assert!(matches!(
            enc.encode(&vec![0u8; MAX_PAYLOAD + 1]),
            Err(TlsObfuscator2Error::PayloadTooLarge(_))
        ));
        assert!(enc.encode(&vec![0u8; MAX_PAYLOAD]).is_ok());
    }

    #[test]
    fn max_payload_frame_fits_content_cap() {
        let now = 1_000_000_000;
        let mut enc = codec_at(now);
        let frame = enc.encode(&vec![0u8; MAX_PAYLOAD]).expect("encode");
        let content = u16::from_be_bytes([frame[3], frame[4]]) as usize;
        assert!(content <= MAX_CONTENT_LENGTH);
        let dec = codec_at(now);
        assert!(dec.decode(&frame).is_ok());
    }

    #[test]
    fn short_frame_is_rejected() {
        let dec = codec_at(1_000_000_000);
        assert!(matches!(
            dec.decode(&[0u8; HEADER_LEN - 1]),
            Err(TlsObfuscator2Error::FrameTooShort)
        ));
    }

    #[test]
    fn wrong_record_bytes_are_rejected() {
        let now = 1_000_000_000;
        let mut enc = codec_at(now);
        let mut frame = enc.encode(b"x").expect("encode");
        frame[0] = 0x16; // handshake record, not application data
        let dec = codec_at(now);
        assert!(matches!(
            dec.decode(&frame),
            Err(TlsObfuscator2Error::NotATls2Frame)
        ));
    }

    #[test]
    fn inconsistent_content_length_is_rejected() {
        let now = 1_000_000_000;
        let mut enc = codec_at(now);
        let mut frame = enc.encode(b"abc").expect("encode");
        frame[3] = 0xff;
        frame[4] = 0xff;
        let dec = codec_at(now);
        assert!(matches!(
            dec.decode(&frame),
            Err(TlsObfuscator2Error::BadContentLength { .. })
        ));
    }

    #[test]
    fn truncated_body_is_rejected() {
        let now = 1_000_000_000;
        let mut enc = codec_at(now);
        let frame = enc.encode(b"payload bytes").expect("encode");
        let dec = codec_at(now);
        assert!(matches!(
            dec.decode(&frame[..frame.len() - 1]),
            Err(TlsObfuscator2Error::Truncated { .. })
        ));
    }

    #[test]
    fn buffered_ingest_frames_all_data() {
        let now = 1_000_000_000;
        let mut enc = codec_at(now);
        assert!(enc.add_data(b"first "));
        assert!(enc.add_data(b"second"));
        assert!(enc.has_pending_data());
        let frames = enc.encode_pending();
        assert_eq!(frames.len(), 1);
        assert!(!enc.has_pending_data());
        let dec = codec_at(now);
        let decoded = dec.decode(&frames[0]).expect("decode");
        assert_eq!(decoded.payload, b"first second");
    }

    #[test]
    fn buffered_ingest_chunks_at_max_payload() {
        let now = 1_000_000_000;
        let mut enc = codec_at(now);
        let total = MAX_PAYLOAD + 100;
        assert!(enc.add_data(&vec![7u8; total]));
        let frames = enc.encode_pending();
        assert_eq!(frames.len(), 2);
        let dec = codec_at(now);
        let mut joined = Vec::new();
        for f in &frames {
            joined.extend_from_slice(&dec.decode(f).expect("decode").payload);
        }
        assert_eq!(joined, vec![7u8; total]);
    }

    #[test]
    fn buffer_overflow_drops_and_reset_clears() {
        let mut enc = codec_at(1_000_000_000);
        assert!(enc.add_data(&vec![0u8; MAX_INPUT_BUFFER]));
        assert!(!enc.add_data(&[1u8; 1]));
        assert!(!enc.has_pending_data());
        enc.reset();
        assert!(!enc.has_pending_data());
    }

    #[test]
    fn check_protocol_accepts_and_rejects() {
        let now = 1_000_000_000;
        let mut enc = codec_at(now);
        let frame = enc.encode(b"ok").expect("encode");
        let dec = codec_at(now);
        assert!(dec.check_protocol(&frame));
        assert!(!dec.check_protocol(&frame[..10]));
        assert!(!dec.check_protocol(&[0u8; HEADER_LEN]));
    }
}
