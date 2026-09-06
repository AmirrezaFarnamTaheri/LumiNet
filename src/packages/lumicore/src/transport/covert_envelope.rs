//! Covert Storage Envelope Engine
//!
//! Implements a robust binary framing protocol for covert data staging over storage backends,
//! cloud drives, and dead-drop queues.

use std::fmt;

/// Magic protocol byte identifying a Flow covert envelope.
pub const COVERT_MAGIC_BYTE: u8 = 0x1F;

/// Represents an envelope packet exchanged over covert storage / dead-drop mediums.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CovertEnvelope {
    /// Unique connection / flow session identifier.
    pub session_id: String,
    /// Sequence counter for ordered in-stream reassembly.
    pub seq: u64,
    /// Target destination address (host:port), sent typically on seq 0 or session initiation.
    pub target_addr: String,
    /// Flag signaling connection teardown.
    pub is_close: bool,
    /// Raw inner payload data.
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CovertEnvelopeError {
    EmptyBuffer,
    InvalidMagicByte { expected: u8, found: u8 },
    UnexpectedEof,
    StringDecodeError(String),
}

impl fmt::Display for CovertEnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyBuffer => write!(f, "buffer is empty"),
            Self::InvalidMagicByte { expected, found } => {
                write!(f, "invalid magic byte: expected 0x{:02X}, found 0x{:02X}", expected, found)
            }
            Self::UnexpectedEof => write!(f, "unexpected end of buffer while decoding covert envelope"),
            Self::StringDecodeError(err) => write!(f, "failed to decode string field: {}", err),
        }
    }
}

impl std::error::Error for CovertEnvelopeError {}

impl CovertEnvelope {
    /// Creates a new active data envelope.
    pub fn new(session_id: impl Into<String>, seq: u64, target_addr: impl Into<String>, payload: Vec<u8>) -> Self {
        Self {
            session_id: session_id.into(),
            seq,
            target_addr: target_addr.into(),
            is_close: false,
            payload,
        }
    }

    /// Creates a session termination envelope.
    pub fn new_close(session_id: impl Into<String>, seq: u64) -> Self {
        Self {
            session_id: session_id.into(),
            seq,
            target_addr: String::new(),
            is_close: true,
            payload: Vec::new(),
        }
    }

    /// Computes the exact encoded size in bytes.
    pub fn encoded_len(&self) -> usize {
        1 // magic
        + 1 + self.session_id.len()
        + 8 // seq
        + 1 + self.target_addr.len()
        + 1 // is_close
        + 4 // payload len
        + self.payload.len()
    }

    /// Serializes the envelope into binary wire format.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.encoded_len());

        buf.push(COVERT_MAGIC_BYTE);

        let sid_bytes = self.session_id.as_bytes();
        buf.push(sid_bytes.len().min(255) as u8);
        buf.extend_from_slice(&sid_bytes[..sid_bytes.len().min(255)]);

        buf.extend_from_slice(&self.seq.to_be_bytes());

        let target_bytes = self.target_addr.as_bytes();
        buf.push(target_bytes.len().min(255) as u8);
        buf.extend_from_slice(&target_bytes[..target_bytes.len().min(255)]);

        buf.push(if self.is_close { 1 } else { 0 });

        buf.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.payload);

        buf
    }

    /// Deserializes an envelope from binary wire format.
    /// Returns the decoded envelope and number of bytes consumed.
    pub fn decode(src: &[u8]) -> Result<(Self, usize), CovertEnvelopeError> {
        if src.is_empty() {
            return Err(CovertEnvelopeError::EmptyBuffer);
        }

        if src[0] != COVERT_MAGIC_BYTE {
            return Err(CovertEnvelopeError::InvalidMagicByte {
                expected: COVERT_MAGIC_BYTE,
                found: src[0],
            });
        }

        let mut offset = 1;

        // Session ID
        if src.len() < offset + 1 {
            return Err(CovertEnvelopeError::UnexpectedEof);
        }
        let sid_len = src[offset] as usize;
        offset += 1;

        if src.len() < offset + sid_len {
            return Err(CovertEnvelopeError::UnexpectedEof);
        }
        let session_id = String::from_utf8(src[offset..offset + sid_len].to_vec())
            .map_err(|e| CovertEnvelopeError::StringDecodeError(e.to_string()))?;
        offset += sid_len;

        // Sequence number (u64 big-endian)
        if src.len() < offset + 8 {
            return Err(CovertEnvelopeError::UnexpectedEof);
        }
        let seq = u64::from_be_bytes(
            src[offset..offset + 8]
                .try_into()
                .map_err(|_| CovertEnvelopeError::UnexpectedEof)?,
        );
        offset += 8;

        // Target Address
        if src.len() < offset + 1 {
            return Err(CovertEnvelopeError::UnexpectedEof);
        }
        let target_len = src[offset] as usize;
        offset += 1;

        if src.len() < offset + target_len {
            return Err(CovertEnvelopeError::UnexpectedEof);
        }
        let target_addr = String::from_utf8(src[offset..offset + target_len].to_vec())
            .map_err(|e| CovertEnvelopeError::StringDecodeError(e.to_string()))?;
        offset += target_len;

        // Is close flag
        if src.len() < offset + 1 {
            return Err(CovertEnvelopeError::UnexpectedEof);
        }
        let is_close = src[offset] != 0;
        offset += 1;

        // Payload len (u32 big-endian)
        if src.len() < offset + 4 {
            return Err(CovertEnvelopeError::UnexpectedEof);
        }
        let payload_len = u32::from_be_bytes(
            src[offset..offset + 4]
                .try_into()
                .map_err(|_| CovertEnvelopeError::UnexpectedEof)?,
        ) as usize;
        offset += 4;

        // Payload bytes
        if src.len() < offset + payload_len {
            return Err(CovertEnvelopeError::UnexpectedEof);
        }
        let payload = src[offset..offset + payload_len].to_vec();
        offset += payload_len;

        Ok((
            Self {
                session_id,
                seq,
                target_addr,
                is_close,
                payload,
            },
            offset,
        ))
    }
}

use std::collections::BTreeMap;

/// Ordered packet reassembly engine for asynchronous covert storage polling.
#[derive(Debug, Clone, Default)]
pub struct CovertPacketReassembler {
    expected_seq: u64,
    buffer: BTreeMap<u64, CovertEnvelope>,
    is_closed: bool,
}

impl CovertPacketReassembler {
    pub fn new() -> Self {
        Self {
            expected_seq: 0,
            buffer: BTreeMap::new(),
            is_closed: false,
        }
    }

    pub fn with_start_seq(start_seq: u64) -> Self {
        Self {
            expected_seq: start_seq,
            buffer: BTreeMap::new(),
            is_closed: false,
        }
    }

    /// Ingests an incoming envelope. If packets arrive out of order, holds them in buffer
    /// and yields contiguous payload bytes in strict sequence order.
    pub fn push(&mut self, env: CovertEnvelope) -> Vec<u8> {
        if env.seq < self.expected_seq {
            // Stale or duplicate packet
            return Vec::new();
        }

        self.buffer.insert(env.seq, env);

        let mut contiguous = Vec::new();
        while let Some(next) = self.buffer.remove(&self.expected_seq) {
            contiguous.extend_from_slice(&next.payload);
            if next.is_close {
                self.is_closed = true;
            }
            self.expected_seq += 1;
        }

        contiguous
    }

    pub fn is_closed(&self) -> bool {
        self.is_closed
    }

    pub fn expected_seq(&self) -> u64 {
        self.expected_seq
    }

    pub fn buffered_count(&self) -> usize {
        self.buffer.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_roundtrip() {
        let env = CovertEnvelope::new("sess-12345", 42, "api.example.com:443", b"hello covert world".to_vec());
        let encoded = env.encode();
        assert_eq!(encoded[0], COVERT_MAGIC_BYTE);
        assert_eq!(encoded.len(), env.encoded_len());

        let (decoded, consumed) = CovertEnvelope::decode(&encoded).expect("decode failed");
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.session_id, "sess-12345");
        assert_eq!(decoded.seq, 42);
        assert_eq!(decoded.target_addr, "api.example.com:443");
        assert!(!decoded.is_close);
        assert_eq!(decoded.payload, b"hello covert world");
    }

    #[test]
    fn test_envelope_close() {
        let env = CovertEnvelope::new_close("term-session", 999);
        let encoded = env.encode();
        let (decoded, consumed) = CovertEnvelope::decode(&encoded).expect("decode close failed");
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.session_id, "term-session");
        assert_eq!(decoded.seq, 999);
        assert!(decoded.target_addr.is_empty());
        assert!(decoded.is_close);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn test_corrupt_magic() {
        let mut encoded = CovertEnvelope::new("s", 1, "t", vec![]).encode();
        encoded[0] = 0xAA;
        let err = CovertEnvelope::decode(&encoded).unwrap_err();
        assert_eq!(
            err,
            CovertEnvelopeError::InvalidMagicByte {
                expected: COVERT_MAGIC_BYTE,
                found: 0xAA
            }
        );
    }

    #[test]
    fn test_covert_packet_reassembler_out_of_order() {
        let mut reassembler = CovertPacketReassembler::new();

        // Envelopes arrive out of order: seq 1, then seq 0, then seq 3, then seq 2 (with close)
        let env1 = CovertEnvelope::new("s1", 1, "", b"World!".to_vec());
        let env0 = CovertEnvelope::new("s1", 0, "target:80", b"Hello ".to_vec());
        let env2 = CovertEnvelope::new_close("s1", 2);

        // Ingest seq 1 -> cannot emit yet because seq 0 missing
        let chunk1 = reassembler.push(env1);
        assert!(chunk1.is_empty());
        assert_eq!(reassembler.buffered_count(), 1);
        assert_eq!(reassembler.expected_seq(), 0);

        // Ingest seq 0 -> yields both seq 0 and seq 1 ("Hello World!")
        let chunk0 = reassembler.push(env0);
        assert_eq!(chunk0, b"Hello World!");
        assert_eq!(reassembler.buffered_count(), 0);
        assert_eq!(reassembler.expected_seq(), 2);
        assert!(!reassembler.is_closed());

        // Ingest seq 2 (close) -> stream closed
        let chunk2 = reassembler.push(env2);
        assert!(chunk2.is_empty());
        assert!(reassembler.is_closed());
        assert_eq!(reassembler.expected_seq(), 3);
    }
}
