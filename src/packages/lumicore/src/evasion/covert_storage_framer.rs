//! Covert Storage Multiplex Stream Framer
//!
//! Packages multiplexed bidirectional TCP/UDP proxy payloads into HTTP REST
//! multipart/storage chunk envelopes to blend in seamlessly with legitimate cloud storage traffic.

use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum StorageFramerError {
    HeaderTooShort,
    MagicMismatch,
    ChecksumMismatch,
    DataTruncated,
}

impl fmt::Display for StorageFramerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeaderTooShort => write!(f, "Storage chunk header too short"),
            Self::MagicMismatch => write!(f, "Invalid covert chunk magic signature"),
            Self::ChecksumMismatch => write!(f, "Chunk payload checksum mismatch"),
            Self::DataTruncated => write!(f, "Chunk data truncated"),
        }
    }
}

impl std::error::Error for StorageFramerError {}

pub const STORAGE_CHUNK_MAGIC: [u8; 4] = [0x53, 0x4B, 0x52, 0x4B]; // "SKRK"

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CovertChunk {
    pub stream_id: u32,
    pub sequence: u64,
    pub is_fin: bool,
    pub payload: Vec<u8>,
}

pub struct CovertStorageFramer;

impl CovertStorageFramer {
    /// Formats a chunk into a binary block:
    /// [Magic: 4B] [StreamID: 4B] [Seq: 8B] [Flags: 1B] [Len: 4B] [CRC-8: 1B] [Payload: N bytes]
    pub fn frame_chunk(chunk: &CovertChunk) -> Vec<u8> {
        let mut out = Vec::with_capacity(22 + chunk.payload.len());
        out.extend_from_slice(&STORAGE_CHUNK_MAGIC);
        out.extend_from_slice(&chunk.stream_id.to_be_bytes());
        out.extend_from_slice(&chunk.sequence.to_be_bytes());
        let flags = if chunk.is_fin { 0x01 } else { 0x00 };
        out.push(flags);
        out.extend_from_slice(&(chunk.payload.len() as u32).to_be_bytes());
        
        // Simple CRC8 over payload
        let crc = Self::compute_crc8(&chunk.payload);
        out.push(crc);

        out.extend_from_slice(&chunk.payload);
        out
    }

    pub fn unframe_chunk(buf: &[u8]) -> Result<(CovertChunk, usize), StorageFramerError> {
        if buf.len() < 22 {
            return Err(StorageFramerError::HeaderTooShort);
        }

        if &buf[0..4] != STORAGE_CHUNK_MAGIC {
            return Err(StorageFramerError::MagicMismatch);
        }

        let stream_id = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let sequence = u64::from_be_bytes([
            buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
        ]);
        let is_fin = (buf[16] & 0x01) != 0;
        let payload_len = u32::from_be_bytes([buf[17], buf[18], buf[19], buf[20]]) as usize;
        let expected_crc = buf[21];

        let total_size = 22 + payload_len;
        if buf.len() < total_size {
            return Err(StorageFramerError::DataTruncated);
        }

        let payload = buf[22..total_size].to_vec();
        let computed_crc = Self::compute_crc8(&payload);
        if computed_crc != expected_crc {
            return Err(StorageFramerError::ChecksumMismatch);
        }

        Ok((
            CovertChunk {
                stream_id,
                sequence,
                is_fin,
                payload,
            },
            total_size,
        ))
    }

    fn compute_crc8(data: &[u8]) -> u8 {
        let mut crc = 0x00u8;
        for &b in data {
            crc ^= b;
            for _ in 0..8 {
                if (crc & 0x80) != 0 {
                    crc = (crc << 1) ^ 0x07;
                } else {
                    crc <<= 1;
                }
            }
        }
        crc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_framer_roundtrip() {
        let chunk = CovertChunk {
            stream_id: 1042,
            sequence: 88,
            is_fin: false,
            payload: b"encrypted covert stream data".to_vec(),
        };

        let framed = CovertStorageFramer::frame_chunk(&chunk);
        assert!(framed.starts_with(&STORAGE_CHUNK_MAGIC));

        let (unframed, consumed) = CovertStorageFramer::unframe_chunk(&framed).unwrap();
        assert_eq!(unframed, chunk);
        assert_eq!(consumed, framed.len());
    }
}
