//! Range-Parallel Download Chunking, Content-Range Verification, and Streaming Stitcher.
//!
//! Enables streaming of large files (> 40 MiB Apps Script / Edge GET ceiling) across
//! domain-fronted HTTP relays using parallel byte-range requests.

use std::collections::BTreeMap;

pub const DEFAULT_RANGE_CHUNK_BYTES: u64 = 256 * 1024; // 256 KiB
pub const APPS_SCRIPT_BODY_MAX_BYTES: u64 = 40 * 1024 * 1024; // 40 MiB
pub const BUFFERED_STITCH_MAX_BYTES: u64 = 64 * 1024 * 1024; // 64 MiB
pub const MAX_STREAMED_RANGE_BYTES: u64 = 16 * 1024 * 1024 * 1024; // 16 GiB

/// Wire dispatch state to protect against duplicate side effects on non-idempotent replays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestSent {
    /// Stream was never opened or request header was never dispatched; safe to replay.
    No,
    /// Request was dispatched onto the wire; must not replay through fallback paths.
    Yes,
}

/// Specification of a single byte-range chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RangeChunkSpec {
    pub chunk_index: usize,
    pub start_byte: u64,
    pub end_byte: u64, // inclusive
    pub total_bytes: u64,
}

impl RangeChunkSpec {
    /// Returns the length of this chunk in bytes.
    pub fn length(&self) -> usize {
        (self.end_byte - self.start_byte + 1) as usize
    }

    /// Formats the standard HTTP Range request header value: ytes=<start>-<end>.
    pub fn to_range_header(&self) -> String {
        format!("bytes={}-{}", self.start_byte, self.end_byte)
    }
}

/// Computes the exact slice boundaries for parallel chunk requests.
pub fn compute_chunks(total_bytes: u64, chunk_size: u64) -> Result<Vec<RangeChunkSpec>, String> {
    if total_bytes == 0 {
        return Err("Total bytes cannot be zero".to_string());
    }
    if total_bytes > MAX_STREAMED_RANGE_BYTES {
        return Err(format!(
            "Total bytes {} exceeds hard ceiling of {} bytes",
            total_bytes, MAX_STREAMED_RANGE_BYTES
        ));
    }
    let sz = if chunk_size == 0 { DEFAULT_RANGE_CHUNK_BYTES } else { chunk_size };

    let mut chunks = Vec::new();
    let mut start = 0u64;
    let mut index = 0usize;

    while start < total_bytes {
        let end = (start + sz - 1).min(total_bytes - 1);
        chunks.push(RangeChunkSpec {
            chunk_index: index,
            start_byte: start,
            end_byte: end,
            total_bytes,
        });
        start = end + 1;
        index += 1;
    }

    Ok(chunks)
}

/// Parses an RFC 7233 Content-Range response header.
/// Format: ytes <start>-<end>/<total> (e.g. ytes 0-262143/10485760).
pub fn parse_content_range(header_val: &str) -> Option<(u64, u64, u64)> {
    let clean = header_val.trim();
    if !clean.to_ascii_lowercase().starts_with("bytes ") {
        return None;
    }
    let rest = clean["bytes ".len()..].trim();
    let parts: Vec<&str> = rest.split('/').collect();
    if parts.len() != 2 {
        return None;
    }

    let range_part = parts[0].trim();
    let total_part = parts[1].trim();

    let total: u64 = total_part.parse().ok()?;

    let bounds: Vec<&str> = range_part.split('-').collect();
    if bounds.len() != 2 {
        return None;
    }

    let start: u64 = bounds[0].trim().parse().ok()?;
    let end: u64 = bounds[1].trim().parse().ok()?;

    if start <= end && end < total {
        Some((start, end, total))
    } else {
        None
    }
}

/// In-memory reassembly and streaming stitcher for range chunks.
#[derive(Debug)]
pub struct RangeParallelStitcher {
    total_bytes: u64,
    received_bytes: usize,
    chunks: BTreeMap<u64, Vec<u8>>,
    next_expected_start: u64,
}

impl RangeParallelStitcher {
    /// Creates a new stitcher expecting 	otal_bytes.
    pub fn new(total_bytes: u64) -> Result<Self, String> {
        if total_bytes == 0 {
            return Err("Total bytes must be greater than zero".to_string());
        }
        if total_bytes > BUFFERED_STITCH_MAX_BYTES {
            return Err(format!(
                "Total bytes {} exceeds maximum in-memory stitch capacity of {} bytes",
                total_bytes, BUFFERED_STITCH_MAX_BYTES
            ));
        }
        Ok(Self {
            total_bytes,
            received_bytes: 0,
            chunks: BTreeMap::new(),
            next_expected_start: 0,
        })
    }

    /// Ingests a chunk verifying that it matches its expected bounds.
    pub fn ingest_chunk(&mut self, start_byte: u64, data: Vec<u8>) -> Result<(), String> {
        let len = data.len() as u64;
        if start_byte + len > self.total_bytes {
            return Err(format!(
                "Chunk range {}..{} exceeds total file length {}",
                start_byte,
                start_byte + len,
                self.total_bytes
            ));
        }

        if self.chunks.contains_key(&start_byte) {
            // Duplicate chunk, ignore
            return Ok(());
        }

        self.received_bytes += data.len();
        self.chunks.insert(start_byte, data);
        Ok(())
    }

    /// Drains all contiguous available bytes in ascending order.
    pub fn drain_contiguous(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        while let Some(entry) = self.chunks.first_entry() {
            if *entry.key() == self.next_expected_start {
                let (_, data) = entry.remove_entry();
                self.next_expected_start += data.len() as u64;
                out.extend(data);
            } else {
                break;
            }
        }
        out
    }

    /// Returns true if all chunks have been received and completely reassembled.
    pub fn is_complete(&self) -> bool {
        self.next_expected_start == self.total_bytes
    }
}
