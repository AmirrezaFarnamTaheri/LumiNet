//! # Multi-Path Micro-Dispersal Engine
//!
//! Splits arbitrary TCP stream byte sequences into discrete `MicroFrame`s,
//! stripes them across orthogonal serverless edge runners (Cloudflare Workers,
//! Vercel Edge, AWS Lambda, Google Apps Script), and provides an out-of-order
//! sequence reassembly buffer.
//!
//! ## Official References:
//! - RFC 9293 (Transmission Control Protocol: In-order Sequence Reassembly)
//! - bytes crate: <https://docs.rs/bytes/latest/bytes/>
//! - thiserror: <https://docs.rs/thiserror/latest/thiserror/>
//!
//! ## Design Patterns:
//! - `leonardomso-rust-skills`: `mem-zero-copy`, `type-enum-states`, `err-thiserror-lib`, `own-borrow-over-clone`

use bytes::{Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Dispersal operational errors.
#[derive(Debug, Error)]
pub enum DispersalError {
    #[error("no edge runner endpoints configured")]
    NoEndpointsConfigured,
    #[error("payload chunking error: {0}")]
    ChunkingFailed(String),
}

/// Supported serverless edge runner types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeRunnerType {
    CloudflareWorkers,
    VercelEdge,
    AWSLambda,
    GoogleAppsScript,
}

/// An edge runner endpoint configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeEndpoint {
    pub runner_type: EdgeRunnerType,
    pub url: String,
}

/// Striped micro-frame transmitted over an edge relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicroFrame {
    pub session_id: String,
    pub seq: u64,
    pub chunk_idx: usize,
    pub total_chunks: usize,
    #[serde(with = "bytes_serde")]
    pub data: Bytes,
    pub endpoint_url: String,
}

mod bytes_serde {
    use bytes::Bytes;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Bytes, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Bytes, D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec = Vec::<u8>::deserialize(deserializer)?;
        Ok(Bytes::from(vec))
    }
}

/// Multi-path micro-disperser that fragments and routes streams.
pub struct MicroDisperser {
    endpoints: Vec<EdgeEndpoint>,
    chunk_size: usize,
}

impl MicroDisperser {
    /// Creates a new `MicroDisperser`.
    #[must_use]
    pub fn new(endpoints: Vec<EdgeEndpoint>, chunk_size: usize) -> Self {
        let size = if chunk_size == 0 { 1024 } else { chunk_size };
        Self {
            endpoints,
            chunk_size: size,
        }
    }

    /// Splits a slice of data into `MicroFrame`s striped across available endpoints.
    #[must_use]
    pub fn chunk_payload(&self, session_id: &str, _target: &str, data: &[u8]) -> Vec<MicroFrame> {
        if data.is_empty() || self.endpoints.is_empty() {
            return Vec::new();
        }

        let chunks: Vec<&[u8]> = data.chunks(self.chunk_size).collect();
        let total_chunks = chunks.len();
        let mut frames = Vec::with_capacity(total_chunks);

        for (i, chunk) in chunks.into_iter().enumerate() {
            let endpoint = &self.endpoints[i % self.endpoints.len()];
            frames.push(MicroFrame {
                session_id: session_id.to_string(),
                seq: i as u64,
                chunk_idx: i,
                total_chunks,
                data: Bytes::copy_from_slice(chunk),
                endpoint_url: endpoint.url.clone(),
            });
        }

        frames
    }
}

/// Out-of-order sequence reassembler buffer.
#[derive(Debug, Default)]
pub struct DispersalReassembler {
    expected_seq: u64,
    queue: BTreeMap<u64, Bytes>,
}

impl DispersalReassembler {
    /// Creates a new, empty `DispersalReassembler`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            expected_seq: 0,
            queue: BTreeMap::new(),
        }
    }

    /// Pushes a received `MicroFrame` into the reassembly buffer.
    pub fn push_frame(&mut self, frame: MicroFrame) {
        if frame.seq >= self.expected_seq {
            self.queue.insert(frame.seq, frame.data);
        }
    }

    /// Drains all contiguous available bytes in sequence.
    pub fn drain_contiguous(&mut self) -> Bytes {
        let mut out = BytesMut::new();
        while let Some(chunk) = self.queue.remove(&self.expected_seq) {
            out.extend_from_slice(&chunk);
            self.expected_seq += 1;
        }
        out.freeze()
    }

    /// Returns the currently expected contiguous sequence number.
    #[must_use]
    pub fn expected_seq(&self) -> u64 {
        self.expected_seq
    }

    /// Returns the count of out-of-order frames currently buffered.
    #[must_use]
    pub fn buffered_count(&self) -> usize {
        self.queue.len()
    }
}
