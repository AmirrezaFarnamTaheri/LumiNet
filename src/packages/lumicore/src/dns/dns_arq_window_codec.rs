//! DNS Tunnel ARQ Sliding Window and Compact Codec
//!
//! Provides selective Automatic Repeat reQuest (ARQ) sequencing and Base32/Base36
//! compact encoding for lossy DNS tunnel query and response streams.

use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Default)]
pub struct DnsArqWindowCodec {
    window_size: usize,
    next_send_seq: u32,
    expected_recv_seq: u32,
    unacked_frames: BTreeMap<u32, Vec<u8>>,
    received_frames: BTreeMap<u32, Vec<u8>>,
}

impl DnsArqWindowCodec {
    pub fn new(window_size: usize) -> Self {
        Self {
            window_size: window_size.max(4),
            next_send_seq: 1,
            expected_recv_seq: 1,
            unacked_frames: BTreeMap::new(),
            received_frames: BTreeMap::new(),
        }
    }

    /// Prepares an outbound frame: [Seq: 2B] [Len: 2B] [Data: NB]
    pub fn prepare_frame(&mut self, data: &[u8]) -> Option<(u32, Vec<u8>)> {
        if self.unacked_frames.len() >= self.window_size {
            return None; // Window full
        }

        let seq = self.next_send_seq;
        self.next_send_seq += 1;

        let mut frame = Vec::with_capacity(4 + data.len());
        frame.extend_from_slice(&(seq as u16).to_be_bytes());
        frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
        frame.extend_from_slice(data);

        self.unacked_frames.insert(seq, frame.clone());
        Some((seq, frame))
    }

    /// Acknowledges received frame
    pub fn acknowledge(&mut self, seq: u32) {
        self.unacked_frames.remove(&seq);
    }

    /// Ingests an incoming frame and returns in-order assembled data if contiguous
    pub fn ingest_frame(&mut self, frame: &[u8]) -> Vec<Vec<u8>> {
        if frame.len() < 4 {
            return Vec::new();
        }

        let seq = u16::from_be_bytes([frame[0], frame[1]]) as u32;
        let len = u16::from_be_bytes([frame[2], frame[3]]) as usize;

        if frame.len() < 4 + len {
            return Vec::new();
        }

        let payload = frame[4..4 + len].to_vec();

        if seq < self.expected_recv_seq || self.received_frames.contains_key(&seq) {
            return Vec::new(); // Duplicate
        }

        self.received_frames.insert(seq, payload);

        let mut ready = Vec::new();
        while let Some(data) = self.received_frames.remove(&self.expected_recv_seq) {
            ready.push(data);
            self.expected_recv_seq += 1;
        }
        ready
    }

    pub fn unacked_count(&self) -> usize {
        self.unacked_frames.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_arq_window() {
        let mut arq = DnsArqWindowCodec::new(8);
        let (s1, f1) = arq.prepare_frame(b"chunk1").unwrap();
        let (s2, f2) = arq.prepare_frame(b"chunk2").unwrap();

        assert_eq!(s1, 1);
        assert_eq!(s2, 2);
        assert_eq!(arq.unacked_count(), 2);

        arq.acknowledge(1);
        assert_eq!(arq.unacked_count(), 1);

        // Receiver side: receive out of order
        let r2 = arq.ingest_frame(&f2);
        assert!(r2.is_empty()); // Frame 2 buffered waiting for 1

        let r1 = arq.ingest_frame(&f1);
        assert_eq!(r1.len(), 2); // Both 1 and 2 ready!
        assert_eq!(r1[0], b"chunk1");
        assert_eq!(r1[1], b"chunk2");
    }
}
