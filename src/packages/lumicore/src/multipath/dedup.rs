//! Multipath Reorder & Deduplication Buffer
//!
//! Ported and unified from `XPlex-main` (`internal/mpdedup`).
//! Presents out-of-order, duplicated packets arriving across multiple bonded tunnels
//! as a clean, single in-order byte stream. Includes adaptive gap-timeout recovery.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// Default time to wait for a missing sequence number before skipping the gap.
pub const DEFAULT_GAP_TIMEOUT: Duration = Duration::from_millis(3000);

/// Errors surfaced by the deduplication buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DedupError {
    BufferFull { capacity: usize },
}

impl std::fmt::Display for DedupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BufferFull { capacity } => {
                write!(f, "multipath dedup buffer reached capacity limit of {}", capacity)
            }
        }
    }
}

impl std::error::Error for DedupError {}

/// An in-memory reordering and deduplication buffer.
pub struct DedupBuffer {
    next_seq: u64,
    pending: BTreeMap<u64, Vec<u8>>,
    capacity: usize,
    gap_timeout: Duration,
    gap_since: Option<Instant>,
}

impl DedupBuffer {
    /// Creates a new buffer starting at initial sequence number 0.
    pub fn new(capacity: usize) -> Self {
        Self::with_initial_seq(0, capacity, DEFAULT_GAP_TIMEOUT)
    }

    /// Creates a new buffer with custom starting sequence and gap timeout.
    pub fn with_initial_seq(start_seq: u64, capacity: usize, gap_timeout: Duration) -> Self {
        Self {
            next_seq: start_seq,
            pending: BTreeMap::new(),
            capacity,
            gap_timeout,
            gap_since: None,
        }
    }

    /// Returns the next expected sequence number.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Returns the count of pending out-of-order frames currently buffered.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Ingests a frame. Drops duplicates (seq < next_seq).
    /// Emits all contiguous deliverable payloads in order.
    pub fn push(&mut self, seq: u64, payload: Vec<u8>) -> Result<Vec<Vec<u8>>, DedupError> {
        // Stale or duplicate packet
        if seq < self.next_seq {
            return Ok(Vec::new());
        }

        // Expected in-order packet
        if seq == self.next_seq {
            let mut delivered = Vec::new();
            delivered.push(payload);
            self.next_seq += 1;

            // Drain any contiguous successors already in the buffer
            while let Some(entry) = self.pending.remove(&self.next_seq) {
                delivered.push(entry);
                self.next_seq += 1;
            }

            if self.pending.is_empty() {
                self.gap_since = None;
            } else {
                self.gap_since = Some(Instant::now());
            }

            return Ok(delivered);
        }

        // Out-of-order packet (seq > next_seq)
        if self.pending.len() >= self.capacity {
            return Err(DedupError::BufferFull {
                capacity: self.capacity,
            });
        }

        self.pending.insert(seq, payload);
        if self.gap_since.is_none() {
            self.gap_since = Some(Instant::now());
        }

        Ok(Vec::new())
    }

    /// Checks if the gap wait duration has elapsed. If so, skips the missing
    /// sequence numbers, jumps to the lowest available frame, and delivers contiguous data.
    pub fn check_timeout(&mut self) -> Vec<Vec<u8>> {
        let is_timed_out = match self.gap_since {
            Some(since) => since.elapsed() >= self.gap_timeout,
            None => false,
        };

        if !is_timed_out || self.pending.is_empty() {
            return Vec::new();
        }

        // Recover: jump to the lowest buffered sequence
        let lowest_seq = *self.pending.keys().next().unwrap();
        self.next_seq = lowest_seq;

        let mut delivered = Vec::new();
        while let Some(entry) = self.pending.remove(&self.next_seq) {
            delivered.push(entry);
            self.next_seq += 1;
        }

        if self.pending.is_empty() {
            self.gap_since = None;
        } else {
            self.gap_since = Some(Instant::now());
        }

        delivered
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_order_delivery() {
        let mut buf = DedupBuffer::new(100);
        let p0 = buf.push(0, b"packet 0".to_vec()).unwrap();
        assert_eq!(p0, vec![b"packet 0".to_vec()]);

        let p1 = buf.push(1, b"packet 1".to_vec()).unwrap();
        assert_eq!(p1, vec![b"packet 1".to_vec()]);
        assert_eq!(buf.next_seq(), 2);
    }

    #[test]
    fn test_duplicate_dropping() {
        let mut buf = DedupBuffer::new(100);
        buf.push(0, b"packet 0".to_vec()).unwrap();
        assert_eq!(buf.next_seq(), 1);

        // Duplicate seq 0 dropped
        let dup = buf.push(0, b"packet 0 dup".to_vec()).unwrap();
        assert!(dup.is_empty());
        assert_eq!(buf.next_seq(), 1);
    }

    #[test]
    fn test_out_of_order_reassembly() {
        let mut buf = DedupBuffer::new(100);
        // Arrive in order: 2, 3, 1, 0
        assert!(buf.push(2, b"packet 2".to_vec()).unwrap().is_empty());
        assert!(buf.push(3, b"packet 3".to_vec()).unwrap().is_empty());
        assert!(buf.push(1, b"packet 1".to_vec()).unwrap().is_empty());

        // Now seq 0 arrives -> delivers 0, 1, 2, 3 in order!
        let delivered = buf.push(0, b"packet 0".to_vec()).unwrap();
        assert_eq!(delivered.len(), 4);
        assert_eq!(delivered[0], b"packet 0".to_vec());
        assert_eq!(delivered[1], b"packet 1".to_vec());
        assert_eq!(delivered[2], b"packet 2".to_vec());
        assert_eq!(delivered[3], b"packet 3".to_vec());
        assert_eq!(buf.next_seq(), 4);
        assert_eq!(buf.pending_count(), 0);
    }

    #[test]
    fn test_buffer_full_error() {
        let mut buf = DedupBuffer::new(2);
        buf.push(5, b"far 1".to_vec()).unwrap();
        buf.push(6, b"far 2".to_vec()).unwrap();
        // Capacity is 2
        let err = buf.push(7, b"far 3".to_vec()).unwrap_err();
        assert_eq!(err, DedupError::BufferFull { capacity: 2 });
    }

    #[test]
    fn test_gap_timeout_recovery() {
        let mut buf = DedupBuffer::with_initial_seq(0, 10, Duration::from_millis(10));
        // Missing seq 0, only seq 2 and 3 arrived
        buf.push(2, b"packet 2".to_vec()).unwrap();
        buf.push(3, b"packet 3".to_vec()).unwrap();
        assert_eq!(buf.next_seq(), 0);

        // Sleep to exceed gap timeout
        std::thread::sleep(Duration::from_millis(15));
        let recovered = buf.check_timeout();
        assert_eq!(recovered.len(), 2);
        assert_eq!(recovered[0], b"packet 2".to_vec());
        assert_eq!(recovered[1], b"packet 3".to_vec());
        assert_eq!(buf.next_seq(), 4);
    }
}
