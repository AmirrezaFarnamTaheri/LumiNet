//! Multipath Packet Deduplication and Sequence Reordering Buffer
//!
//! Tracks received packet sequence numbers over bonded multi-link interfaces,
//! discards duplicate arrivals, and emits ordered streams with minimum jitter.

use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Default)]
pub struct MultipathDedupBuffer {
    expected_seq: u64,
    seen_history: HashSet<u64>,
    reorder_queue: BTreeMap<u64, Vec<u8>>,
    max_history_size: usize,
}

impl MultipathDedupBuffer {
    pub fn new(initial_seq: u64, max_history_size: usize) -> Self {
        Self {
            expected_seq: initial_seq,
            seen_history: HashSet::new(),
            reorder_queue: BTreeMap::new(),
            max_history_size: max_history_size.max(64),
        }
    }

    /// Ingests a packet with a given sequence number.
    /// Returns:
    /// - `None` if duplicate or buffered out-of-order
    /// - `Some(Vec<Vec<u8>>)` containing in-order packets ready for immediate delivery
    pub fn ingest(&mut self, seq: u64, data: Vec<u8>) -> Option<Vec<Vec<u8>>> {
        // Drop duplicates
        if seq < self.expected_seq || self.seen_history.contains(&seq) || self.reorder_queue.contains_key(&seq) {
            return None;
        }

        self.seen_history.insert(seq);
        if self.seen_history.len() > self.max_history_size {
            // Prune lowest
            let min = *self.seen_history.iter().min().unwrap();
            self.seen_history.remove(&min);
        }

        self.reorder_queue.insert(seq, data);

        // Emit contiguous sequence
        let mut ready = Vec::new();
        while let Some(pkt) = self.reorder_queue.remove(&self.expected_seq) {
            ready.push(pkt);
            self.expected_seq += 1;
        }

        if ready.is_empty() {
            None
        } else {
            Some(ready)
        }
    }

    pub fn expected_seq(&self) -> u64 {
        self.expected_seq
    }

    pub fn pending_count(&self) -> usize {
        self.reorder_queue.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dedup_and_reorder() {
        let mut buf = MultipathDedupBuffer::new(1, 100);

        // Packet 2 arrives out of order
        assert!(buf.ingest(2, b"pkt2".to_vec()).is_none());
        assert_eq!(buf.pending_count(), 1);

        // Duplicate packet 2 arrives via link 2 -> dropped
        assert!(buf.ingest(2, b"pkt2".to_vec()).is_none());

        // Packet 1 arrives -> both 1 and 2 ready!
        let ready = buf.ingest(1, b"pkt1".to_vec()).unwrap();
        assert_eq!(ready.len(), 2);
        assert_eq!(ready[0], b"pkt1");
        assert_eq!(ready[1], b"pkt2");
        assert_eq!(buf.expected_seq(), 3);
        assert_eq!(buf.pending_count(), 0);
    }
}
