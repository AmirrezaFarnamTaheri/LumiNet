//! Transactional Session State Machine with Rollback and Reassembly.
//!
//! Provides transactional chunk draining, connect-data SYN ride-along,
//! sequence-ordered out-of-order packet reassembly, and pre-drain snapshot rollback.

use std::collections::BTreeMap;
use crate::relay::batch_frame_codec::{Frame, FLAG_FIN, FLAG_SYN, SESSION_ID_LEN};

/// Soft limit for tx buffer backpressure (8 MB).
pub const TX_BUF_HIGH_WATER: usize = 8 * 1024 * 1024;

/// Pre-drain snapshot enabling full session state rollback if batch transport fails.
#[derive(Debug, Clone)]
pub struct DrainSnapshot {
    pub syn_needed: bool,
    pub tx_buf: Vec<u8>,
    pub tx_seq: u64,
    pub fin_sent: bool,
    pub remaining_len: usize,
}

/// Transactional per-connection state machine for relay multiplexing.
pub struct TransactionalSession {
    pub id: [u8; SESSION_ID_LEN],
    pub target: String,
    pub syn_needed: bool,
    pub close_req: bool,
    pub fin_sent: bool,
    pub rx_closed: bool,
    pub tx_buf: Vec<u8>,
    pub tx_seq: u64,
    pub rx_seq: u64,
    pub rx_queue: BTreeMap<u64, Frame>,
}

impl TransactionalSession {
    pub fn new(id: [u8; SESSION_ID_LEN], target: impl Into<String>, needs_syn: bool) -> Self {
        Self {
            id,
            target: target.into(),
            syn_needed: needs_syn,
            close_req: false,
            fin_sent: false,
            rx_closed: false,
            tx_buf: Vec::new(),
            tx_seq: 0,
            rx_seq: 0,
            rx_queue: BTreeMap::new(),
        }
    }

    /// Appends data to the tx buffer if session is open.
    pub fn enqueue_tx(&mut self, data: &[u8]) {
        if self.close_req {
            return;
        }
        self.tx_buf.extend_from_slice(data);
    }

    /// Enqueue initial data to ride along on the SYN frame (connect_data optimization).
    /// Preserves strict FIFO arrival ordering.
    pub fn enqueue_initial_data(&mut self, data: &[u8]) {
        self.tx_buf.extend_from_slice(data);
    }

    /// Requests session closure. Triggers emission of FIN on next drain.
    pub fn request_close(&mut self) {
        self.close_req = true;
    }

    pub fn has_pending_tx(&self) -> bool {
        self.syn_needed || !self.tx_buf.is_empty() || (self.close_req && !self.fin_sent)
    }

    pub fn has_pending_syn(&self) -> bool {
        self.syn_needed
    }

    /// Drains up to `max_frames` frames (each capped at `max_payload` bytes)
    /// and returns a state snapshot for rollback if network transmission fails.
    pub fn drain_tx_limited_txn(
        &mut self,
        max_payload: usize,
        max_frames: usize,
    ) -> (Vec<Frame>, Option<DrainSnapshot>) {
        if !self.has_pending_tx() {
            return (Vec::new(), None);
        }

        let pre_syn_needed = self.syn_needed;
        let pre_tx_buf = self.tx_buf.clone();
        let pre_tx_seq = self.tx_seq;
        let pre_fin_sent = self.fin_sent;

        let mut frames = Vec::new();
        let can_append = |f_len: usize| max_frames == 0 || f_len < max_frames;

        // 1. SYN frame (with first chunk of payload if present)
        if self.syn_needed && can_append(frames.len()) {
            let mut frame = Frame::new(self.id, self.tx_seq, FLAG_SYN).with_target(&self.target);
            self.tx_seq += 1;
            self.syn_needed = false;

            if !self.tx_buf.is_empty() {
                let n = self.tx_buf.len().min(max_payload);
                frame.payload = self.tx_buf.drain(..n).collect();
            }
            frames.push(frame);
        }

        // 2. Remaining payload chunks
        while !self.tx_buf.is_empty() && can_append(frames.len()) {
            let n = self.tx_buf.len().min(max_payload);
            let payload: Vec<u8> = self.tx_buf.drain(..n).collect();
            let frame = Frame::new(self.id, self.tx_seq, 0).with_payload(payload);
            self.tx_seq += 1;
            frames.push(frame);
        }

        // 3. Trailing FIN frame
        if self.close_req && !self.fin_sent && can_append(frames.len()) {
            let frame = Frame::new(self.id, self.tx_seq, FLAG_FIN);
            self.tx_seq += 1;
            self.fin_sent = true;
            frames.push(frame);
        }

        if frames.is_empty() {
            (frames, None)
        } else {
            let snapshot = DrainSnapshot {
                syn_needed: pre_syn_needed,
                tx_buf: pre_tx_buf,
                tx_seq: pre_tx_seq,
                fin_sent: pre_fin_sent,
                remaining_len: self.tx_buf.len(),
            };
            (frames, Some(snapshot))
        }
    }

    /// Restores pre-drain state if batch transmission failed.
    /// Preserves any newly enqueued bytes by appending them after the restored unsent bytes.
    pub fn rollback_drain(&mut self, snapshot: DrainSnapshot) {
        let mut merged = snapshot.tx_buf;
        if self.tx_buf.len() > snapshot.remaining_len {
            merged.extend_from_slice(&self.tx_buf[snapshot.remaining_len..]);
        }
        self.tx_buf = merged;

        self.syn_needed = snapshot.syn_needed;
        self.tx_seq = snapshot.tx_seq;
        self.fin_sent = snapshot.fin_sent;
    }

    /// Delivers an incoming frame into the sequence reassembler.
    /// Returns ordered payloads ready for consumption.
    pub fn process_rx(&mut self, frame: Frame) -> Vec<Vec<u8>> {
        if self.rx_closed {
            return Vec::new();
        }

        // Drop already-acknowledged past sequence frames
        if frame.seq < self.rx_seq {
            return Vec::new();
        }

        // If out of order, buffer into rx_queue
        if frame.seq > self.rx_seq {
            self.rx_queue.insert(frame.seq, frame);
            return Vec::new();
        }

        // In-order frame: process current and any contiguous buffered frames
        let mut delivered = Vec::new();
        let mut current = frame;

        loop {
            let has_fin = current.has_flag(FLAG_FIN);
            if !current.payload.is_empty() {
                delivered.push(current.payload);
            }
            self.rx_seq += 1;

            if has_fin {
                self.rx_closed = true;
                break;
            }

            if let Some(next) = self.rx_queue.remove(&self.rx_seq) {
                current = next;
            } else {
                break;
            }
        }

        delivered
    }

    /// Returns whether both sending and receiving sides have cleanly terminated.
    pub fn is_done(&self) -> bool {
        self.fin_sent && self.rx_closed
    }
}
