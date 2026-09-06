//! # DNS Packet Fragmentation Store
//!
//! Collects and reassembles fragmented UDP/DNS tunnel datagrams into complete contiguous packets.
//! Provides single-fragment fast-path, retention-based duplicate suppression, and periodic expiration.
//! Conforms to §8 structural cleanroom rules.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct FragmentEntry {
    created_at: Instant,
    total_fragments: u8,
    chunks: Vec<Option<Vec<u8>>>,
    received_count: u8,
}

/// Thread-safe fragment collector and reassembly store.
pub struct DnsFragmentStore<K: Eq + Hash + Clone> {
    state: Mutex<StoreState<K>>,
}

struct StoreState<K> {
    items: HashMap<K, FragmentEntry>,
    completed: HashMap<K, Instant>,
    last_purge: Instant,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CollectResult {
    /// Packet is partially received; waiting for more fragments.
    Incomplete,
    /// Packet was previously completed and is rejected within the retention window.
    DuplicateSuppressed,
    /// All fragments have been collected and contiguous payload reassembled.
    Assembled(Vec<u8>),
}

impl<K: Eq + Hash + Clone> DnsFragmentStore<K> {
    pub fn new(capacity: usize) -> Self {
        Self {
            state: Mutex::new(StoreState {
                items: HashMap::with_capacity(capacity),
                completed: HashMap::with_capacity(capacity),
                last_purge: Instant::now(),
            }),
        }
    }

    /// Collects a fragment for the given message key.
    /// - If `total_fragments <= 1`, fast path returns data immediately while remembering completion.
    /// - When all fragments `0..total_fragments-1` are collected, returns `CollectResult::Assembled`.
    pub fn collect(
        &self,
        key: K,
        payload: &[u8],
        fragment_id: u8,
        total_fragments: u8,
        retention: Duration,
    ) -> CollectResult {
        let now = Instant::now();

        // Single fragment fast path
        if total_fragments <= 1 {
            if retention.is_zero() {
                return CollectResult::Assembled(payload.to_vec());
            }

            let mut state = self.state.lock().unwrap();
            Self::maybe_purge(&mut state, now, retention);

            if let Some(&expires_at) = state.completed.get(&key) {
                if now < expires_at {
                    return CollectResult::DuplicateSuppressed;
                }
            }

            state.items.remove(&key);
            state.completed.insert(key, now + retention);
            return CollectResult::Assembled(payload.to_vec());
        }

        if fragment_id >= total_fragments {
            return CollectResult::Incomplete;
        }

        let mut state = self.state.lock().unwrap();
        Self::maybe_purge(&mut state, now, retention);

        if let Some(&expires_at) = state.completed.get(&key) {
            if now < expires_at {
                return CollectResult::DuplicateSuppressed;
            }
        }

        let entry = state.items.entry(key.clone()).or_insert_with(|| FragmentEntry {
            created_at: now,
            total_fragments,
            chunks: vec![None; total_fragments as usize],
            received_count: 0,
        });

        if entry.total_fragments != total_fragments {
            // Sequence mismatch: reset entry
            entry.total_fragments = total_fragments;
            entry.chunks = vec![None; total_fragments as usize];
            entry.received_count = 0;
            entry.created_at = now;
        }

        let idx = fragment_id as usize;
        if idx < entry.chunks.len() {
            if entry.chunks[idx].is_none() {
                entry.received_count += 1;
            }
            entry.chunks[idx] = Some(payload.to_vec());
        }

        if entry.received_count < total_fragments {
            return CollectResult::Incomplete;
        }

        // All fragments have arrived: assemble contiguous buffer
        let mut total_len = 0;
        for chunk_opt in &entry.chunks {
            match chunk_opt {
                Some(chunk) => total_len += chunk.len(),
                None => return CollectResult::Incomplete,
            }
        }

        let mut assembled = Vec::with_capacity(total_len);
        for chunk_opt in &entry.chunks {
            if let Some(chunk) = chunk_opt {
                assembled.extend_from_slice(chunk);
            }
        }

        state.items.remove(&key);
        if !retention.is_zero() {
            state.completed.insert(key, now + retention);
        }

        CollectResult::Assembled(assembled)
    }

    /// Purges expired incomplete entries and completion markers.
    pub fn purge(&self, retention: Duration) {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap();
        Self::purge_internal(&mut state, now, retention);
    }

    fn maybe_purge(state: &mut StoreState<K>, now: Instant, retention: Duration) {
        if now.duration_since(state.last_purge) >= Duration::from_secs(1) {
            Self::purge_internal(state, now, retention);
            state.last_purge = now;
        }
    }

    fn purge_internal(state: &mut StoreState<K>, now: Instant, retention: Duration) {
        let max_age = if retention > Duration::from_secs(5) {
            retention
        } else {
            Duration::from_secs(5)
        };

        state.items.retain(|_, entry| now.duration_since(entry.created_at) < max_age);
        state.completed.retain(|_, &mut expires_at| now < expires_at);
    }

    /// Returns the number of currently active incomplete fragment sets.
    pub fn active_count(&self) -> usize {
        let state = self.state.lock().unwrap();
        state.items.len()
    }
}
