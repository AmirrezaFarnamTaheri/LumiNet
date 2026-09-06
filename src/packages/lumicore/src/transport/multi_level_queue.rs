//! # Multi-Level Priority Queue (MLQ)
//!
//! Provides a thread-safe, 6-level priority queue with O(1) highest-priority selection via
//! CPU bitmask trailing zeros (`trailing_zeros`), coupled with an O(1) hash map census for
//! key-based deduplication and direct removal.
//! Conforms to §8 structural cleanroom rules.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::RwLock;

const NUM_PRIORITIES: usize = 6;
const DEFAULT_PRIORITY: usize = 3;

#[derive(Debug, Clone)]
struct QueueEntry<T> {
    key: u64,
    item: T,
}

#[derive(Debug, Clone)]
struct CensusEntry {
    priority: usize,
    index_in_queue: usize,
}

/// Multi-level priority queue with O(1) bitmask priority selection.
/// Lower priority numbers represent higher priority (0 is highest, 5 is lowest).
pub struct MultiLevelQueue<T> {
    queues: RwLock<[VecDeque<QueueEntry<T>>; NUM_PRIORITIES]>,
    census: RwLock<HashMap<u64, CensusEntry>>,
    bitmask: RwLock<u16>,
    fast_size: AtomicI32,
}

impl<T: Clone> MultiLevelQueue<T> {
    pub fn new(initial_capacity: usize) -> Self {
        Self {
            queues: RwLock::new(std::array::from_fn(|_| VecDeque::with_capacity(initial_capacity / NUM_PRIORITIES + 1))),
            census: RwLock::new(HashMap::with_capacity(initial_capacity)),
            bitmask: RwLock::new(0),
            fast_size: AtomicI32::new(0),
        }
    }

    /// Pushes an item at the given priority level with a unique key.
    /// Returns `false` if the key is already present in the queue (deduplication).
    pub fn push(&self, mut priority: usize, key: u64, item: T) -> bool {
        let mut census = self.census.write().unwrap();
        if census.contains_key(&key) {
            return false;
        }

        if priority >= NUM_PRIORITIES {
            priority = DEFAULT_PRIORITY;
        }

        let mut queues = self.queues.write().unwrap();
        let idx = queues[priority].len();
        queues[priority].push_back(QueueEntry { key, item });

        census.insert(key, CensusEntry { priority, index_in_queue: idx });

        let mut mask = self.bitmask.write().unwrap();
        *mask |= 1 << (priority as u16);
        self.fast_size.fetch_add(1, Ordering::Relaxed);

        true
    }

    /// Pops the highest-priority (lowest priority index) item in FIFO order.
    pub fn pop(&self) -> Option<(T, usize)> {
        let mut mask = self.bitmask.write().unwrap();
        if *mask == 0 {
            return None;
        }

        let mut queues = self.queues.write().unwrap();
        let mut census = self.census.write().unwrap();

        while *mask != 0 {
            let priority = mask.trailing_zeros() as usize;
            if priority >= NUM_PRIORITIES {
                *mask = 0;
                return None;
            }

            let q = &mut queues[priority];
            if let Some(entry) = q.pop_front() {
                census.remove(&entry.key);
                self.fast_size.fetch_sub(1, Ordering::Relaxed);

                // Update indices of remaining elements in this priority queue
                for (i, elem) in q.iter().enumerate() {
                    if let Some(c) = census.get_mut(&elem.key) {
                        c.index_in_queue = i;
                    }
                }

                if q.is_empty() {
                    *mask &= !(1 << (priority as u16));
                }
                return Some((entry.item, priority));
            } else {
                *mask &= !(1 << (priority as u16));
            }
        }

        None
    }

    /// Peeks at the highest-priority item without removing it.
    pub fn peek(&self) -> Option<(T, usize)> {
        let mask = *self.bitmask.read().unwrap();
        if mask == 0 {
            return None;
        }

        let priority = mask.trailing_zeros() as usize;
        if priority >= NUM_PRIORITIES {
            return None;
        }

        let queues = self.queues.read().unwrap();
        queues[priority].front().map(|e| (e.item.clone(), priority))
    }

    /// Retrieves an item by its key without removing it.
    pub fn get(&self, key: u64) -> Option<T> {
        let census = self.census.read().unwrap();
        let entry_meta = census.get(&key)?;
        let queues = self.queues.read().unwrap();
        queues[entry_meta.priority]
            .get(entry_meta.index_in_queue)
            .map(|e| e.item.clone())
    }

    /// Removes an item directly by its key in O(N_priority) where N_priority is items in that specific tier.
    pub fn remove_by_key(&self, key: u64) -> Option<T> {
        let mut census = self.census.write().unwrap();
        let entry_meta = census.remove(&key)?;

        let mut queues = self.queues.write().unwrap();
        let q = &mut queues[entry_meta.priority];

        if entry_meta.index_in_queue < q.len() {
            let removed = q.remove(entry_meta.index_in_queue)?;
            self.fast_size.fetch_sub(1, Ordering::Relaxed);

            // Re-index subsequent items in this queue tier
            for i in entry_meta.index_in_queue..q.len() {
                let k = q[i].key;
                if let Some(c) = census.get_mut(&k) {
                    c.index_in_queue = i;
                }
            }

            if q.is_empty() {
                let mut mask = self.bitmask.write().unwrap();
                *mask &= !(1 << (entry_meta.priority as u16));
            }
            return Some(removed.item);
        }

        None
    }

    /// Returns the total count of items in the queue.
    pub fn len(&self) -> usize {
        let sz = self.fast_size.load(Ordering::Relaxed);
        if sz < 0 {
            0
        } else {
            sz as usize
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the number of items in a specific priority tier.
    pub fn count_at_priority(&self, priority: usize) -> usize {
        if priority >= NUM_PRIORITIES {
            return 0;
        }
        let queues = self.queues.read().unwrap();
        queues[priority].len()
    }

    /// Clears the queue.
    pub fn clear(&self) {
        let mut queues = self.queues.write().unwrap();
        let mut census = self.census.write().unwrap();
        let mut mask = self.bitmask.write().unwrap();

        for q in queues.iter_mut() {
            q.clear();
        }
        census.clear();
        *mask = 0;
        self.fast_size.store(0, Ordering::Relaxed);
    }
}
