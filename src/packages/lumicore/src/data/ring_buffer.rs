//! # Ring Buffer
//!
//! Fixed-capacity circular buffer with automatic oldest-first eviction.
//!
//! Used for bounded-memory data streams where old data can be dropped
//! when new data arrives faster than it can be consumed.

use std::collections::VecDeque;

/// Fixed-capacity ring buffer with automatic eviction.
#[derive(Debug)]
pub struct RingBuffer<T> {
    buffer: VecDeque<T>,
    capacity: usize,
    evicted: u64,
}

impl<T> RingBuffer<T> {
    /// Creates a new ring buffer with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: VecDeque::with_capacity(capacity),
            capacity,
            evicted: 0,
        }
    }

    /// Pushes an item, evicting the oldest if at capacity.
    pub fn push(&mut self, item: T) {
        if self.buffer.len() >= self.capacity {
            self.buffer.pop_front();
            self.evicted += 1;
        }
        self.buffer.push_back(item);
    }

    /// Drains up to `count` items from the buffer.
    pub fn drain(&mut self, count: usize) -> Vec<T> {
        let drain_count = count.min(self.buffer.len());
        self.buffer.drain(..drain_count).collect()
    }

    /// Drains all items from the buffer.
    pub fn drain_all(&mut self) -> Vec<T> {
        self.buffer.drain(..).collect()
    }

    /// Returns the current number of items.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Returns true if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Returns true if the buffer is at capacity.
    pub fn is_full(&self) -> bool {
        self.buffer.len() >= self.capacity
    }

    /// Returns the number of evicted items.
    pub fn evicted_count(&self) -> u64 {
        self.evicted
    }

    /// Returns the capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

/// Thread-safe stream buffer with dual storage for push/export.
pub struct StreamBuffer<T: Clone> {
    ring: RingBuffer<T>,
    export_batch: VecDeque<T>,
}

impl<T: Clone> StreamBuffer<T> {
    /// Creates a new stream buffer.
    pub fn new(capacity: usize) -> Self {
        Self {
            ring: RingBuffer::new(capacity),
            export_batch: VecDeque::new(),
        }
    }

    /// Pushes an item, evicting oldest if needed.
    pub fn push(&mut self, item: T) {
        self.ring.push(item);
    }

    /// Takes a batch of items for export.
    /// First drains from export_batch, then from ring.
    pub fn take_batch(&mut self, max: usize) -> Vec<T> {
        let mut result = Vec::with_capacity(max);

        // Take from export batch first
        while result.len() < max {
            match self.export_batch.pop_front() {
                Some(item) => result.push(item),
                None => break,
            }
        }

        // Then from ring
        let remaining = max - result.len();
        if remaining > 0 {
            let ring_items = self.ring.drain(remaining);
            result.extend(ring_items);
        }

        result
    }

    /// Restores items back to the export batch (e.g., on export failure).
    pub fn restore(&mut self, items: Vec<T>) {
        for item in items.into_iter().rev() {
            self.export_batch.push_front(item);
        }
    }

    /// Returns total pending items (ring + export batch).
    pub fn pending(&self) -> usize {
        self.ring.len() + self.export_batch.len()
    }
}

/// Buffer pool for zero-allocation packet recycling.
pub struct BufferPool {
    pool: Vec<Vec<u8>>,
    buffer_size: usize,
    max_retained: usize,
}

impl BufferPool {
    /// Creates a new buffer pool with pre-allocated buffers.
    pub fn new(capacity: usize, buffer_size: usize) -> Self {
        let mut pool = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            pool.push(vec![0u8; buffer_size]);
        }
        Self {
            pool,
            buffer_size,
            max_retained: capacity,
        }
    }

    /// Acquires a buffer from the pool.
    pub fn acquire(&mut self) -> Vec<u8> {
        self.pool
            .pop()
            .unwrap_or_else(|| vec![0u8; self.buffer_size])
    }

    /// Returns a buffer to the pool.
    pub fn release(&mut self, mut buf: Vec<u8>) {
        buf.clear();
        buf.resize(self.buffer_size, 0);
        if self.pool.len() < self.max_retained {
            self.pool.push(buf);
        }
    }

    /// Returns the number of available buffers.
    pub fn available(&self) -> usize {
        self.pool.len()
    }
}

/// Stream counter for observability.
pub struct StreamCounter {
    received: std::sync::atomic::AtomicU64,
    flushed: std::sync::atomic::AtomicU64,
    evicted: std::sync::atomic::AtomicU64,
}

impl StreamCounter {
    pub fn new() -> Self {
        Self {
            received: std::sync::atomic::AtomicU64::new(0),
            flushed: std::sync::atomic::AtomicU64::new(0),
            evicted: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn inc_received(&self) {
        self.received
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn inc_flushed(&self, count: u64) {
        self.flushed
            .fetch_add(count, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn inc_evicted(&self, count: u64) {
        self.evicted
            .fetch_add(count, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn received(&self) -> u64 {
        self.received.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn flushed(&self) -> u64 {
        self.flushed.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn evicted(&self) -> u64 {
        self.evicted.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl Default for StreamCounter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ring_buffer_push_evict() {
        let mut ring = RingBuffer::new(3);
        ring.push(1);
        ring.push(2);
        ring.push(3);
        assert_eq!(ring.len(), 3);

        ring.push(4); // Should evict 1
        assert_eq!(ring.len(), 3);
        assert_eq!(ring.evicted_count(), 1);

        let items = ring.drain_all();
        assert_eq!(items, vec![2, 3, 4]);
    }

    #[test]
    fn test_stream_buffer() {
        let mut sb = StreamBuffer::new(10);
        sb.push("a");
        sb.push("b");
        sb.push("c");

        let batch = sb.take_batch(2);
        assert_eq!(batch, vec!["a", "b"]);
        assert_eq!(sb.pending(), 1);
    }

    #[test]
    fn test_buffer_pool() {
        let mut pool = BufferPool::new(3, 1024);
        assert_eq!(pool.available(), 3);

        let buf1 = pool.acquire();
        assert_eq!(pool.available(), 2);

        pool.release(buf1);
        assert_eq!(pool.available(), 3);
    }

    #[test]
    fn test_buffer_pool_never_retains_more_than_capacity() {
        let mut pool = BufferPool::new(2, 64);
        let first = pool.acquire();
        let second = pool.acquire();
        let overflow = pool.acquire();
        assert_eq!(pool.available(), 0);

        pool.release(first);
        pool.release(second);
        pool.release(overflow);

        assert_eq!(pool.available(), 2);
    }
}
