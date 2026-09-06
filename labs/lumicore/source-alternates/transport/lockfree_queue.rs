//! # Lock-Free SPSC/MPSC Ring Queue
//!
//! Cache-aligned, atomic lock-free ring buffer optimized for single-producer
//! single-consumer (SPSC) and multi-producer single-consumer (MPSC) usage.
//! Ported from unique-queue-master (C11 atomic queue implementation).
//!
//! Design:
//! - Power-of-two capacity for bitmask indexing (no modulo).
//! - Cache-line padded head and tail (64-byte alignment) to prevent false sharing.
//! - Relaxed loads on the fast path; Release/Acquire only at the commit fence.

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::mem::MaybeUninit;

/// Cache line size for padding.
const CACHE_LINE: usize = 64;

/// Cache-line-padded atomic counter to prevent false sharing.
#[repr(C, align(64))]
struct PaddedAtomic {
    val: AtomicUsize,
    _pad: [u8; CACHE_LINE - std::mem::size_of::<AtomicUsize>()],
}

impl PaddedAtomic {
    const fn new(v: usize) -> Self {
        Self {
            val: AtomicUsize::new(v),
            _pad: [0u8; CACHE_LINE - std::mem::size_of::<AtomicUsize>()],
        }
    }
}

/// Internal shared ring buffer state.
struct RingInner<T> {
    capacity: usize,
    mask: usize,
    head: PaddedAtomic,
    tail: PaddedAtomic,
    slots: Box<[UnsafeCell<MaybeUninit<T>>]>,
}

unsafe impl<T: Send> Send for RingInner<T> {}
unsafe impl<T: Send> Sync for RingInner<T> {}

impl<T> RingInner<T> {
    fn with_capacity(cap: usize) -> Self {
        assert!(cap.is_power_of_two(), "capacity must be a power of two");
        let slots: Box<[UnsafeCell<MaybeUninit<T>>]> = (0..cap)
            .map(|_| UnsafeCell::new(MaybeUninit::uninit()))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            capacity: cap,
            mask: cap - 1,
            head: PaddedAtomic::new(0),
            tail: PaddedAtomic::new(0),
            slots,
        }
    }

    /// Returns true if the queue currently holds no elements.
    fn is_empty(&self) -> bool {
        let head = self.head.val.load(Ordering::Acquire);
        let tail = self.tail.val.load(Ordering::Acquire);
        head == tail
    }

    /// Returns the number of elements currently in the queue.
    fn len(&self) -> usize {
        let head = self.head.val.load(Ordering::Acquire);
        let tail = self.tail.val.load(Ordering::Acquire);
        tail.wrapping_sub(head)
    }
}

/// SPSC lock-free producer handle.
pub struct Producer<T> {
    inner: Arc<RingInner<T>>,
}

/// SPSC lock-free consumer handle.
pub struct Consumer<T> {
    inner: Arc<RingInner<T>>,
}

/// Creates a new SPSC lock-free ring queue with the given power-of-two capacity.
///
/// # Panics
/// Panics if `capacity` is not a power of two.
pub fn spsc_ring<T>(capacity: usize) -> (Producer<T>, Consumer<T>) {
    let inner = Arc::new(RingInner::with_capacity(capacity));
    (Producer { inner: Arc::clone(&inner) }, Consumer { inner })
}

impl<T> Producer<T> {
    /// Tries to enqueue an item. Returns `Err(item)` if the queue is full.
    pub fn push(&self, item: T) -> Result<(), T> {
        let inner = &*self.inner;
        let tail = inner.tail.val.load(Ordering::Relaxed);
        let head = inner.head.val.load(Ordering::Acquire);

        if tail.wrapping_sub(head) >= inner.capacity {
            return Err(item); // Full
        }

        let slot = tail & inner.mask;
        unsafe {
            (*inner.slots[slot].get()).write(item);
        }
        // Release fence: ensures the write is visible before incrementing tail.
        inner.tail.val.store(tail.wrapping_add(1), Ordering::Release);
        Ok(())
    }

    /// Returns how many slots are currently available.
    pub fn available(&self) -> usize {
        let inner = &*self.inner;
        let tail = inner.tail.val.load(Ordering::Relaxed);
        let head = inner.head.val.load(Ordering::Acquire);
        inner.capacity - tail.wrapping_sub(head)
    }
}

impl<T> Consumer<T> {
    /// Tries to dequeue an item. Returns `None` if the queue is empty.
    pub fn pop(&self) -> Option<T> {
        let inner = &*self.inner;
        let head = inner.head.val.load(Ordering::Relaxed);
        let tail = inner.tail.val.load(Ordering::Acquire);

        if head == tail {
            return None; // Empty
        }

        let slot = head & inner.mask;
        let item = unsafe { (*inner.slots[slot].get()).assume_init_read() };
        // Release: ensures read completes before head is incremented.
        inner.head.val.store(head.wrapping_add(1), Ordering::Release);
        Some(item)
    }

    /// Returns the current number of items ready to consume.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if there are no items to consume.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Drains all available items into a `Vec`.
    pub fn drain_all(&self) -> Vec<T> {
        let mut out = Vec::with_capacity(self.len());
        while let Some(item) = self.pop() {
            out.push(item);
        }
        out
    }
}

struct MpscCell<T> {
    sequence: AtomicUsize,
    value: UnsafeCell<MaybeUninit<T>>,
}

struct MpscInner<T> {
    capacity: usize,
    mask: usize,
    head: PaddedAtomic,
    tail: PaddedAtomic,
    buffer: Box<[MpscCell<T>]>,
}

unsafe impl<T: Send> Send for MpscInner<T> {}
unsafe impl<T: Send> Sync for MpscInner<T> {}

impl<T> MpscInner<T> {
    fn with_capacity(cap: usize) -> Self {
        assert!(cap.is_power_of_two(), "capacity must be a power of two");
        let mut vec = Vec::with_capacity(cap);
        for i in 0..cap {
            vec.push(MpscCell {
                sequence: AtomicUsize::new(i),
                value: UnsafeCell::new(MaybeUninit::uninit()),
            });
        }
        Self {
            capacity: cap,
            mask: cap - 1,
            head: PaddedAtomic::new(0),
            tail: PaddedAtomic::new(0),
            buffer: vec.into_boxed_slice(),
        }
    }

    fn is_empty(&self) -> bool {
        let head = self.head.val.load(Ordering::Acquire);
        let tail = self.tail.val.load(Ordering::Acquire);
        head == tail
    }

    fn len(&self) -> usize {
        let head = self.head.val.load(Ordering::Acquire);
        let tail = self.tail.val.load(Ordering::Acquire);
        tail.wrapping_sub(head)
    }
}

/// MPSC (multi-producer, single-consumer) ring queue.
/// Multiple threads can push concurrently; only one thread may pop.
pub struct MpscRing<T> {
    inner: Arc<MpscInner<T>>,
}

impl<T: Send> MpscRing<T> {
    /// Creates a new MPSC ring with the given power-of-two capacity.
    pub fn new(capacity: usize) -> (Vec<MpscProducer<T>>, MpscConsumer<T>) {
        let inner = Arc::new(MpscInner::with_capacity(capacity));
        // All producers share the same Arc; the tail is CAS-protected.
        let producers = (0..4).map(|_| MpscProducer { inner: Arc::clone(&inner) }).collect();
        let consumer = MpscConsumer { inner };
        (producers, consumer)
    }
}

/// MPSC producer — uses a compare-and-swap to claim a slot.
pub struct MpscProducer<T> {
    inner: Arc<MpscInner<T>>,
}

impl<T> MpscProducer<T> {
    /// Tries to enqueue an item using a CAS loop. Returns `Err(item)` if full.
    pub fn push(&self, item: T) -> Result<(), T> {
        let inner = &*self.inner;
        let mut tail = inner.tail.val.load(Ordering::Relaxed);
        loop {
            let cell = &inner.buffer[tail & inner.mask];
            let seq = cell.sequence.load(Ordering::Acquire);
            let diff = (seq as isize).wrapping_sub(tail as isize);
            if diff == 0 {
                match inner.tail.val.compare_exchange_weak(
                    tail,
                    tail.wrapping_add(1),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        unsafe { (*cell.value.get()).write(item); }
                        cell.sequence.store(tail.wrapping_add(1), Ordering::Release);
                        return Ok(());
                    }
                    Err(x) => tail = x,
                }
            } else if diff < 0 {
                let head = inner.head.val.load(Ordering::Acquire);
                if tail.wrapping_sub(head) >= inner.capacity {
                    return Err(item);
                }
                tail = inner.tail.val.load(Ordering::Relaxed);
            } else {
                tail = inner.tail.val.load(Ordering::Relaxed);
            }
        }
    }
}

/// MPSC consumer — single-threaded pop.
pub struct MpscConsumer<T> {
    inner: Arc<MpscInner<T>>,
}

impl<T> MpscConsumer<T> {
    pub fn pop(&self) -> Option<T> {
        let inner = &*self.inner;
        let mut head = inner.head.val.load(Ordering::Relaxed);
        loop {
            let cell = &inner.buffer[head & inner.mask];
            let seq = cell.sequence.load(Ordering::Acquire);
            let diff = (seq as isize).wrapping_sub((head.wrapping_add(1)) as isize);
            if diff == 0 {
                match inner.head.val.compare_exchange_weak(
                    head,
                    head.wrapping_add(1),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        let item = unsafe { (*cell.value.get()).assume_init_read() };
                        cell.sequence.store(head.wrapping_add(inner.capacity), Ordering::Release);
                        return Some(item);
                    }
                    Err(x) => head = x,
                }
            } else if diff < 0 {
                let tail = inner.tail.val.load(Ordering::Acquire);
                if head == tail {
                    return None;
                }
                head = inner.head.val.load(Ordering::Relaxed);
            } else {
                head = inner.head.val.load(Ordering::Relaxed);
            }
        }
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_spsc_basic_push_pop() {
        let (prod, cons) = spsc_ring::<u32>(16);
        prod.push(1).unwrap();
        prod.push(2).unwrap();
        prod.push(3).unwrap();
        assert_eq!(cons.pop(), Some(1));
        assert_eq!(cons.pop(), Some(2));
        assert_eq!(cons.pop(), Some(3));
        assert_eq!(cons.pop(), None);
    }

    #[test]
    fn test_spsc_full_returns_err() {
        let (prod, _cons) = spsc_ring::<u32>(4);
        prod.push(1).unwrap();
        prod.push(2).unwrap();
        prod.push(3).unwrap();
        prod.push(4).unwrap();
        assert!(prod.push(5).is_err());
    }

    #[test]
    fn test_spsc_drain_all() {
        let (prod, cons) = spsc_ring::<u32>(8);
        for i in 0..5 {
            prod.push(i).unwrap();
        }
        let drained = cons.drain_all();
        assert_eq!(drained, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn test_spsc_thread_safety() {
        let (prod, cons) = spsc_ring::<u32>(1024);
        let n = 500u32;

        let producer = thread::spawn(move || {
            for i in 0..n {
                loop {
                    if prod.push(i).is_ok() { break; }
                    std::hint::spin_loop();
                }
            }
        });

        let mut received = Vec::new();
        while received.len() < n as usize {
            if let Some(item) = cons.pop() {
                received.push(item);
            } else {
                std::hint::spin_loop();
            }
        }

        producer.join().unwrap();
        assert_eq!(received, (0..n).collect::<Vec<_>>());
    }

    #[test]
    fn test_capacity_must_be_power_of_two() {
        let result = std::panic::catch_unwind(|| {
            spsc_ring::<u32>(7)
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_mpsc_basic_push_pop() {
        let (prods, cons) = MpscRing::<u32>::new(16);
        prods[0].push(1).unwrap();
        prods[0].push(2).unwrap();
        prods[1].push(3).unwrap();
        assert_eq!(cons.pop(), Some(1));
        assert_eq!(cons.pop(), Some(2));
        assert_eq!(cons.pop(), Some(3));
        assert_eq!(cons.pop(), None);
    }

    #[test]
    fn test_mpsc_full_returns_err() {
        let (prods, _cons) = MpscRing::<u32>::new(4);
        prods[0].push(1).unwrap();
        prods[0].push(2).unwrap();
        prods[0].push(3).unwrap();
        prods[0].push(4).unwrap();
        assert!(prods[0].push(5).is_err());
    }

    #[test]
    fn test_mpsc_thread_safety() {
        let (prods, cons) = MpscRing::<u32>::new(1024);
        let n = 250u32;
        let mut threads = Vec::new();

        // 4 producers, each pushing 250 items
        for (idx, prod) in prods.into_iter().enumerate() {
            threads.push(thread::spawn(move || {
                for i in 0..n {
                    let val = (idx as u32) * 1000 + i;
                    loop {
                        if prod.push(val).is_ok() { break; }
                        std::hint::spin_loop();
                    }
                }
            }));
        }

        let mut received = Vec::new();
        let total_expected = n as usize * 4;
        while received.len() < total_expected {
            if let Some(item) = cons.pop() {
                received.push(item);
            } else {
                std::hint::spin_loop();
            }
        }

        for t in threads {
            t.join().unwrap();
        }

        assert_eq!(received.len(), total_expected);
        // Verify we got the correct numbers of elements from each producer prefix
        for idx in 0..4 {
            let count = received.iter().filter(|&&v| v >= (idx as u32) * 1000 && v < (idx as u32) * 1000 + n).count();
            assert_eq!(count, n as usize);
        }
    }
}
