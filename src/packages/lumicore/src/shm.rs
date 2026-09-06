//! Shared memory IPC channel for packet processing.
//! Layout-compatible with Go's SharedChannel.

pub const RING_CAPACITY: usize = 1024;
pub const SLOT_SIZE: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingPushError {
    PacketTooLarge,
    BufferFull,
    InvalidCapacity,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Slot {
    pub length: u32,
    pub reserved: u32,
    pub data: [u8; SLOT_SIZE],
}

#[repr(C)]
pub struct RingBuffer {
    pub head: std::sync::atomic::AtomicU64,
    pub tail: std::sync::atomic::AtomicU64,
    pub capacity: u32,
    pub reserved: u32,
    pub slots: [Slot; RING_CAPACITY],
}

#[repr(C)]
pub struct SharedChannel {
    pub go_to_rust: RingBuffer,
    pub rust_to_go: RingBuffer,
}

impl RingBuffer {
    fn checked_capacity(&self) -> Option<u64> {
        let capacity = self.capacity as usize;
        if capacity == 0 || capacity > RING_CAPACITY {
            return None;
        }
        Some(capacity as u64)
    }
}

impl SharedChannel {
    /// Pushes a packet to the Rust-to-Go ring buffer.
    pub fn push_rust_to_go(&self, packet: &[u8]) -> Result<(), RingPushError> {
        if packet.len() > SLOT_SIZE {
            return Err(RingPushError::PacketTooLarge);
        }
        let capacity = self
            .rust_to_go
            .checked_capacity()
            .ok_or(RingPushError::InvalidCapacity)?;
        let head = self
            .rust_to_go
            .head
            .load(std::sync::atomic::Ordering::Acquire);
        let tail = self
            .rust_to_go
            .tail
            .load(std::sync::atomic::Ordering::Acquire);
        let used = head
            .checked_sub(tail)
            .ok_or(RingPushError::InvalidCapacity)?;
        if used >= capacity {
            return Err(RingPushError::BufferFull);
        }
        let idx = (head % capacity) as usize;
        unsafe {
            let slots_ptr = self.rust_to_go.slots.as_ptr() as *mut Slot;
            let slot = &mut *slots_ptr.add(idx);
            slot.length = packet.len() as u32;
            std::ptr::copy_nonoverlapping(packet.as_ptr(), slot.data.as_mut_ptr(), packet.len());
        }
        self.rust_to_go
            .head
            .store(head + 1, std::sync::atomic::Ordering::Release);
        Ok(())
    }

    /// Pops a packet from the Go-to-Rust ring buffer.
    pub fn pop_go_to_rust(&self) -> Option<Vec<u8>> {
        let capacity = self.go_to_rust.checked_capacity()?;
        let head = self
            .go_to_rust
            .head
            .load(std::sync::atomic::Ordering::Acquire);
        let tail = self
            .go_to_rust
            .tail
            .load(std::sync::atomic::Ordering::Acquire);
        let used = head.checked_sub(tail)?;
        if used == 0 {
            return None; // Buffer empty
        }
        if used > capacity {
            return None; // Corrupt sequence/capacity state.
        }
        let idx = (tail % capacity) as usize;
        let packet = unsafe {
            let slots_ptr = self.go_to_rust.slots.as_ptr() as *mut Slot;
            let slot = &*slots_ptr.add(idx);
            let len = slot.length as usize;
            if len > SLOT_SIZE {
                return None;
            }
            slot.data[..len].to_vec()
        };
        self.go_to_rust
            .tail
            .store(tail + 1, std::sync::atomic::Ordering::Release);
        Some(packet)
    }
}

pub static SHM_CHANNEL: std::sync::atomic::AtomicPtr<SharedChannel> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());
