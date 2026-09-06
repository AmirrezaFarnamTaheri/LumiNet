package proxy

import (
	"sync"
	"sync/atomic"
)

// PacketItem represents a raw packet held inside the ring queue.
type PacketItem struct {
	Payload []byte
	Length  int
}

// PacketRingQueue provides a lock-free / low-contention ring queue inspired by udp-ring-queue.
type PacketRingQueue struct {
	capacity uint64
	mask     uint64
	head     uint64
	tail     uint64
	ring     []PacketItem
	mu       sync.Mutex
}

// NewPacketRingQueue creates a new ring queue with a power-of-two capacity.
func NewPacketRingQueue(capPow2 uint64) *PacketRingQueue {
	if capPow2 == 0 || (capPow2&(capPow2-1)) != 0 {
		capPow2 = 1024 // Default fallback to 1024
	}
	return &PacketRingQueue{
		capacity: capPow2,
		mask:     capPow2 - 1,
		ring:     make([]PacketItem, capPow2),
	}
}

// Push enqueues a packet payload into the ring queue.
func (q *PacketRingQueue) Push(payload []byte) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	head := atomic.LoadUint64(&q.head)
	tail := atomic.LoadUint64(&q.tail)

	if tail-head >= q.capacity {
		return false // Queue is full
	}

	idx := tail & q.mask
	buf := make([]byte, len(payload))
	copy(buf, payload)

	q.ring[idx] = PacketItem{
		Payload: buf,
		Length:  len(payload),
	}

	atomic.StoreUint64(&q.tail, tail+1)
	return true
}

// Pop dequeues a packet payload from the ring queue.
func (q *PacketRingQueue) Pop() ([]byte, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	head := atomic.LoadUint64(&q.head)
	tail := atomic.LoadUint64(&q.tail)

	if head == tail {
		return nil, false // Queue is empty
	}

	idx := head & q.mask
	item := q.ring[idx]
	q.ring[idx] = PacketItem{} // Clear reference

	atomic.StoreUint64(&q.head, head+1)
	return item.Payload, true
}

// Len returns the current number of items in the queue.
func (q *PacketRingQueue) Len() int {
	head := atomic.LoadUint64(&q.head)
	tail := atomic.LoadUint64(&q.tail)
	if tail >= head {
		return int(tail - head)
	}
	return 0
}
