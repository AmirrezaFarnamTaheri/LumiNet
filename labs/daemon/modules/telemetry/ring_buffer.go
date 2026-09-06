package telemetry

import (
	"sync"
	"time"
)

// Sample represents a single telemetry data point.
type Sample struct {
	Timestamp int64   `json:"timestamp"` // Unix nanoseconds
	LatencyMs float64 `json:"latency_ms"`
	BytesTx   int64   `json:"bytes_tx"`
	BytesRx   int64   `json:"bytes_rx"`
}

// RingBuffer stores a fixed-capacity rolling window of telemetry samples.
type RingBuffer struct {
	mu       sync.RWMutex
	samples  []Sample
	head     int
	count    int
	capacity int
}

// NewRingBuffer creates a new telemetry ring buffer with specified capacity.
func NewRingBuffer(capacity int) *RingBuffer {
	if capacity <= 0 {
		capacity = 60 // default 60 samples
	}
	return &RingBuffer{
		samples:  make([]Sample, capacity),
		capacity: capacity,
	}
}

// Push adds a new telemetry sample to the buffer.
func (rb *RingBuffer) Push(latencyMs float64, bytesTx, bytesRx int64) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	sample := Sample{
		Timestamp: time.Now().UnixNano(),
		LatencyMs: latencyMs,
		BytesTx:   bytesTx,
		BytesRx:   bytesRx,
	}

	rb.samples[rb.head] = sample
	rb.head = (rb.head + 1) % rb.capacity
	if rb.count < rb.capacity {
		rb.count++
	}
}

// Snapshot returns a copy of the last n samples in chronological order.
func (rb *RingBuffer) Snapshot(n int) []Sample {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	if n <= 0 || n > rb.count {
		n = rb.count
	}

	result := make([]Sample, n)
	start := (rb.head - n + rb.capacity) % rb.capacity

	for i := 0; i < n; i++ {
		idx := (start + i) % rb.capacity
		result[i] = rb.samples[idx]
	}

	return result
}

// Count returns the current number of valid samples stored.
func (rb *RingBuffer) Count() int {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return rb.count
}
