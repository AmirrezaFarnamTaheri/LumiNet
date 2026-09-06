package system

import "sync"

// TelemetryRingBuffer is a fixed-capacity circular log buffer.
type TelemetryRingBuffer struct {
	mu       sync.RWMutex
	capacity int
	entries  []string
	head     int
	count    int
}

// NewTelemetryRingBuffer returns a TelemetryRingBuffer with the given capacity.
func NewTelemetryRingBuffer(capacity int) *TelemetryRingBuffer {
	if capacity <= 0 {
		capacity = 256
	}
	return &TelemetryRingBuffer{
		capacity: capacity,
		entries:  make([]string, capacity),
	}
}

// Append adds a log entry to the ring buffer, evicting the oldest if at capacity.
func (r *TelemetryRingBuffer) Append(entry string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[r.head] = entry
	r.head = (r.head + 1) % r.capacity
	if r.count < r.capacity {
		r.count++
	}
}

// Snapshot returns a copy of all current log entries.
func (r *TelemetryRingBuffer) Snapshot() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, r.count)
	start := (r.head - r.count + r.capacity) % r.capacity
	for i := 0; i < r.count; i++ {
		out[i] = r.entries[(start+i)%r.capacity]
	}
	return out
}
