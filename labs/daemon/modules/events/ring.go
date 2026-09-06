// Package events provides replayable event delivery for LumiNet.
//
// Addresses:
//   R-06: WebSocket Events Need Replay
//   R-07: Telemetry Ring and Logs Need Bounded Retention
//
// The EventRing provides:
//   - Monotonic sequence IDs
//   - Bounded in-memory ring (oldest events evicted when full)
//   - Since(seq) for reconnect replay
//   - Thread-safe append and read
package events

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// eventBusDropped counts events dropped because a slow subscriber's
// channel was full. Exported as luminet_event_bus_dropped_total.
var eventBusDropped = promauto.NewCounter(prometheus.CounterOpts{
	Namespace: "luminet",
	Name:      "event_bus_dropped_total",
	Help:      "Total number of events dropped due to full subscriber channels.",
})


// Event is a replayable, sequenced event emitted by any LumiNet subsystem.
type Event struct {
	// Seq is a monotonically increasing sequence number assigned at append time.
	Seq uint64 `json:"seq"`
	// JobID is set for events associated with a specific job.
	JobID string `json:"job_id,omitempty"`
	// Type is the event category, e.g. "job.started", "job.progress", "job.completed", "system.change".
	Type string `json:"type"`
	// Component is the source component, e.g. "scheduler", "proxy", "dns", "system".
	Component string `json:"component,omitempty"`
	// TraceID links this event to a distributed trace.
	TraceID string `json:"trace_id,omitempty"`
	// Timestamp is the wall-clock time the event was appended.
	Timestamp time.Time `json:"timestamp"`
	// Payload is the event-specific data. Must be JSON-serializable.
	Payload any `json:"payload,omitempty"`
}

// EventRing is a bounded, thread-safe in-memory event ring buffer.
// When full, the oldest events are evicted (sliding window).
type EventRing struct {
	mu     sync.RWMutex
	next   uint64
	limit  int
	events []Event
}

// NewEventRing creates an EventRing with the given capacity.
// limit must be > 0. Recommended: 1000–10000.
func NewEventRing(limit int) *EventRing {
	if limit <= 0 {
		limit = 1000
	}
	return &EventRing{
		limit:  limit,
		events: make([]Event, 0, limit),
	}
}

// Append adds an event to the ring, assigns a monotonic sequence number,
// sets Timestamp to now, and returns the stored event (with seq filled in).
func (r *EventRing) Append(e Event) Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.next++
	e.Seq = r.next
	e.Timestamp = time.Now()
	if len(r.events) == r.limit {
		// Ring is full: evict the oldest event (shift left)
		copy(r.events, r.events[1:])
		r.events[len(r.events)-1] = e
	} else {
		r.events = append(r.events, e)
	}
	return e
}

// Since returns all events with Seq > seq, in ascending order.
// Pass seq=0 to get all events currently in the ring.
// Used by WebSocket clients on reconnect to replay missed events.
func (r *EventRing) Since(seq uint64) []Event {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []Event
	for _, e := range r.events {
		if e.Seq > seq {
			out = append(out, e)
		}
	}
	return out
}

// Latest returns the last N events (or fewer if ring contains less).
func (r *EventRing) Latest(n int) []Event {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if n <= 0 || len(r.events) == 0 {
		return nil
	}
	start := len(r.events) - n
	if start < 0 {
		start = 0
	}
	result := make([]Event, len(r.events)-start)
	copy(result, r.events[start:])
	return result
}

// Len returns the number of events currently in the ring.
func (r *EventRing) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.events)
}

// MaxSeq returns the highest sequence number assigned, or 0 if empty.
func (r *EventRing) MaxSeq() uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.next
}

// EventBus is a replayable fan-out event bus backed by an EventRing.
// Subscribers receive all future events via a buffered channel.
// On reconnect, they can use Since() to replay missed events.
type EventBus struct {
	ring        *EventRing
	mu          sync.RWMutex
	subscribers map[string]chan Event
}

// NewEventBus creates an EventBus with the specified ring capacity.
func NewEventBus(ringSize int) *EventBus {
	return &EventBus{
		ring:        NewEventRing(ringSize),
		subscribers: make(map[string]chan Event),
	}
}

// Publish appends an event to the ring and delivers it to all current subscribers.
// Non-blocking: subscribers with full channels receive a dropped-event metric.
func (b *EventBus) Publish(e Event) Event {
	stored := b.ring.Append(e)
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, ch := range b.subscribers {
		select {
		case ch <- stored:
		default:
			// Subscriber channel full — drop event (subscriber is slow).
			eventBusDropped.Inc()
		}
	}
	return stored
}

// Subscribe registers a new subscriber with the given id.
// Returns a channel that receives future events and the current max sequence
// number — caller should call Since(maxSeq) to replay any events missed between
// calling Subscribe and beginning to read the channel.
// bufSize controls the channel buffer. Recommended: 256.
func (b *EventBus) Subscribe(id string, bufSize int) (<-chan Event, uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch := make(chan Event, bufSize)
	b.subscribers[id] = ch
	return ch, b.ring.MaxSeq()
}

// Unsubscribe removes and closes the subscriber channel.
func (b *EventBus) Unsubscribe(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ch, ok := b.subscribers[id]; ok {
		close(ch)
		delete(b.subscribers, id)
	}
}

// Since proxies to the underlying ring for reconnect replay.
func (b *EventBus) Since(seq uint64) []Event {
	return b.ring.Since(seq)
}

// Ring returns the underlying EventRing for direct inspection.
func (b *EventBus) Ring() *EventRing { return b.ring }
