package proxy

import (
	"container/heap"
	"container/list"
	"sync"
)

// ScheduledWriteRequest represents a payload packet write request from a specific stream.
type ScheduledWriteRequest struct {
	StreamID uint32
	Class    int    // Priority class (lower = higher priority)
	Seq      uint32 // Monotonically increasing sequence number
	Data     []byte
	Callback func(err error)
}

// writeRequestHeap is a min-heap of ScheduledWriteRequest sorted by Class then Seq.
type writeRequestHeap []ScheduledWriteRequest

func (h writeRequestHeap) Len() int { return len(h) }
func (h writeRequestHeap) Less(i, j int) bool {
	if h[i].Class != h[j].Class {
		return h[i].Class < h[j].Class
	}
	return int32(h[i].Seq-h[j].Seq) < 0
}
func (h writeRequestHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *writeRequestHeap) Push(x any)   { *h = append(*h, x.(ScheduledWriteRequest)) }
func (h *writeRequestHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

// StreamScheduler implements priority and round-robin fair-share scheduling
// for multiplexed streams, preventing stream starvation or buffer hogging.
type StreamScheduler struct {
	mu      sync.Mutex
	streams map[uint32]*writeRequestHeap
	rrList  *list.List    // Round-robin list of stream IDs
	next    *list.Element // Next stream node to schedule
	count   int
}

// NewStreamScheduler creates a new StreamScheduler.
func NewStreamScheduler() *StreamScheduler {
	return &StreamScheduler{
		streams: make(map[uint32]*writeRequestHeap),
		rrList:  list.New(),
	}
}

// Push adds a write request for a stream.
func (s *StreamScheduler) Push(req ScheduledWriteRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sid := req.StreamID
	h, exists := s.streams[sid]
	if !exists {
		h = new(writeRequestHeap)
		heap.Init(h)
		s.streams[sid] = h
		elem := s.rrList.PushBack(sid)
		if s.next == nil {
			s.next = elem
		}
	}

	heap.Push(h, req)
	s.count++
}

// Pop retrieves the next scheduled write request using priority-class round-robin.
func (s *StreamScheduler) Pop() (ScheduledWriteRequest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.next == nil || s.count == 0 {
		return ScheduledWriteRequest{}, false
	}

	// 1. Find the highest priority (minimum class value) among all pending requests
	minClass := -1
	for _, h := range s.streams {
		if h.Len() > 0 {
			topClass := (*h)[0].Class
			if minClass == -1 || topClass < minClass {
				minClass = topClass
			}
		}
	}

	if minClass == -1 {
		return ScheduledWriteRequest{}, false
	}

	// 2. Perform Round-Robin to find the first stream with a request of that class
	start := s.next
	current := start

	for {
		sid := current.Value.(uint32)
		h := s.streams[sid]

		if h.Len() > 0 && (*h)[0].Class == minClass {
			req := heap.Pop(h).(ScheduledWriteRequest)
			s.count--

			// Advance the round-robin pointer
			next := current.Next()
			if next == nil {
				next = s.rrList.Front()
			}
			s.next = next

			// If this stream heap is empty, clean it up
			if h.Len() == 0 {
				delete(s.streams, sid)
				s.rrList.Remove(current)
				if s.rrList.Len() == 0 {
					s.next = nil
				}
			}
			return req, true
		}

		current = current.Next()
		if current == nil {
			current = s.rrList.Front()
		}
		if current == start { // fully looped
			break
		}
	}

	return ScheduledWriteRequest{}, false
}

// Len returns total pending requests.
func (s *StreamScheduler) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}
