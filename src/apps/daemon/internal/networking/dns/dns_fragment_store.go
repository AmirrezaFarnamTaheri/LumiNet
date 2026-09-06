// Package dns provides networking, tunneling, and scheduling primitives.
// Conforms strictly to §8 structural cleanroom rules.

package dns

import (
	"sync"
	"time"
)

type fragmentEntry struct {
	createdAt      time.Time
	totalFragments uint8
	chunks         [256][]byte
	count          uint8
}

// DnsFragmentStore collects multi-chunk DNS tunnel datagrams and reassembles them upon completion.
// Includes duplicate completion tracking with configurable TTL retention.
type DnsFragmentStore[K comparable] struct {
	mu        sync.Mutex
	items     map[K]*fragmentEntry
	completed map[K]time.Time
	lastPurge time.Time
}

// NewDnsFragmentStore creates an initialized store with given initial capacity.
func NewDnsFragmentStore[K comparable](capacity int) *DnsFragmentStore[K] {
	if capacity < 1 {
		capacity = 16
	}
	return &DnsFragmentStore[K]{
		items:     make(map[K]*fragmentEntry, capacity),
		completed: make(map[K]time.Time, capacity),
		lastPurge: time.Now(),
	}
}

// Collect processes a received fragment for a message key.
// Returns:
// - assembled payload (non-nil when all chunks are collected)
// - completed boolean (true when assembled or single-packet succeeded)
// - duplicate boolean (true if packet was already delivered within retention period)
func (s *DnsFragmentStore[K]) Collect(key K, payload []byte, fragmentID uint8, totalFragments uint8, now time.Time, retention time.Duration) ([]byte, bool, bool) {
	// Single fragment fast path
	if totalFragments <= 1 {
		if retention <= 0 {
			return append([]byte(nil), payload...), true, false
		}

		s.mu.Lock()
		defer s.mu.Unlock()

		s.maybePurgeLocked(now, retention)
		if expiresAt, ok := s.completed[key]; ok && now.Before(expiresAt) {
			return nil, false, true
		}

		delete(s.items, key)
		s.completed[key] = now.Add(retention)
		return append([]byte(nil), payload...), true, false
	}

	if fragmentID >= totalFragments {
		return nil, false, false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.maybePurgeLocked(now, retention)
	if expiresAt, ok := s.completed[key]; ok && now.Before(expiresAt) {
		return nil, false, true
	}

	current, ok := s.items[key]
	if !ok || current.totalFragments != totalFragments {
		current = &fragmentEntry{
			createdAt:      now,
			totalFragments: totalFragments,
		}
		s.items[key] = current
	}

	if current.chunks[fragmentID] == nil {
		current.count++
	}
	current.chunks[fragmentID] = append(current.chunks[fragmentID][:0], payload...)

	if current.count < totalFragments {
		return nil, false, false
	}

	// All fragments received: assemble contiguous buffer
	totalSize := 0
	for i := uint8(0); i < totalFragments; i++ {
		chunk := current.chunks[i]
		if chunk == nil {
			return nil, false, false
		}
		totalSize += len(chunk)
	}

	assembled := make([]byte, 0, totalSize)
	for i := uint8(0); i < totalFragments; i++ {
		assembled = append(assembled, current.chunks[i]...)
	}

	delete(s.items, key)
	if retention > 0 {
		s.completed[key] = now.Add(retention)
	} else {
		delete(s.completed, key)
	}

	return assembled, true, false
}

// Purge evicts expired entries and completed sequence markers.
func (s *DnsFragmentStore[K]) Purge(now time.Time, retention time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked(now, retention)
}

func (s *DnsFragmentStore[K]) maybePurgeLocked(now time.Time, retention time.Duration) {
	if now.Sub(s.lastPurge) >= time.Second {
		s.purgeLocked(now, retention)
		s.lastPurge = now
	}
}

func (s *DnsFragmentStore[K]) purgeLocked(now time.Time, retention time.Duration) {
	maxAge := retention
	if maxAge < 5*time.Second {
		maxAge = 5 * time.Second
	}

	for k, entry := range s.items {
		if now.Sub(entry.createdAt) > maxAge {
			delete(s.items, k)
		}
	}
	for k, exp := range s.completed {
		if now.After(exp) {
			delete(s.completed, k)
		}
	}
}

// ActiveEntries returns the count of currently uncompleted fragment sets.
func (s *DnsFragmentStore[K]) ActiveEntries() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}
