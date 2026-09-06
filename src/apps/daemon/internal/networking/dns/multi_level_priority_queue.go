// Package dns provides networking, tunneling, and scheduling primitives.
// Conforms strictly to §8 structural cleanroom rules.

package dns

import (
	"container/list"
	"math/bits"
	"sync"
	"sync/atomic"
)

const (
	NumQueuePriorities = 6
	DefaultQueuePriority = 3
)

type queueEntry[T any] struct {
	key  uint64
	item T
}

type censusEntry struct {
	priority int
	elem     *list.Element
}

// MultiLevelPriorityQueue is a thread-safe, 6-priority FIFO queue with O(1) scheduling.
// Lower priority numbers represent higher priority (0 is highest, 5 is lowest).
type MultiLevelPriorityQueue[T any] struct {
	mu       sync.RWMutex
	queues   [NumQueuePriorities]*list.List
	census   map[uint64]censusEntry
	bitmask  uint16
	fastSize atomic.Int32
}

// NewMultiLevelPriorityQueue initializes a multi-level priority queue with pre-allocated capacity.
func NewMultiLevelPriorityQueue[T any](initialCapacity int) *MultiLevelPriorityQueue[T] {
	m := &MultiLevelPriorityQueue[T]{
		census: make(map[uint64]censusEntry, initialCapacity),
	}
	for i := range m.queues {
		m.queues[i] = list.New()
	}
	return m
}

// Push adds an item with a priority (0..5) and unique key.
// Returns false if the key already exists (deduplication).
func (m *MultiLevelPriorityQueue[T]) Push(priority int, key uint64, item T) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.census[key]; exists {
		return false
	}

	if priority < 0 || priority >= NumQueuePriorities {
		priority = DefaultQueuePriority
	}

	elem := m.queues[priority].PushBack(queueEntry[T]{
		key:  key,
		item: item,
	})

	m.census[key] = censusEntry{
		priority: priority,
		elem:     elem,
	}
	m.bitmask |= (1 << uint(priority))
	m.fastSize.Add(1)
	return true
}

// Pop extracts the highest-priority item in FIFO order.
func (m *MultiLevelPriorityQueue[T]) Pop() (T, int, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var zero T
	for m.bitmask != 0 {
		priority := bits.TrailingZeros16(m.bitmask)
		if priority >= NumQueuePriorities {
			m.bitmask = 0
			return zero, 0, false
		}

		q := m.queues[priority]
		front := q.Front()
		if front == nil {
			m.bitmask &= ^(1 << uint(priority))
			continue
		}

		entry := front.Value.(queueEntry[T])
		q.Remove(front)
		delete(m.census, entry.key)
		m.fastSize.Add(-1)

		if q.Len() == 0 {
			m.bitmask &= ^(1 << uint(priority))
		}

		return entry.item, priority, true
	}

	return zero, 0, false
}

// Peek returns the highest-priority item without removing it.
func (m *MultiLevelPriorityQueue[T]) Peek() (T, int, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var zero T
	if m.bitmask == 0 {
		return zero, 0, false
	}

	priority := bits.TrailingZeros16(m.bitmask)
	if priority >= NumQueuePriorities {
		return zero, 0, false
	}

	q := m.queues[priority]
	front := q.Front()
	if front != nil {
		entry := front.Value.(queueEntry[T])
		return entry.item, priority, true
	}

	return zero, 0, false
}

// Get retrieves an item by its key without removing it.
func (m *MultiLevelPriorityQueue[T]) Get(key uint64) (T, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var zero T
	entry, exists := m.census[key]
	if !exists || entry.elem == nil {
		return zero, false
	}

	val, ok := entry.elem.Value.(queueEntry[T])
	if !ok {
		return zero, false
	}
	return val.item, true
}

// RemoveByKey removes an item directly by its key in O(1).
func (m *MultiLevelPriorityQueue[T]) RemoveByKey(key uint64) (T, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var zero T
	entry, exists := m.census[key]
	if !exists || entry.elem == nil || entry.priority < 0 || entry.priority >= NumQueuePriorities {
		return zero, false
	}

	val, ok := entry.elem.Value.(queueEntry[T])
	if !ok {
		return zero, false
	}

	q := m.queues[entry.priority]
	q.Remove(entry.elem)
	delete(m.census, key)
	m.fastSize.Add(-1)

	if q.Len() == 0 {
		m.bitmask &= ^(1 << uint(entry.priority))
	}

	return val.item, true
}

// Size returns total items currently enqueued.
func (m *MultiLevelPriorityQueue[T]) Size() int {
	return int(m.fastSize.Load())
}

// CountAtPriority returns items queued at a specific priority tier.
func (m *MultiLevelPriorityQueue[T]) CountAtPriority(priority int) int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if priority < 0 || priority >= NumQueuePriorities {
		return 0
	}
	return m.queues[priority].Len()
}

// Clear flushes all entries from all priority queues.
func (m *MultiLevelPriorityQueue[T]) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i := range m.queues {
		m.queues[i].Init()
	}
	m.census = make(map[uint64]censusEntry)
	m.bitmask = 0
	m.fastSize.Store(0)
}
