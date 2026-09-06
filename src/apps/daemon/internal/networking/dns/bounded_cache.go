package dns

import (
	"container/list"
	"sync"
	"time"
)

const defaultDNSCacheEntries = 4096

type cacheFreshness uint8

const (
	cacheMiss cacheFreshness = iota
	cacheFresh
	cacheStale
)

type timedLRUEntry[V any] struct {
	key        string
	value      V
	expiresAt  time.Time
	staleUntil time.Time
}

// boundedTTLCache is the shared DNS-plane memory cache primitive. It keeps one
// bounded LRU index, supports an optional stale window, and clones values at
// the ownership boundary so callers cannot mutate cached slices after Set/Get.
//
// It intentionally uses one mutex: DNS cache operations are tiny and the
// single lock keeps LRU ordering, expiry, capacity, and ownership atomic.
type boundedTTLCache[V any] struct {
	mu         sync.Mutex
	maxEntries int
	items      map[string]*list.Element
	order      *list.List
	clone      func(V) V
	evictions  uint64
}

func newBoundedTTLCache[V any](maxEntries int, clone func(V) V) *boundedTTLCache[V] {
	if maxEntries <= 0 {
		maxEntries = defaultDNSCacheEntries
	}
	if clone == nil {
		clone = func(v V) V { return v }
	}
	return &boundedTTLCache[V]{
		maxEntries: maxEntries,
		items:      make(map[string]*list.Element, maxEntries),
		order:      list.New(),
		clone:      clone,
	}
}

func (c *boundedTTLCache[V]) Get(key string, now time.Time, allowStale bool) (V, cacheFreshness) {
	var zero V
	if c == nil {
		return zero, cacheMiss
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	elem, ok := c.items[key]
	if !ok {
		return zero, cacheMiss
	}
	entry := elem.Value.(*timedLRUEntry[V])
	if !entry.staleUntil.IsZero() && !now.Before(entry.staleUntil) {
		c.removeElementLocked(elem)
		return zero, cacheMiss
	}
	if entry.staleUntil.IsZero() && !now.Before(entry.expiresAt) {
		c.removeElementLocked(elem)
		return zero, cacheMiss
	}
	c.order.MoveToFront(elem)
	if now.Before(entry.expiresAt) {
		return c.clone(entry.value), cacheFresh
	}
	if allowStale {
		return c.clone(entry.value), cacheStale
	}
	return zero, cacheMiss
}

// Peek returns an entry without applying expiry rules. It exists for the
// resolver's diagnostic/admin methods; serving paths should use Get.
func (c *boundedTTLCache[V]) Peek(key string) (value V, expiresAt time.Time, staleUntil time.Time, ok bool) {
	if c == nil {
		return value, time.Time{}, time.Time{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	elem, ok := c.items[key]
	if !ok {
		return value, time.Time{}, time.Time{}, false
	}
	entry := elem.Value.(*timedLRUEntry[V])
	c.order.MoveToFront(elem)
	return c.clone(entry.value), entry.expiresAt, entry.staleUntil, true
}

func (c *boundedTTLCache[V]) Set(key string, value V, expiresAt, staleUntil time.Time) {
	if c == nil || key == "" {
		return
	}
	if staleUntil.IsZero() || staleUntil.Before(expiresAt) {
		staleUntil = expiresAt
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if elem, ok := c.items[key]; ok {
		entry := elem.Value.(*timedLRUEntry[V])
		entry.value = c.clone(value)
		entry.expiresAt = expiresAt
		entry.staleUntil = staleUntil
		c.order.MoveToFront(elem)
		return
	}
	entry := &timedLRUEntry[V]{
		key:        key,
		value:      c.clone(value),
		expiresAt:  expiresAt,
		staleUntil: staleUntil,
	}
	c.items[key] = c.order.PushFront(entry)
	for len(c.items) > c.maxEntries {
		c.removeElementLocked(c.order.Back())
	}
}

func (c *boundedTTLCache[V]) Delete(key string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if elem, ok := c.items[key]; ok {
		c.removeElementLocked(elem)
	}
}

func (c *boundedTTLCache[V]) Clear() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[string]*list.Element, c.maxEntries)
	c.order.Init()
}

func (c *boundedTTLCache[V]) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

func (c *boundedTTLCache[V]) Keys() []string {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	keys := make([]string, 0, len(c.items))
	for key := range c.items {
		keys = append(keys, key)
	}
	return keys
}

func (c *boundedTTLCache[V]) ExpiredCount(now time.Time) int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	count := 0
	for _, elem := range c.items {
		entry := elem.Value.(*timedLRUEntry[V])
		if !now.Before(entry.expiresAt) {
			count++
		}
	}
	return count
}

// EvictExpired removes entries that are no longer serviceable, including via
// their stale window, and returns the number removed.
func (c *boundedTTLCache[V]) EvictExpired(now time.Time) int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	removed := 0
	for key, elem := range c.items {
		entry := elem.Value.(*timedLRUEntry[V])
		deadline := entry.staleUntil
		if deadline.IsZero() {
			deadline = entry.expiresAt
		}
		if !now.Before(deadline) {
			delete(c.items, key)
			c.order.Remove(elem)
			c.evictions++
			removed++
		}
	}
	return removed
}

func (c *boundedTTLCache[V]) Evictions() uint64 {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.evictions
}

func (c *boundedTTLCache[V]) removeElementLocked(elem *list.Element) {
	if elem == nil {
		return
	}
	entry := elem.Value.(*timedLRUEntry[V])
	delete(c.items, entry.key)
	c.order.Remove(elem)
	c.evictions++
}
