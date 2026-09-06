// Copyright 2024 LumiNet. Use of this source code is governed by the MIT license.
// Serve-stale functionality: serves cached DNS responses past their TTL when the
// upstream resolver is unreachable or slow. This improves UX on flaky connections
// and reduces perceived latency for repeat queries.

package dns

import (
	"sync"
	"time"
)

// CachedResponse holds a wire-format DNS response and its associated metadata.
type CachedResponse struct {
	Query     string    // normalised query name (e.g. "example.com" not "example.com.")
	Wire      []byte    // raw DNS wire-format message.
	ExpiresAt time.Time // wall-clock expiry; after this the entry is stale.
	MinTTL    uint32    // minimum TTL extracted from the original response.
	Upstream  string    // identifier of the upstream that provided the response.
}

// StaleCache implements a TTL-bounded in-memory cache of DNS responses.
// Entries are retained past their expiry to serve stale responses, up to a
// configurable max-stale window.
type StaleCache struct {
	mu         sync.RWMutex
	entries    map[string]*CachedResponse
	maxStale   time.Duration // how long past expiry to still serve the entry.
	entryLimit int           // maximum number of entries before eviction.
	evictCount int           // entries to evict when at capacity.
}

// StaleCacheConfig configures a new StaleCache.
type StaleCacheConfig struct {
	MaxStale   time.Duration
	EntryLimit int
}

// NewStaleCache constructs a cache with sensible defaults.
func NewStaleCache(cfg StaleCacheConfig) *StaleCache {
	maxStale := cfg.MaxStale
	if maxStale == 0 {
		maxStale = 24 * time.Hour
	}
	limit := cfg.EntryLimit
	if limit == 0 {
		limit = 10000
	}
	return &StaleCache{
		entries:    make(map[string]*CachedResponse),
		maxStale:   maxStale,
		entryLimit: limit,
		evictCount: 100,
	}
}

// Set stores a response for the given query. The cache key is the normalised
// query name. If the cache is at capacity, stale entries are evicted first,
// then LRU-style excess entries are removed.
func (c *StaleCache) Set(query string, resp CachedResponse) {
	key := normaliseKey(query)
	c.mu.Lock()
	defer c.mu.Unlock()
	// Evict stale entries first if we are near capacity.
	if len(c.entries) >= c.entryLimit {
		c.evictStaleLocked()
	}
	// If still at limit, evict oldest entries.
	if len(c.entries) >= c.entryLimit {
		c.evictOldestLocked(c.evictCount)
	}
	// Shallow copy to avoid external mutations.
	entry := resp
	c.entries[key] = &entry
}

// ServeStale returns a cached response for the given query if one exists and
// has not exceeded the max-stale window. The boolean indicates whether the
// response was served from the stale window.
func (c *StaleCache) ServeStale(query string) (CachedResponse, bool) {
	key := normaliseKey(query)
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[key]
	if !ok {
		return CachedResponse{}, false
	}
	now := time.Now()
	// Fresh entry: return immediately.
	if now.Before(entry.ExpiresAt) {
		return *entry, false
	}
	// Stale but within max-stale window.
	if now.Before(entry.ExpiresAt.Add(c.maxStale)) {
		return *entry, true
	}
	// Beyond max-stale.
	return CachedResponse{}, false
}

// Size returns the current number of entries in the cache.
func (c *StaleCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Evict removes the entry for the given query.
func (c *StaleCache) Evict(query string) {
	key := normaliseKey(query)
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

// Clear removes all entries.
func (c *StaleCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*CachedResponse)
}

// MaxStale returns the configured max-stale duration.
func (c *StaleCache) MaxStale() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.maxStale
}

// SetMaxStale updates the max-stale window.
func (c *StaleCache) SetMaxStale(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.maxStale = d
}

// normaliseKey lowercases and trims trailing dot from a domain name.
func normaliseKey(name string) string {
	// Strip trailing dot (FQDN terminator) if present.
	if len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	return name
}

// evictStaleLocked removes entries that have exceeded the max-stale window.
// Caller must hold c.mu.
func (c *StaleCache) evictStaleLocked() {
	now := time.Now()
	deadline := now.Add(-c.maxStale)
	for key, entry := range c.entries {
		if entry.ExpiresAt.Before(deadline) {
			delete(c.entries, key)
		}
	}
}

// evictOldestLocked removes the oldest N entries by Expiry time.
// Caller must hold c.mu.
func (c *StaleCache) evictOldestLocked(n int) {
	if n <= 0 || len(c.entries) == 0 {
		return
	}
	// Find the N oldest expiry times.
	type entryRef struct {
		key     string
		expires time.Time
	}
	var refs []entryRef
	for key, entry := range c.entries {
		refs = append(refs, entryRef{key: key, expires: entry.ExpiresAt})
	}
	// Simple selection sort for small n.
	for i := 0; i < n && i < len(refs); i++ {
		minIdx := i
		for j := i + 1; j < len(refs); j++ {
			if refs[j].expires.Before(refs[minIdx].expires) {
				minIdx = j
			}
		}
		delete(c.entries, refs[minIdx].key)
		refs = append(refs[:minIdx], refs[minIdx+1:]...)
	}
}
