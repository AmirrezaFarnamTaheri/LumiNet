package dns

import (
	"testing"
	"time"
)

func TestStaleCache_SetAndServe(t *testing.T) {
	t.Parallel()
	c := NewStaleCache(StaleCacheConfig{MaxStale: 1 * time.Hour, EntryLimit: 100})
	resp := CachedResponse{
		Query:     "example.com",
		Wire:      []byte("response-wire"),
		ExpiresAt: time.Now().Add(300 * time.Second),
		MinTTL:    300,
	}
	c.Set("example.com", resp)
	// API contract: the bool is true only when the entry was served from
	// the STALE window. A within-TTL entry is served fresh (bool=false).
	got, staleServed := c.ServeStale("example.com")
	if staleServed {
		t.Error("expected staleServed=false for entry within TTL window")
	}
	if string(got.Wire) != "response-wire" {
		t.Errorf("unexpected wire data: %q", string(got.Wire))
	}
}

func TestStaleCache_ServeStaleAfterExpiry(t *testing.T) {
	t.Parallel()
	c := NewStaleCache(StaleCacheConfig{MaxStale: 1 * time.Hour, EntryLimit: 100})
	c.mu.Lock()
	c.entries["example.com"] = &CachedResponse{
		Query:     "example.com",
		Wire:      []byte("stale-wire"),
		ExpiresAt: time.Now().Add(-5 * time.Minute), // expired 5 minutes ago
		MinTTL:    300,
	}
	c.mu.Unlock()

	got, isStale := c.ServeStale("example.com")
	if !isStale {
		t.Error("expected isStale=true for expired-but-fresh response")
	}
	if string(got.Wire) != "stale-wire" {
		t.Errorf("expected stale-wire, got %q", string(got.Wire))
	}
}

func TestStaleCache_RejectsBeyondMaxStale(t *testing.T) {
	t.Parallel()
	c := NewStaleCache(StaleCacheConfig{MaxStale: 1 * time.Hour, EntryLimit: 100})
	c.mu.Lock()
	c.entries["old.example.com"] = &CachedResponse{
		Query:     "old.example.com",
		Wire:      []byte("old-wire"),
		ExpiresAt: time.Now().Add(-2 * time.Hour), // expired 2 hours ago, beyond max-stale of 1h
		MinTTL:    300,
	}
	c.mu.Unlock()
	_, found := c.ServeStale("old.example.com")
	if found {
		t.Error("expected no result beyond max-stale window")
	}
}

func TestStaleCache_NormaliseKey(t *testing.T) {
	t.Parallel()
	c := NewStaleCache(StaleCacheConfig{MaxStale: 1 * time.Hour, EntryLimit: 100})
	c.Set("Example.COM.", CachedResponse{Wire: []byte("data")})
	_, stale := c.ServeStale("example.com")
	if stale {
		t.Error("key normalisation failed: expected fresh lookup")
	}
	// Try with trailing dot.
	_, stale = c.ServeStale("example.com.")
	if stale {
		t.Error("key normalisation failed for FQDN form")
	}
}

func TestStaleCache_Evict(t *testing.T) {
	t.Parallel()
	c := NewStaleCache(StaleCacheConfig{MaxStale: 1 * time.Hour, EntryLimit: 100})
	c.Set("example.com", CachedResponse{Wire: []byte("data")})
	c.Evict("example.com")
	if size := c.Size(); size != 0 {
		t.Errorf("expected empty cache after Evict, got size %d", size)
	}
}

func TestStaleCache_Clear(t *testing.T) {
	t.Parallel()
	c := NewStaleCache(StaleCacheConfig{MaxStale: 1 * time.Hour, EntryLimit: 100})
	for i := 0; i < 10; i++ {
		c.Set("example.com", CachedResponse{Wire: []byte("data")})
	}
	c.Clear()
	if size := c.Size(); size != 0 {
		t.Errorf("expected 0 after Clear, got %d", size)
	}
}

func TestStaleCache_EntryLimitEviction(t *testing.T) {
	t.Parallel()
	c := NewStaleCache(StaleCacheConfig{MaxStale: 1 * time.Hour, EntryLimit: 5})
	for i := 0; i < 10; i++ {
		c.Set("host.example.com", CachedResponse{Wire: []byte("data"), ExpiresAt: time.Now().Add(time.Hour)})
	}
	if size := c.Size(); size > 5 {
		t.Errorf("expected at most 5 entries, got %d", size)
	}
}

func TestStaleCache_MaxStaleGetterSetter(t *testing.T) {
	t.Parallel()
	c := NewStaleCache(StaleCacheConfig{MaxStale: 30 * time.Minute})
	if d := c.MaxStale(); d != 30*time.Minute {
		t.Errorf("expected 30m max-stale, got %v", d)
	}
	c.SetMaxStale(2 * time.Hour)
	if d := c.MaxStale(); d != 2*time.Hour {
		t.Errorf("expected 2h max-stale after setter, got %v", d)
	}
}

func TestStaleCache_MissingEntry(t *testing.T) {
	t.Parallel()
	c := NewStaleCache(StaleCacheConfig{MaxStale: 1 * time.Hour})
	_, found := c.ServeStale("notfound.com")
	if found {
		t.Error("expected false for missing entry")
	}
}
