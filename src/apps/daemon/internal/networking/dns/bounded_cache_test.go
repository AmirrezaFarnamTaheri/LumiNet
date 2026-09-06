package dns

import (
	"bytes"
	"testing"
	"time"
)

func TestBoundedTTLCacheEvictsLRUAndClones(t *testing.T) {
	clone := func(v []byte) []byte { return bytes.Clone(v) }
	cache := newBoundedTTLCache[[]byte](2, clone)
	now := time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC)
	one := []byte("one")
	cache.Set("one", one, now.Add(time.Minute), time.Time{})
	one[0] = 'X'
	cache.Set("two", []byte("two"), now.Add(time.Minute), time.Time{})
	if got, state := cache.Get("one", now, false); state != cacheFresh || string(got) != "one" {
		t.Fatalf("one=(%q,%v), want cloned fresh value", got, state)
	}
	cache.Set("three", []byte("three"), now.Add(time.Minute), time.Time{})
	if _, _, _, ok := cache.Peek("two"); ok {
		t.Fatal("least-recently-used key two was not evicted")
	}
	if cache.Len() != 2 {
		t.Fatalf("len=%d, want 2", cache.Len())
	}
}

func TestBoundedTTLCacheStaleWindow(t *testing.T) {
	cache := newBoundedTTLCache[string](2, nil)
	now := time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC)
	cache.Set("k", "value", now.Add(time.Second), now.Add(3*time.Second))
	if _, state := cache.Get("k", now.Add(2*time.Second), false); state != cacheMiss {
		t.Fatalf("fresh-only state=%v, want miss while stale", state)
	}
	if got, state := cache.Get("k", now.Add(2*time.Second), true); state != cacheStale || got != "value" {
		t.Fatalf("stale=(%q,%v), want value/stale", got, state)
	}
	if _, state := cache.Get("k", now.Add(3*time.Second), true); state != cacheMiss {
		t.Fatalf("expired stale state=%v, want miss", state)
	}
}

func TestBoundedTTLCacheEvictExpiredUsesStaleDeadline(t *testing.T) {
	cache := newBoundedTTLCache[string](2, nil)
	now := time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC)
	cache.Set("stale-serviceable", "a", now.Add(time.Second), now.Add(10*time.Second))
	cache.Set("dead", "b", now.Add(time.Second), now.Add(2*time.Second))
	if removed := cache.EvictExpired(now.Add(5 * time.Second)); removed != 1 {
		t.Fatalf("removed=%d, want 1", removed)
	}
	if _, _, _, ok := cache.Peek("stale-serviceable"); !ok {
		t.Fatal("serviceable stale entry was evicted early")
	}
}
