package dns

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDoHCacheGetAndHit(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write([]byte("MOCK_DNS_RESPONSE"))
	}))
	defer upstream.Close()

	cache := NewDoHCache(upstream.URL, 5*time.Minute)
	key := base64RawURLEncode([]byte("query"))
	req := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+key, nil)

	rec := httptest.NewRecorder()
	cache.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("first response=(%d,%q), want 200/MISS", rec.Code, rec.Header().Get("X-Cache"))
	}

	rec2 := httptest.NewRecorder()
	cache.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/dns-query?dns="+key, nil))
	if rec2.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("expected X-Cache: HIT, got %s", rec2.Header().Get("X-Cache"))
	}
	if calls.Load() != 1 {
		t.Fatalf("upstream calls=%d, want 1", calls.Load())
	}
}

func TestDoHCacheDoesNotCacheUpstreamHTTPFailure(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			http.Error(w, "temporary", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("RECOVERED_DNS_RESPONSE"))
	}))
	defer upstream.Close()

	cache := NewDoHCache(upstream.URL, time.Minute)
	key := base64RawURLEncode([]byte("query"))
	first := httptest.NewRecorder()
	cache.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/dns-query?dns="+key, nil))
	if first.Code != http.StatusBadGateway {
		t.Fatalf("first status=%d, want 502", first.Code)
	}
	if cache.Stats().Entries != 0 {
		t.Fatalf("upstream HTTP failure entered cache: %+v", cache.Stats())
	}

	second := httptest.NewRecorder()
	cache.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/dns-query?dns="+key, nil))
	if second.Code != http.StatusOK || second.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("second response=(%d,%q), want 200/MISS", second.Code, second.Header().Get("X-Cache"))
	}
	third := httptest.NewRecorder()
	cache.ServeHTTP(third, httptest.NewRequest(http.MethodGet, "/dns-query?dns="+key, nil))
	if third.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("third cache state=%q, want HIT", third.Header().Get("X-Cache"))
	}
	if calls.Load() != 2 {
		t.Fatalf("upstream calls=%d, want 2", calls.Load())
	}
}

func TestDoHCacheServesStaleOnlyAfterRefreshFailure(t *testing.T) {
	var fail atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("STABLE_DNS_RESPONSE"))
	}))
	defer upstream.Close()

	cache := NewDoHCacheWithPolicy(upstream.URL, DoHCachePolicy{
		TTL:        time.Second,
		StaleTTL:   5 * time.Second,
		MaxEntries: 8,
	})
	now := time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC)
	cache.now = func() time.Time { return now }
	key := base64RawURLEncode([]byte("query"))

	fresh := httptest.NewRecorder()
	cache.ServeHTTP(fresh, httptest.NewRequest(http.MethodGet, "/dns-query?dns="+key, nil))
	if fresh.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("prime state=%q, want MISS", fresh.Header().Get("X-Cache"))
	}

	now = now.Add(2 * time.Second)
	fail.Store(true)
	stale := httptest.NewRecorder()
	cache.ServeHTTP(stale, httptest.NewRequest(http.MethodGet, "/dns-query?dns="+key, nil))
	if stale.Code != http.StatusOK || stale.Header().Get("X-Cache") != "STALE" {
		t.Fatalf("stale response=(%d,%q), want 200/STALE", stale.Code, stale.Header().Get("X-Cache"))
	}
	if stale.Body.String() != "STABLE_DNS_RESPONSE" {
		t.Fatalf("stale body=%q", stale.Body.String())
	}
	if stale.Header().Get("Warning") == "" {
		t.Fatal("stale response is not explicitly marked with Warning")
	}

	now = now.Add(5 * time.Second)
	dead := httptest.NewRecorder()
	cache.ServeHTTP(dead, httptest.NewRequest(http.MethodGet, "/dns-query?dns="+key, nil))
	if dead.Code != http.StatusBadGateway {
		t.Fatalf("expired stale status=%d, want 502", dead.Code)
	}
	if cache.Stats().StaleHits != 1 {
		t.Fatalf("stats=%+v, want one stale hit", cache.Stats())
	}
}

func TestDoHCacheCapacityIsBounded(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte("BOUNDED_DNS_RESPONSE"))
	}))
	defer upstream.Close()

	cache := NewDoHCacheWithPolicy(upstream.URL, DoHCachePolicy{TTL: time.Minute, StaleTTL: time.Second, MaxEntries: 2})
	for _, q := range []string{"one", "two", "three"} {
		key := base64RawURLEncode([]byte(q))
		rec := httptest.NewRecorder()
		cache.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/dns-query?dns="+key, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status=%d", q, rec.Code)
		}
	}
	stats := cache.Stats()
	if stats.Entries != 2 || stats.Evictions == 0 {
		t.Fatalf("stats=%+v, want 2 entries and an eviction", stats)
	}
}

func TestDoHCacheCoalescesConcurrentMisses(t *testing.T) {
	var calls atomic.Int32
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		_, _ = w.Write([]byte("COALESCED_DNS_RESPONSE"))
	}))
	defer upstream.Close()

	cache := NewDoHCache(upstream.URL, time.Minute)
	key := base64RawURLEncode([]byte("same-query"))
	const workers = 12
	var wg sync.WaitGroup
	wg.Add(workers)
	codes := make(chan int, workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			cache.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/dns-query?dns="+key, nil))
			codes <- rec.Code
		}()
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("upstream was not entered")
	}
	close(release)
	wg.Wait()
	close(codes)
	for code := range codes {
		if code != http.StatusOK {
			t.Fatalf("worker status=%d", code)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("upstream calls=%d, want one coalesced fetch", calls.Load())
	}
	if cache.Stats().Coalesced == 0 {
		t.Fatalf("coalescing was not observed: %+v", cache.Stats())
	}
}

func TestDoHCacheRejectsInvalidGETBeforeUpstream(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte("unexpected"))
	}))
	defer upstream.Close()
	cache := NewDoHCache(upstream.URL, time.Minute)
	rec := httptest.NewRecorder()
	cache.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/dns-query?dns=***", nil))
	if rec.Code != http.StatusBadRequest || calls.Load() != 0 {
		t.Fatalf("response=%d calls=%d, want 400/0", rec.Code, calls.Load())
	}
}

func TestDoHCachePOSTAndGETShareCanonicalKey(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte("CANONICAL_DNS_RESPONSE"))
	}))
	defer upstream.Close()
	cache := NewDoHCache(upstream.URL, time.Minute)
	wire := []byte("wire-query")
	post := httptest.NewRecorder()
	cache.ServeHTTP(post, httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(wire)))
	if post.Code != http.StatusOK || post.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("post=(%d,%q)", post.Code, post.Header().Get("X-Cache"))
	}
	get := httptest.NewRecorder()
	cache.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/dns-query?dns="+base64RawURLEncode(wire), nil))
	if get.Header().Get("X-Cache") != "HIT" || calls.Load() != 1 {
		t.Fatalf("get cache=%q calls=%d, want HIT/1", get.Header().Get("X-Cache"), calls.Load())
	}
}
