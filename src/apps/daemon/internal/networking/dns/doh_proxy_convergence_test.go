package dns

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDoHProxyUsesBoundedSharedCache(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte("PROXY_DNS_RESPONSE"))
	}))
	defer upstream.Close()

	proxy := NewDoHProxyWithProviders([]DoHProvider{{Name: "local", URL: upstream.URL, Weight: 1}})
	proxy.cache = newBoundedTTLCache[[]byte](2, func(v []byte) []byte { return append([]byte(nil), v...) })
	for _, query := range []string{"one", "two", "three"} {
		if _, err := proxy.QueryGET(query); err != nil {
			t.Fatalf("QueryGET(%q): %v", query, err)
		}
	}
	if got := proxy.cache.Len(); got != 2 {
		t.Fatalf("cache len=%d, want 2", got)
	}
	if proxy.cache.Evictions() == 0 {
		t.Fatal("capacity eviction did not occur")
	}
}

func TestDoHProxyRejectsEmptyProviderSet(t *testing.T) {
	proxy := NewDoHProxyWithProviders(nil)
	if _, err := proxy.QueryGET("query"); err == nil {
		t.Fatal("QueryGET() error=nil, want no-provider failure")
	}
	if _, err := proxy.QueryPOST([]byte("query")); err == nil {
		t.Fatal("QueryPOST() error=nil, want no-provider failure")
	}
}

func TestDoHProxyProviderSelectionIsConcurrencySafe(t *testing.T) {
	proxy := NewDoHProxyWithProviders([]DoHProvider{
		{Name: "a", URL: "https://a.invalid", Weight: 1},
		{Name: "b", URL: "https://b.invalid", Weight: 1},
	})
	var wg sync.WaitGroup
	wg.Add(32)
	for i := 0; i < 32; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if got := proxy.SelectProvider(); got.Name == "" {
					t.Errorf("SelectProvider returned empty provider")
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestDoHProxyPurgeExpiredUsesCacheDeadline(t *testing.T) {
	proxy := NewDoHProxyWithProviders([]DoHProvider{{Name: "a", URL: "https://a.invalid", Weight: 1}})
	proxy.cache = newBoundedTTLCache[[]byte](2, nil)
	past := time.Now().Add(-time.Second)
	proxy.cache.Set("expired", []byte("x"), past, past)
	if got := proxy.PurgeExpiredCache(); got != 1 {
		t.Fatalf("purged=%d, want 1", got)
	}
}
