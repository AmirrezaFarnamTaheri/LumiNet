package dns

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFailoverResolverEmptyProvidersFailClosed(t *testing.T) {
	resolver := NewFailoverDOHResolver(time.Minute)
	resolver.ClearProviders()
	if got := resolver.SelectProvider(); got != (DoHProvider{}) {
		t.Fatalf("SelectProvider after ClearProviders = %+v, want zero provider", got)
	}
	if _, err := resolver.lookupRace(context.Background(), "example.com"); err == nil || !strings.Contains(err.Error(), "no providers configured") {
		t.Fatalf("lookupRace error = %v, want no providers configured", err)
	}
}

func TestFailoverResolverCacheIsCapacityBounded(t *testing.T) {
	resolver := NewFailoverDOHResolver(time.Minute)
	for i := 0; i < defaultDNSCacheEntries+128; i++ {
		resolver.SetCachedIPs(fmt.Sprintf("host-%d.example", i), []string{"192.0.2.1"})
	}
	if got := resolver.GetCacheSize(); got != defaultDNSCacheEntries {
		t.Fatalf("cache size = %d, want %d", got, defaultDNSCacheEntries)
	}
}

func TestFailoverResolverClientReconfigurationUsesReplacementSnapshots(t *testing.T) {
	resolver := NewFailoverDOHResolver(time.Minute)
	resolver.cacheMu.RLock()
	before := resolver.client
	resolver.cacheMu.RUnlock()

	resolver.SetHTTPClientTimeout(17 * time.Second)
	resolver.cacheMu.RLock()
	afterTimeout := resolver.client
	resolver.cacheMu.RUnlock()
	if before == afterTimeout {
		t.Fatal("SetHTTPClientTimeout mutated the in-use http.Client instead of replacing its snapshot")
	}
	if got := resolver.GetHTTPClientTimeout(); got != 17*time.Second {
		t.Fatalf("timeout = %v, want 17s", got)
	}

	transport := &http.Transport{}
	resolver.SetClientTransport(transport)
	resolver.cacheMu.RLock()
	afterTransport := resolver.client
	resolver.cacheMu.RUnlock()
	if afterTransport == afterTimeout {
		t.Fatal("SetClientTransport mutated the in-use http.Client instead of replacing its snapshot")
	}
	if got := resolver.GetClientTransport(); got != transport {
		t.Fatalf("transport = %p, want %p", got, transport)
	}
}

func TestFailoverResolverProviderReconfigurationIsConcurrencySafe(t *testing.T) {
	resolver := NewFailoverDOHResolver(time.Minute)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 250; j++ {
				_ = resolver.SelectProvider()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 100; j++ {
			resolver.ClearProviders()
			resolver.AddProvider(DoHProvider{Name: "fallback", URL: "https://example.test/dns-query", Weight: 1})
		}
	}()
	wg.Wait()
}
