package dns

import (
	"net"
	"testing"
	"time"
)

func TestDnsCacheKey(t *testing.T) {
	key := CacheKey("Example.Com", 1, false)
	if key != "0:1:example.com" {
		t.Errorf("expected 0:1:example.com, got %s", key)
	}

	keyDoh := CacheKey("example.com", 1, true)
	if keyDoh != "1:1:example.com" {
		t.Errorf("expected 1:1:example.com, got %s", keyDoh)
	}

	ip := net.ParseIP("192.168.1.50")
	keyEcs := CacheKeyWithECS("example.com", 15, true, ip, 24)
	if keyEcs != "1:15:example.com:192.168.1.50/24" {
		t.Errorf("expected 1:15:example.com:192.168.1.50/24, got %s", keyEcs)
	}
}

func TestUpstreamDomainRouting(t *testing.T) {
	domains := map[string][]string{
		"example.com": {"1.1.1.1"},
		"google.com":  {"8.8.4.4"},
	}
	config := NewUpstreamConfig(
		[]string{"8.8.8.8"},
		domains,
		[]string{"exclude.example.com"},
	)

	// Exact match
	ups := config.GetUpstreamsForDomain("example.com")
	if len(ups) != 1 || ups[0] != "1.1.1.1" {
		t.Errorf("expected [1.1.1.1], got %v", ups)
	}

	// Subdomain match
	upsSub := config.GetUpstreamsForDomain("sub.example.com")
	if len(upsSub) != 1 || upsSub[0] != "1.1.1.1" {
		t.Errorf("expected [1.1.1.1], got %v", upsSub)
	}

	// Excluded domain
	upsExcl := config.GetUpstreamsForDomain("exclude.example.com")
	if len(upsExcl) != 1 || upsExcl[0] != "8.8.8.8" {
		t.Errorf("expected default [8.8.8.8] due to exclusion, got %v", upsExcl)
	}

	// Fallback fallback
	upsFall := config.GetUpstreamsForDomain("other.com")
	if len(upsFall) != 1 || upsFall[0] != "8.8.8.8" {
		t.Errorf("expected [8.8.8.8], got %v", upsFall)
	}
}

func TestBogusNxDomain(t *testing.T) {
	bogus := NewBogusNxDomain()
	bogus.BogusIPs = append(bogus.BogusIPs, net.ParseIP("127.0.0.9"))
	_, subnet, _ := net.ParseCIDR("10.0.0.0/24")
	bogus.BogusSubnets = append(bogus.BogusSubnets, subnet)

	if !bogus.IsBogus([]net.IP{net.ParseIP("127.0.0.9")}) {
		t.Error("expected 127.0.0.9 to be detected as bogus")
	}

	if !bogus.IsBogus([]net.IP{net.ParseIP("10.0.0.15")}) {
		t.Error("expected 10.0.0.15 to be detected as bogus via subnet")
	}

	if bogus.IsBogus([]net.IP{net.ParseIP("8.8.8.8")}) {
		t.Error("expected 8.8.8.8 to not be detected as bogus")
	}
}

func TestDnsCacheLRUAndExpiration(t *testing.T) {
	cache := NewDnsCache(2, 10*time.Millisecond, 100*time.Second)

	entry1 := NewCacheEntry([]byte{1, 2}, 50*time.Millisecond, "8.8.8.8", "a.com", 1, 10*time.Millisecond, 100*time.Second)
	entry2 := NewCacheEntry([]byte{3, 4}, 50*time.Millisecond, "8.8.8.8", "b.com", 1, 10*time.Millisecond, 100*time.Second)
	entry3 := NewCacheEntry([]byte{5, 6}, 50*time.Millisecond, "8.8.8.8", "c.com", 1, 10*time.Millisecond, 100*time.Second)

	cache.Insert("a.com", entry1)
	cache.Insert("b.com", entry2)

	if cache.Len() != 2 {
		t.Errorf("expected len 2, got %d", cache.Len())
	}

	// Insert third, should evict one since max size is 2
	cache.Insert("c.com", entry3)
	if cache.Len() != 2 {
		t.Errorf("expected len 2, got %d", cache.Len())
	}

	// Make sure entry1 or entry2 was evicted (since they have the same expiry, one of them will be evicted)
	_, hasA := cache.Get("a.com")
	_, hasB := cache.Get("b.com")
	_, hasC := cache.Get("c.com")

	if !hasC {
		t.Error("expected to find c.com")
	}
	if hasA && hasB {
		t.Error("expected either a.com or b.com to be evicted")
	}

	// Test expiration
	time.Sleep(60 * time.Millisecond)
	_, hasCExpired := cache.Get("c.com")
	if hasCExpired {
		t.Error("expected c.com to be expired")
	}
}

func TestRateLimiterSubnet(t *testing.T) {
	limiter := NewRateLimiter(5, 24, 48)
	ip1 := net.ParseIP("192.168.1.100")
	ip2 := net.ParseIP("192.168.1.200") // in same /24 subnet

	// First 5 requests should pass
	for i := 0; i < 5; i++ {
		if limiter.IsLimited(ip1) {
			t.Errorf("request %d should not be limited", i)
		}
	}

	// 6th should be limited
	if !limiter.IsLimited(ip1) {
		t.Error("expected 6th request to be limited")
	}

	// Request from ip2 should also be limited as it is in the same subnet
	if !limiter.IsLimited(ip2) {
		t.Error("expected request from same subnet to be limited")
	}
}
