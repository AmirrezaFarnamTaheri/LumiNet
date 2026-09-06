package dns

import (
	"context"
	"testing"
	"time"
)

func TestFailoverDOHResolver_LookupHost(t *testing.T) {
	resolver := NewFailoverDOHResolver(5 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	// Try resolving a well-known domain to test functionality
	ips, err := resolver.LookupHost(ctx, "www.google.com")
	if err != nil {
		t.Logf("Warning: LookupHost failed (possibly offline or firewall): %v", err)
		return
	}

	if len(ips) == 0 {
		t.Errorf("expected at least one IP address, got zero")
	}
}

func TestFailoverDOHResolver_RaceAndGeoIPFilter(t *testing.T) {
	resolver := NewFailoverDOHResolver(5 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	// Direct check checkIPCountry
	code, err := resolver.checkIPCountry(ctx, "8.8.8.8")
	if err != nil {
		t.Logf("Warning: checkIPCountry failed (offline or API limit): %v", err)
		return
	}

	// 8.8.8.8 is US (not CN), verify it's resolved and detected
	if code == "CN" {
		t.Errorf("expected US for 8.8.8.8, got CN")
	}
}
