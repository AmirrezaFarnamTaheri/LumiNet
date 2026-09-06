package routing

import (
	"testing"
)

func TestEnhancedGeoIpLookup(t *testing.T) {
	geo := NewEnhancedGeoIpLookup()
	geo.AddCidr([4]byte{1, 0, 1, 0}, 24, "CN")
	geo.AddCidr([4]byte{8, 8, 8, 0}, 24, "US")
	geo.AddCidr([4]byte{8, 8, 0, 0}, 16, "US-BROAD")

	cc, ok := geo.Lookup([4]byte{1, 0, 1, 55})
	if !ok || cc != "CN" {
		t.Fatalf("expected CN, got %s, %v", cc, ok)
	}

	// Longest prefix match: /24 beats /16
	cc, ok = geo.Lookup([4]byte{8, 8, 8, 8})
	if !ok || cc != "US" {
		t.Fatalf("expected US, got %s, %v", cc, ok)
	}

	cc, ok = geo.Lookup([4]byte{8, 8, 10, 1})
	if !ok || cc != "US-BROAD" {
		t.Fatalf("expected US-BROAD, got %s, %v", cc, ok)
	}

	_, ok = geo.Lookup([4]byte{9, 9, 9, 9})
	if ok {
		t.Fatal("expected no match for 9.9.9.9")
	}

	if !IsPrivateIPv4([4]byte{192, 168, 1, 1}) {
		t.Fatal("expected 192.168.1.1 to be private")
	}
	if !IsPrivateIPv4([4]byte{10, 0, 0, 1}) {
		t.Fatal("expected 10.0.0.1 to be private")
	}
	if IsPrivateIPv4([4]byte{8, 8, 8, 8}) {
		t.Fatal("expected 8.8.8.8 to NOT be private")
	}
}
