package netpolicy

import (
	"net/netip"
	"testing"
)

func TestIsPublicAddress(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"8.8.8.8":         true,
		"1.1.1.1":         true,
		"2606:4700::1111": true,
		"127.0.0.1":       false,
		"10.0.0.1":        false,
		"172.16.0.1":      false,
		"192.168.0.1":     false,
		"169.254.1.1":     false,
		"100.64.0.1":      false,
		"198.18.0.1":      false,
		"192.0.2.7":       false,
		"198.51.100.8":    false,
		"203.0.113.9":     false,
		"2001:db8::1":     false,
		"::1":             false,
		"fc00::1":         false,
		"fe80::1":         false,
	}
	for raw, want := range cases {
		raw, want := raw, want
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			if got := IsPublicAddress(netip.MustParseAddr(raw)); got != want {
				t.Fatalf("IsPublicAddress(%s)=%v, want %v", raw, got, want)
			}
		})
	}
}

func TestIsDocumentationAddress(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"192.0.2.1", "198.51.100.1", "203.0.113.1", "2001:db8::1"} {
		if !IsDocumentationAddress(netip.MustParseAddr(raw)) {
			t.Fatalf("%s should be documentation address", raw)
		}
	}
	for _, raw := range []string{"1.1.1.1", "2001:4860:4860::8888"} {
		if IsDocumentationAddress(netip.MustParseAddr(raw)) {
			t.Fatalf("%s should not be documentation address", raw)
		}
	}
}
