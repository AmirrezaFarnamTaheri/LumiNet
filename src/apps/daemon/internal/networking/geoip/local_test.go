package geoip

import "testing"

func TestIsLocalOrLanIP(t *testing.T) {
	tests := map[string]bool{
		"127.0.0.1":   true,
		"10.1.2.3":    true,
		"172.16.0.1":  true,
		"192.168.1.1": true,
		"169.254.1.1": true,
		"100.64.0.1":  true,
		"fe80::1":     true,
		"fc00::1":     true,
		"8.8.8.8":     false,
		"1.1.1.1":     false,
	}
	for ip, want := range tests {
		if got := IsLocalOrLanIP(ip); got != want {
			t.Fatalf("IsLocalOrLanIP(%q)=%v, want %v", ip, got, want)
		}
	}
}
