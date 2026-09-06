package security

import (
	"net"
	"testing"
)

func TestDnsBlocklistEngine(t *testing.T) {
	engine := NewDnsBlocklistEngine()

	engine.AddExactRule("ads.track.com", CategoryAdvertising)
	engine.AddWildcardRule("badware.net", CategoryMalware)
	engine.AddExactRule("allowed.badware.net", CategoryMalware)
	engine.AddWhitelist("allowed.badware.net")

	cat, blocked := engine.IsDomainBlocked("ads.track.com")
	if !blocked || cat != CategoryAdvertising {
		t.Fatalf("expected ads.track.com blocked as advertising, got %v, %v", blocked, cat)
	}

	cat, blocked = engine.IsDomainBlocked("evil.badware.net")
	if !blocked || cat != CategoryMalware {
		t.Fatalf("expected evil.badware.net blocked as malware, got %v, %v", blocked, cat)
	}

	_, blocked = engine.IsDomainBlocked("allowed.badware.net")
	if blocked {
		t.Fatalf("expected allowed.badware.net to be whitelisted")
	}

	ip := net.ParseIP("1.2.3.4")
	engine.AddBlockedIP(ip)
	if !engine.IsIPBlocked(ip) {
		t.Fatalf("expected IP 1.2.3.4 to be blocked")
	}
}
