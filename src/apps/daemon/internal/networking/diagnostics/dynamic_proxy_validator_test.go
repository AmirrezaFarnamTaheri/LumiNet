package diagnostics

import (
	"testing"
	"time"
)

func TestDynamicProxyValidator(t *testing.T) {
	v := NewDynamicProxyValidator(3 * time.Second)

	probe := v.CraftSocks5Probe()
	if len(probe) != 3 || probe[0] != 0x05 {
		t.Fatalf("unexpected probe bytes: %v", probe)
	}

	if !v.VerifySocks5Response([]byte{0x05, 0x00}) {
		t.Fatalf("expected valid socks5 response")
	}
	if v.VerifySocks5Response([]byte{0x05, 0xFF}) {
		t.Fatalf("expected rejected socks5 response")
	}

	headers := map[string]string{
		"X-Forwarded-For": "203.0.113.195",
	}
	if v.DetermineAnonymity(headers, "203.0.113.195") != AnonymityTransparent {
		t.Fatalf("expected transparent anonymity")
	}

	delete(headers, "X-Forwarded-For")
	headers["Via"] = "1.1 proxy"
	if v.DetermineAnonymity(headers, "203.0.113.195") != AnonymityAnonymous {
		t.Fatalf("expected anonymous anonymity")
	}

	headers = map[string]string{}
	if v.DetermineAnonymity(headers, "203.0.113.195") != AnonymityElite {
		t.Fatalf("expected elite anonymity")
	}

	v.RecordProbe("1.2.3.4", 8080, ProxyProtoHTTP, true, 100*time.Millisecond, AnonymityElite)
	v.RecordProbe("5.6.7.8", 1080, ProxyProtoSocks5, true, 400*time.Millisecond, AnonymityAnonymous)
	v.RecordProbe("9.9.9.9", 8080, ProxyProtoHTTP, false, 2*time.Second, AnonymityTransparent)

	healthy := v.GetHealthyProxies(250 * time.Millisecond)
	if len(healthy) != 1 || healthy[0].Host != "1.2.3.4" {
		t.Fatalf("expected only 1 fast healthy proxy, got %v", healthy)
	}
}
