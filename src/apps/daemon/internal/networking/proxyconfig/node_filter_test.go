package proxyconfig

import (
	"testing"
)

func TestDummyProxyDetection(t *testing.T) {
	if !IsDummyProxy("vless://00000000-0000-0000-0000-000000000000@example.com:443#test") {
		t.Errorf("expected dummy detection for nil UUID")
	}
	if !IsDummyProxy("trojan://pass@example.com:443#app not supported") {
		t.Errorf("expected dummy detection for app not supported")
	}
	if !IsDummyProxy("proxies: []") {
		t.Errorf("expected dummy detection for empty proxies array")
	}
	if IsDummyProxy("vless://b0341a94-4b5b-4c28-98e3-0ecdfb008d51@example.com:443?security=tls#node1") {
		t.Errorf("legitimate node falsely flagged as dummy")
	}
}

func TestInvalidPortValidation(t *testing.T) {
	if !IsInvalidPort(0) {
		t.Errorf("port 0 should be invalid")
	}
	if !IsInvalidPort(65536) {
		t.Errorf("port 65536 should be invalid")
	}
	if IsInvalidPort(443) {
		t.Errorf("port 443 should be valid")
	}
}

func TestUnroutableServer(t *testing.T) {
	if !IsUnroutableServer("127.0.0.1") {
		t.Errorf("127.0.0.1 should be unroutable")
	}
	if !IsUnroutableServer("0.0.0.0") {
		t.Errorf("0.0.0.0 should be unroutable")
	}
	if !IsUnroutableServer("127.0.0.53") {
		t.Errorf("127.0.0.53 should be unroutable")
	}
	if !IsUnroutableServer("169.254.1.1") {
		t.Errorf("169.254.1.1 should be unroutable")
	}
	if !IsUnroutableServer("240.0.0.1") {
		t.Errorf("240.0.0.1 should be unroutable")
	}
	if IsUnroutableServer("1.1.1.1") {
		t.Errorf("1.1.1.1 should be routable")
	}
	if IsUnroutableServer("my-proxy.org") {
		t.Errorf("domain should not be marked unroutable IP")
	}
}

func TestStructurallyInvalidServer(t *testing.T) {
	if !IsStructurallyInvalidServer("") {
		t.Errorf("empty host should be invalid")
	}
	if !IsStructurallyInvalidServer("masir_sefid") {
		t.Errorf("single-label hostname should be invalid")
	}
	if !IsStructurallyInvalidServer("https://github.com/test") {
		t.Errorf("URL should be invalid server host")
	}
	if !IsStructurallyInvalidServer("example.com:443") {
		t.Errorf("host with port residue should be invalid")
	}
	if IsStructurallyInvalidServer("example.com") {
		t.Errorf("valid domain should be accepted")
	}
	if IsStructurallyInvalidServer("1.1.1.1") {
		t.Errorf("valid IP should be accepted")
	}
}

func TestInvalidUUID(t *testing.T) {
	if !IsInvalidUUID("", "vless") {
		t.Errorf("empty UUID should be invalid")
	}
	if !IsInvalidUUID("00000000-0000-0000-0000-000000000000", "vless") {
		t.Errorf("nil UUID should be invalid")
	}
	if IsInvalidUUID("b0341a94-4b5b-4c28-98e3-0ecdfb008d51", "vless") {
		t.Errorf("valid 36-char UUID should be accepted")
	}
	if IsInvalidUUID("f23bb427c1f94373876c2f43e9f790f3", "vmess") {
		t.Errorf("valid 32-char compact UUID should be accepted")
	}
	if IsInvalidUUID("@free_conf_iran", "vless") {
		t.Errorf("valid custom ID < 30 bytes should be accepted")
	}
	if !IsInvalidUUID("this-is-a-very-long-custom-string-exceeding-thirty-bytes", "vless") {
		t.Errorf("overlong custom ID >= 30 bytes should be invalid")
	}
	if IsInvalidUUID("any-password", "shadowsocks") {
		t.Errorf("shadowsocks password should not be constrained by UUID rules")
	}
}

func TestFilterProxyLines(t *testing.T) {
	lines := []string{
		"vless://b0341a94-4b5b-4c28-98e3-0ecdfb008d51@1.2.3.4:443?security=tls&sni=cdn.example.com#Node1",
		"vless://b0341a94-4b5b-4c28-98e3-0ecdfb008d51@1.2.3.4:443?security=tls&sni=cdn.example.com#Node1-Duplicate",
		"vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443#DummyNode",
		"vless://b0341a94-4b5b-4c28-98e3-0ecdfb008d51@127.0.0.1:443#LocalNode",
		"vless://b0341a94-4b5b-4c28-98e3-0ecdfb008d51@invalid_single_label:443#InvalidHost",
	}

	res := FilterProxyLines(lines)
	if res.Stats.Input != 5 {
		t.Errorf("expected 5 inputs, got %d", res.Stats.Input)
	}
	if res.Stats.Kept != 2 {
		t.Errorf("expected 2 kept (valid nodes), got %d", res.Stats.Kept)
	}
	if res.Stats.EndpointsUnique != 1 {
		t.Errorf("expected 1 unique endpoint after deduplication, got %d", res.Stats.EndpointsUnique)
	}
	if res.Dropped[ReasonDummy] != 1 {
		t.Errorf("expected 1 dummy drop, got %d", res.Dropped[ReasonDummy])
	}
	if res.Dropped[ReasonUnroutable] != 1 {
		t.Errorf("expected 1 unroutable drop, got %d", res.Dropped[ReasonUnroutable])
	}
	if res.Dropped[ReasonInvalidServer] != 1 {
		t.Errorf("expected 1 invalid server drop, got %d", res.Dropped[ReasonInvalidServer])
	}
}

func TestCountryCodeToFlag(t *testing.T) {
	if flag := CountryCodeToFlag("US"); flag != "🇺🇸" {
		t.Errorf("expected 🇺🇸, got %s", flag)
	}
	if flag := CountryCodeToFlag("DE"); flag != "🇩🇪" {
		t.Errorf("expected 🇩🇪, got %s", flag)
	}
	if flag := CountryCodeToFlag("ir"); flag != "🇮🇷" {
		t.Errorf("expected 🇮🇷, got %s", flag)
	}
	if flag := CountryCodeToFlag("XYZ"); flag != "" {
		t.Errorf("expected empty string for invalid code, got %s", flag)
	}
}
