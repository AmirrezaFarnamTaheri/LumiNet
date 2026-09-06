package sub

import (
	"testing"

	"github.com/maybeknott/luminet/internal/networking/proxyconfig"
)

func TestFilterSafeProxyConfigRejectsInsecureTLSByDefault(t *testing.T) {
	cfg := &proxyconfig.ProxyConfig{Protocol: proxyconfig.ProtocolVLESS, Address: "1.1.1.1", Port: 443, UUID: "id", TLS: true, SkipCertVerify: true}
	if FilterSafeProxyConfig(cfg) {
		t.Fatal("insecure TLS proxy accepted by default")
	}
	if !filterSafeProxyConfig(cfg, true) {
		t.Fatal("explicit insecure-TLS opt-in did not accept config")
	}
}

func TestFilterSafeProxyConfigRejectsCGNAT(t *testing.T) {
	cfg := &proxyconfig.ProxyConfig{Protocol: proxyconfig.ProtocolSOCKS5, Address: "100.64.12.34", Port: 1080}
	if FilterSafeProxyConfig(cfg) {
		t.Fatal("CGNAT endpoint was treated as public")
	}
}

func TestDedupeProxyConfigsUsesFullSemantics(t *testing.T) {
	first := &proxyconfig.ProxyConfig{Protocol: proxyconfig.ProtocolVLESS, Address: "example.com", Port: 443, UUID: "user-a", TLS: true, Name: "first", RawURI: "one"}
	duplicate := *first
	duplicate.Name = "different display name"
	duplicate.RawURI = "different raw spelling"
	secondCredential := *first
	secondCredential.UUID = "user-b"

	got := dedupeProxyConfigs([]*proxyconfig.ProxyConfig{first, &duplicate, &secondCredential, first})
	if len(got) != 2 {
		t.Fatalf("dedupe returned %d configs, want 2", len(got))
	}
	if got[0].UUID != "user-a" || got[1].UUID != "user-b" {
		t.Fatalf("dedupe changed first-seen deterministic order: %#v", got)
	}
}
