package sub

import (
	"encoding/json"
	"testing"
)

func TestParseMultiProtocolSubscription(t *testing.T) {
	raw := `
# My Subscription Nodes
vless://a1b2c3d4-e5f6-7890-abcd-ef1234567890@198.51.100.25:443?security=reality&pbk=pubkey123&sid=1234&sni=example.com#SameTag
trojan://secret123@trojan.example.com:443?sni=trojan.example.com#SameTag
ss://YWVzLTEyOC1nY206c2VjcmV0cGFzcw==@192.0.2.10:8388#SSNode
// Commented out
`
	configs, warnings := ParseMultiProtocolSubscription(raw)
	if len(warnings) > 0 {
		t.Logf("Warnings during parse: %v", warnings)
	}
	if len(configs) != 3 {
		t.Fatalf("Expected 3 parsed configs, got %d", len(configs))
	}

	if configs[0].Name != "SameTag" {
		t.Fatalf("Expected first node tag 'SameTag', got '%s'", configs[0].Name)
	}
	if configs[1].Name != "SameTag-1" {
		t.Fatalf("Expected deduplicated second node tag 'SameTag-1', got '%s'", configs[1].Name)
	}
	if configs[2].Name != "SSNode" {
		t.Fatalf("Expected third node tag 'SSNode', got '%s'", configs[2].Name)
	}
}

func TestExportSingboxClientConfig(t *testing.T) {
	raw := `
vless://uuid-vless@node1.org:443?security=reality&pbk=key1&sid=sid1#Node1
trojan://pass-trojan@node2.org:443?sni=node2.org#Node2
`
	configs, _ := ParseMultiProtocolSubscription(raw)
	opts := SingboxExportOptions{
		Listen:              "127.0.0.1",
		MixedPort:           2080,
		TunEnabled:          true,
		TunMTU:              9000,
		AutoURLTest:         true,
		TestURL:             "https://www.gstatic.com/generate_204",
		ExperimentalClashAPI: true,
		ClashAPIPort:        9090,
	}

	data, err := ExportSingboxClientConfig(configs, opts)
	if err != nil {
		t.Fatalf("ExportSingboxClientConfig failed: %v", err)
	}

	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("Failed to parse output sing-box JSON: %v", err)
	}

	// Inbounds check
	inbounds, ok := root["inbounds"].([]any)
	if !ok || len(inbounds) != 2 {
		t.Fatalf("Expected 2 inbounds (tun + mixed), got %v", root["inbounds"])
	}

	// Outbounds check
	outbounds, ok := root["outbounds"].([]any)
	if !ok || len(outbounds) < 5 {
		t.Fatalf("Expected at least 5 outbounds, got %d", len(outbounds))
	}

	firstOb := outbounds[0].(map[string]any)
	if firstOb["tag"] != "select" || firstOb["type"] != "selector" {
		t.Fatalf("Expected first outbound to be selector 'select', got %v", firstOb)
	}

	secondOb := outbounds[1].(map[string]any)
	if secondOb["tag"] != "auto" || secondOb["type"] != "urltest" {
		t.Fatalf("Expected second outbound to be urltest 'auto', got %v", secondOb)
	}

	// Experimental check
	exp, ok := root["experimental"].(map[string]any)
	if !ok {
		t.Fatalf("Expected experimental section in sing-box config")
	}
	clashApi, ok := exp["clash_api"].(map[string]any)
	if !ok || clashApi["external_controller"] != "127.0.0.1:9090" {
		t.Fatalf("Unexpected clash_api config: %v", clashApi)
	}
}
