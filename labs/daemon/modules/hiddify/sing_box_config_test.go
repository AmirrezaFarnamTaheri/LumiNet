package hiddify

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNewDefaultSingBoxConfig(t *testing.T) {
	cfg := NewDefaultSingBoxConfig()
	if cfg.Log.Level != "info" {
		t.Errorf("expected log level info, got %s", cfg.Log.Level)
	}
	if len(cfg.Inbounds) != 1 || cfg.Inbounds[0].Type != "mixed" {
		t.Errorf("expected mixed inbound, got %+v", cfg.Inbounds)
	}
}

func TestBuildJSON(t *testing.T) {
	cfg := NewDefaultSingBoxConfig()
	
	// Add custom Trojan outbound with multiplexing
	cfg.Outbounds = append(cfg.Outbounds, OutboundConfig{
		Type:       "trojan",
		Tag:        "trojan-out",
		Server:     "trojan.example.com",
		ServerPort: 443,
		Password:   "secret-pass",
		TLS: &TLSConfig{
			Enabled:    true,
			ServerName: "trojan.example.com",
			Insecure:   true,
		},
		Transport: &TransportConfig{
			Type:        "grpc",
			ServiceName: "my-service-name",
		},
		Multiplex: &MultiplexConfig{
			Enabled:        true,
			Protocol:       "smux",
			MaxConnections: 4,
			MinStreams:     2,
			MaxStreams:     16,
		},
	})

	jsonStr, err := cfg.BuildJSON()
	if err != nil {
		t.Fatalf("BuildJSON failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	outbounds, ok := parsed["outbounds"].([]interface{})
	if !ok {
		t.Fatalf("outbounds not found or not an array")
	}

	foundTrojan := false
	for _, ob := range outbounds {
		m, ok := ob.(map[string]interface{})
		if !ok {
			continue
		}
		if m["type"] == "trojan" {
			foundTrojan = true
			if m["tag"] != "trojan-out" {
				t.Errorf("expected tag trojan-out, got %v", m["tag"])
			}
			tls, ok := m["tls"].(map[string]interface{})
			if !ok || tls["enabled"] != true {
				t.Errorf("expected tls enabled, got %+v", m["tls"])
			}
			transport, ok := m["transport"].(map[string]interface{})
			if !ok || transport["type"] != "grpc" || transport["service_name"] != "my-service-name" {
				t.Errorf("expected transport grpc, got %+v", m["transport"])
			}
			mux, ok := m["multiplex"].(map[string]interface{})
			if !ok || mux["enabled"] != true || mux["protocol"] != "smux" {
				t.Errorf("expected multiplex smux, got %+v", m["multiplex"])
			}
		}
	}

	if !foundTrojan {
		t.Errorf("trojan outbound was not found in output")
	}
}

func TestAddWireguardOutbound(t *testing.T) {
	cfg := NewDefaultSingBoxConfig()
	cfg.AddWireguardOutbound(
		"wg-out",
		"1.2.3.4",
		51820,
		"privatekey123",
		"publickey123",
		[]byte{1, 2, 3},
		[]string{"10.0.0.2/32"},
	)

	if len(cfg.Outbounds) != 3 { // direct, block, wireguard
		t.Fatalf("expected 3 outbounds, got %d", len(cfg.Outbounds))
	}

	wg := cfg.Outbounds[2]
	if wg.Type != "wireguard" || wg.Tag != "wg-out" || wg.Server != "1.2.3.4" || wg.ServerPort != 51820 {
		t.Errorf("unexpected wireguard outbound: %+v", wg)
	}

	// Verify route bypass rule was added at index 0
	if len(cfg.Route.Rules) != 2 {
		t.Fatalf("expected 2 route rules, got %d", len(cfg.Route.Rules))
	}

	bypassRule := cfg.Route.Rules[0]
	if len(bypassRule.IP) != 1 || bypassRule.IP[0] != "1.2.3.4/32" || bypassRule.Outbound != "direct" {
		t.Errorf("unexpected bypass route rule: %+v", bypassRule)
	}
}

func TestAddAmneziaWireguardOutbound(t *testing.T) {
	cfg := NewDefaultSingBoxConfig()
	cfg.AddWireguardOutbound(
		"awg-out",
		"5.6.7.8",
		51820,
		"pkey",
		"pubkey",
		nil,
		[]string{"10.0.0.3/32"},
	)

	// Add Amnezia parameters
	cfg.Outbounds[2].Amnezia = &AmneziaWGConfig{
		Jc:   4,
		Jmin: 50,
		Jmax: 1000,
		S1:   80,
		S2:   44,
	}

	jsonStr, err := cfg.BuildJSON()
	if err != nil {
		t.Fatalf("BuildJSON failed: %v", err)
	}

	if !strings.Contains(jsonStr, `"jc": 4`) || !strings.Contains(jsonStr, `"jmin": 50`) || !strings.Contains(jsonStr, `"jmax": 1000`) {
		t.Errorf("expected Amnezia parameters to be serialized, got %s", jsonStr)
	}
}

func TestAddXhttpOutboundWithHeaders(t *testing.T) {
	cfg := NewDefaultSingBoxConfig()
	cfg.Outbounds = append(cfg.Outbounds, OutboundConfig{
		Type:       "vless",
		Tag:        "xhttp-out",
		Server:     "vercel-relay.com",
		ServerPort: 443,
		Transport: &TransportConfig{
			Type: "xhttp",
			Path: "/relay-path",
			Headers: map[string]interface{}{
				"x-relay-key": "my-secure-token",
			},
		},
	})

	jsonStr, err := cfg.BuildJSON()
	if err != nil {
		t.Fatalf("BuildJSON failed: %v", err)
	}

	if !strings.Contains(jsonStr, `"x-relay-key": "my-secure-token"`) {
		t.Errorf("expected custom xhttp header, got %s", jsonStr)
	}
}
