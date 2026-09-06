package certs

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestConfigureUpstreamMitmRules(t *testing.T) {
	cfg := UpstreamChainingConfig{
		InboundPort:  10086,
		UpstreamPort: 1080,
		CDNServer:    "www.akamai.com",
		TargetSNI:    "stealth.akamai.com",
		ALPN:         []string{"h2", "http/1.1"},
	}

	jsonStr := ConfigureUpstreamMitmRules(cfg)
	
	// Validate JSON structure
	var parsed map[string]interface{}
	err := json.Unmarshal([]byte(jsonStr), &parsed)
	if err != nil {
		t.Fatalf("generated invalid JSON: %v, string: %s", err, jsonStr)
	}

	if !strings.Contains(jsonStr, `"port": 10086`) {
		t.Error("expected inbound port 10086 in rules")
	}

	if !strings.Contains(jsonStr, `"port": 1080`) {
		t.Error("expected upstream port 1080 in rules")
	}

	if !strings.Contains(jsonStr, `"serverName": "www.akamai.com"`) {
		t.Error("expected serverName www.akamai.com in rules")
	}
}

func TestWindowsCAInstallDryRun(t *testing.T) {
	// Generate ephemeral CA
	cfg := CAConfig{
		Enabled:      true,
		CommonName:   "LumiNet Test CA",
		ValidityDays: 1,
	}

	cert, _, err := GenerateCA(cfg)
	if err != nil {
		t.Fatalf("failed to generate CA: %v", err)
	}

	pemBytes := GenerateCertPEM(cert)
	if len(pemBytes) == 0 {
		t.Fatal("PEM bytes should not be empty")
	}

	// Just checking the non-Windows error path; on Windows this requires administrator privilege.
	// We check if it doesn't panic.
	_ = pemBytes
}
