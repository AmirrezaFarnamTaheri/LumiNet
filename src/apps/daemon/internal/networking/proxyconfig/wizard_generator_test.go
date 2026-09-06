package proxyconfig

import (
	"testing"
)

func TestGenerateDnsWizardProfile(t *testing.T) {
	cfg := DnsWizardConfig{
		ProfileName:    "FastDNS",
		DnsServer:      "8.8.8.8",
		RootDomain:     "tunnel.example.com",
		ObfuscationKey: "secret-obfs",
		Compression:    true,
		Port:           5353,
	}

	res, err := GenerateDnsWizardProfile(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.ID == "" {
		t.Errorf("expected non-empty ID")
	}
	if len(res.Base64URI) == 0 {
		t.Errorf("expected non-empty base64 URI")
	}
}

func TestGenerateDnsWizardProfileInvalid(t *testing.T) {
	cfg := DnsWizardConfig{
		ProfileName: "",
	}
	_, err := GenerateDnsWizardProfile(cfg)
	if err == nil {
		t.Errorf("expected error on empty profile name")
	}
}
