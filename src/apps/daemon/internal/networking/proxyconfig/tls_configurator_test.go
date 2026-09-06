package proxyconfig

import (
	"strings"
	"testing"
)

func TestAutomatedTlsServerConfigurator(t *testing.T) {
	configurator := NewAutomatedTlsServerConfigurator()

	cfg := &ServerProvisionConfig{
		LocalAddr:          "0.0.0.0",
		LocalPort:          443,
		RemoteFallbackAddr: "127.0.0.1",
		RemoteFallbackPort: 80,
		Passwords:          []string{"secret_pass_123"},
		TLS: TlsCertificateBinding{
			CertPath:      "/etc/ssl/fullchain.pem",
			KeyPath:       "/etc/ssl/privkey.pem",
			SniDomain:     "edge.example.org",
			AlpnProtocols: []string{"h2", "http/1.1"},
		},
		EnableFastOpen: true,
	}

	configurator.RegisterServer("srv-01", cfg)
	jsonBytes, err := configurator.GenerateJSON("srv-01")
	if err != nil {
		t.Fatal(err)
	}

	str := string(jsonBytes)
	if !strings.Contains(str, `"run_type": "server"`) ||
		!strings.Contains(str, `"secret_pass_123"`) ||
		!strings.Contains(str, `"edge.example.org"`) {
		t.Fatalf("unexpected json generated: %s", str)
	}
}
