package proxyconfig

import (
	"strings"
	"testing"
)

func TestMultiprotocolSynthesizer(t *testing.T) {
	syn := NewMultiprotocolSynthesizer()
	cfg := syn.GenerateInboundConfig(ProtocolPreset{
		ListenPort: 8443,
		ServerUUID: "11111111-2222-3333-4444-555555555555",
		SniDest:    "cdn.cloudflare.com",
		Transport:  TransportTcpReality,
	})

	if !strings.Contains(cfg, `"listen_port":8443`) {
		t.Fatal("missing port in config")
	}
	if !strings.Contains(cfg, `"server_name":"cdn.cloudflare.com"`) {
		t.Fatal("missing SNI destination in config")
	}
}
