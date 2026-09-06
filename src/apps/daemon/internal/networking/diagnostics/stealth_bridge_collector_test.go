package diagnostics

import (
	"testing"
)

func TestStealthBridgeCollector(t *testing.T) {
	col := NewStealthBridgeCollector(0.5)

	obfs4Line := "obfs4 192.0.2.1:443 7325514E91D3B62042C026C1F740E7DF98E2A180 cert=qPMIiat/7J iat-mode=0"
	b1, err := col.ParseBridgeLine(obfs4Line)
	if err != nil || b1.Transport != TransportObfs4 {
		t.Fatalf("failed to parse obfs4 line: %v", err)
	}
	if b1.Params["cert"] != "qPMIiat/7J" || b1.Params["iat-mode"] != "0" {
		t.Fatalf("invalid params parsed: %v", b1.Params)
	}

	webtunnelLine := "webtunnel 198.51.100.5:443 9A8B7C6D5E4F3A2B1C0D url=https://cdn.example.com/tunnel"
	b2, err := col.ParseBridgeLine(webtunnelLine)
	if err != nil || b2.Transport != TransportWebTunnel {
		t.Fatalf("failed to parse webtunnel line: %v", err)
	}

	// Update health
	col.RecordHealth("7325514E91D3B62042C026C1F740E7DF98E2A180", 150, true)
	col.RecordHealth("9A8B7C6D5E4F3A2B1C0D", 900, false)

	best := col.GetBestBridges(TransportObfs4, 5)
	if len(best) != 1 || best[0].Fingerprint != "7325514E91D3B62042C026C1F740E7DF98E2A180" {
		t.Fatalf("unexpected best bridges: %v", best)
	}
	if !best[0].Verified || best[0].Score < 1.0 {
		t.Fatalf("expected high verified score, got %f", best[0].Score)
	}
}
