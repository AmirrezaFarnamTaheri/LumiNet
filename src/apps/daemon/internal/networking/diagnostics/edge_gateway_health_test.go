package diagnostics

import (
	"testing"
)

func TestEdgeGatewayHealthMeter(t *testing.T) {
	meter := NewEdgeGatewayHealthMeter(0.2, 200)
	meter.RegisterGateway("gw1", "https://cf1.example.com")
	meter.RegisterGateway("gw2", "https://cf2.example.com")

	meter.RecordRequest("gw1", 50, true)
	meter.RecordRequest("gw1", 60, true)
	m1 := meter.GetMetrics("gw1")
	if m1 == nil || m1.State != EdgeHealthHealthy {
		t.Fatalf("expected gw1 healthy, got %+v", m1)
	}

	meter.RecordRequest("gw2", 250, false)
	meter.RecordRequest("gw2", 300, false)
	m2 := meter.GetMetrics("gw2")
	if m2 == nil || m2.State == EdgeHealthHealthy {
		t.Fatalf("expected gw2 degraded/critical, got %+v", m2)
	}

	best := meter.SelectBestGateway()
	if best == nil || best.GatewayID != "gw1" {
		t.Fatalf("expected best gateway gw1, got %+v", best)
	}
}
