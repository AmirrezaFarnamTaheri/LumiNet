package safety

import (
	"testing"
)

func TestGatewayHealthMonitor(t *testing.T) {
	m := NewGatewayHealthMonitor()
	m.RegisterGateway("192.0.2.1")
	m.RegisterGateway("192.0.2.2")

	m.RecordProbe("192.0.2.1", 10.0, 0.0)
	m.RecordProbe("192.0.2.2", 20.0, 0.0)
	if active := m.SelectActiveGateway("192.0.2.1", "192.0.2.2"); active != "192.0.2.1" {
		t.Fatalf("expected primary, got %s", active)
	}

	m.RecordProbe("192.0.2.1", 100.0, 0.60) // offline
	if active := m.SelectActiveGateway("192.0.2.1", "192.0.2.2"); active != "192.0.2.2" {
		t.Fatalf("expected backup failover, got %s", active)
	}
}
