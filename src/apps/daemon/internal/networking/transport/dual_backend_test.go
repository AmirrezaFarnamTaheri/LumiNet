package transport

import (
	"testing"
)

func TestDualBackendController(t *testing.T) {
	c := NewDualBackendController()
	if c.SelectEngine() != EngineKcpRawSocket {
		t.Errorf("expected initial engine to be EngineKcpRawSocket")
	}

	// Fail KcpRawSocket 3 times
	c.RecordMetrics(EngineKcpRawSocket, 300, 0.5, false)
	c.RecordMetrics(EngineKcpRawSocket, 300, 0.5, false)
	c.RecordMetrics(EngineKcpRawSocket, 300, 0.5, false)

	if c.SelectEngine() != EngineViolatedTcpQuic {
		t.Errorf("expected failover to EngineViolatedTcpQuic")
	}

	// Test RTT race
	c.RecordMetrics(EngineViolatedTcpQuic, 35, 0.01, true)
	c.RecordMetrics(EngineFallback, 200, 0.05, true)
	if c.SelectByRttRace() != EngineViolatedTcpQuic {
		t.Errorf("expected EngineViolatedTcpQuic to win RTT race")
	}
}
