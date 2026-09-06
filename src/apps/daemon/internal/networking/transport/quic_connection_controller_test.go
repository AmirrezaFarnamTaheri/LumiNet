package transport

import (
	"testing"
)

func TestQuicConnectionController(t *testing.T) {
	qc := NewQuicConnectionController(20000)
	qc.SetState(ConnEstablished)
	if !qc.CanSend(1200) {
		t.Fatalf("expected CanSend to be true")
	}

	qc.OnPacketSent(1, 1200, 1000)
	m := qc.GetMetrics()
	if m.BytesInFlight != 1200 {
		t.Fatalf("expected 1200 in flight, got %d", m.BytesInFlight)
	}

	qc.OnAckReceived(1, 1060) // 60ms RTT
	m = qc.GetMetrics()
	if m.BytesInFlight != 0 {
		t.Fatalf("expected 0 in flight, got %d", m.BytesInFlight)
	}
	if m.CwndBytes <= 20000 {
		t.Fatalf("expected cwnd growth in slow start")
	}
	if qc.CalculatePtoMs() == 0 {
		t.Fatalf("expected non-zero PTO")
	}

	// Test packet loss
	qc.OnPacketSent(2, 1000, 2000)
	qc.OnPacketLoss(2)
	m = qc.GetMetrics()
	if m.LostPacketCount != 1 || m.BytesInFlight != 0 {
		t.Fatalf("loss accounting mismatch: %+v", m)
	}
}
