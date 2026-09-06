package diagnostics

import (
	"net"
	"testing"
)

func TestFlowAnalyzerEngine(t *testing.T) {
	engine := NewFlowAnalyzerEngine()

	src := &net.TCPAddr{IP: net.ParseIP("192.168.1.10"), Port: 54321}
	dst := &net.TCPAddr{IP: net.ParseIP("104.16.12.34"), Port: 443}

	tlsClientHello := []byte{0x16, 0x03, 0x01, 0x00, 0x80}
	fid := engine.RegisterFlow(src, dst, tlsClientHello)

	flow, ok := engine.GetFlow(fid)
	if !ok || flow.Protocol != ProtocolTLS {
		t.Fatalf("expected flow %d identified as TLS, got ok=%v, proto=%v", fid, ok, flow.Protocol)
	}

	engine.RecordPacket(fid, 1200, false, false)
	engine.RecordPacket(fid, 1200, true, true)
	engine.RecordPacket(fid, 1200, true, true)

	updated, _ := engine.GetFlow(fid)
	if updated.RetransmissionRate() < 50.0 {
		t.Fatalf("expected high retransmission rate, got %f", updated.RetransmissionRate())
	}

	anomalies := engine.DetectAnomalies(40.0)
	if len(anomalies) != 1 || anomalies[0] != fid {
		t.Fatalf("expected anomaly %d, got %v", fid, anomalies)
	}
}
