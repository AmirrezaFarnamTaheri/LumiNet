package transport

import (
	"bytes"
	"testing"
)

func TestQuicEvasionTunnelCoordinator(t *testing.T) {
	dcid := []byte{1, 2, 3, 4}
	scid := []byte{5, 6, 7, 8}
	cRand := []byte("c_rand_coord_123")
	sRand := []byte("s_rand_coord_456")

	client := NewQuicEvasionTunnelCoordinator(dcid, scid, cRand, sRand, false)
	server := NewQuicEvasionTunnelCoordinator(dcid, scid, cRand, sRand, false)

	sid := client.OpenTunnelStream()
	now := int64(1700000000)

	outbound, err := client.PrepareOutboundDatagram(sid, []byte("Encrypted Quic Stream Data"), now)
	if err != nil {
		t.Fatalf("prepare outbound failed: %v", err)
	}
	if len(outbound) != 1 {
		t.Fatalf("expected 1 unsegmented datagram, got %d", len(outbound))
	}

	recvSid, payload, err := server.ProcessInboundDatagram(outbound[0], now+1)
	if err != nil {
		t.Fatalf("process inbound failed: %v", err)
	}
	if recvSid != sid || !bytes.Equal(payload, []byte("Encrypted Quic Stream Data")) {
		t.Fatalf("stream mismatch: sid=%d, payload=%s", recvSid, string(payload))
	}

	m := client.GetTunnelMetrics()
	if m.TotalDatagramsSent != 1 {
		t.Fatalf("expected 1 datagram sent, got %d", m.TotalDatagramsSent)
	}
}
