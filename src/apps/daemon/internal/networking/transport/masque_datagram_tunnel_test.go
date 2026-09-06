package transport

import (
	"bytes"
	"testing"
)

func TestMasqueDatagramTunnel(t *testing.T) {
	tunnel := NewMasqueDatagramTunnel(100)

	payload := []byte("UDP_PAYLOAD_FOR_CONNECT_IP_TUNNEL")
	capsule := tunnel.EncodeDatagramCapsule(payload)

	ctxID, recovered, err := tunnel.DecodeDatagramCapsule(capsule)
	if err != nil {
		t.Fatalf("failed to decode datagram capsule: %v", err)
	}
	if ctxID != 100 {
		t.Fatalf("expected context ID 100, got %d", ctxID)
	}
	if !bytes.Equal(recovered, payload) {
		t.Fatalf("recovered payload mismatch")
	}

	// Address request capsule
	addrCapsule := tunnel.EncodeAddressRequestCapsule("10.0.0.99")
	if len(addrCapsule) != 4+len("10.0.0.99") {
		t.Fatalf("address capsule length unexpected")
	}
}
