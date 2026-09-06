package transport

import (
	"bytes"
	"testing"
)

func TestMasqueAmneziaHybridTunnel(t *testing.T) {
	params := DefaultAmneziaParams()
	cfg := MasqueAmneziaHybridConfig{
		ContextID:      42,
		AmneziaParams:  params,
		EnableEvasion:  true,
		JunkBufferSize: 64,
	}

	hybrid, err := NewMasqueAmneziaHybridTunnel(cfg)
	if err != nil {
		t.Fatalf("failed to create hybrid tunnel: %v", err)
	}

	// Test handshake preamble: Jc junk packets + 1 initiation capsule
	initPayload := []byte("WG_INITIATION_EPHEMERAL_PUBLIC_KEY")
	preamble, err := hybrid.GenerateHandshakePreamble(initPayload)
	if err != nil {
		t.Fatalf("failed to generate preamble: %v", err)
	}
	if len(preamble) != params.Jc+1 {
		t.Fatalf("expected %d packets, got %d", params.Jc+1, len(preamble))
	}

	// Test data encapsulation and decapsulation
	innerIP := []byte("IPV4_DATAGRAM_CONTENTS_12345")
	enc := hybrid.EncapsulateDataPacket(innerIP)

	dec, err := hybrid.DecapsulateDataPacket(enc)
	if err != nil {
		t.Fatalf("failed to decapsulate data: %v", err)
	}
	if !bytes.Equal(dec, innerIP) {
		t.Fatalf("decapsulated payload mismatch")
	}
}
