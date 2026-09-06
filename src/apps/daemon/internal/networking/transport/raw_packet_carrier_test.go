package transport

import (
	"bytes"
	"testing"
)

func TestRawPacketCarrierRoundtrip(t *testing.T) {
	payload := []byte("RAW_ETHERNET_OR_IP_LAYER_3_FRAME_BYTES")
	encoded := EncodeCarrierPacket(42, 1001, payload)

	decoded, err := DecodeCarrierPacket(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("failed to decode packet: %v", err)
	}

	if decoded.Sequence != 42 {
		t.Errorf("expected seq 42, got %d", decoded.Sequence)
	}
	if decoded.SessionID != 1001 {
		t.Errorf("expected session 1001, got %d", decoded.SessionID)
	}
	if !bytes.Equal(decoded.Payload, payload) {
		t.Errorf("payload corrupted")
	}
}

func TestRawPacketCarrierCorruptPayload(t *testing.T) {
	payload := []byte("VALID_DATA")
	encoded := EncodeCarrierPacket(1, 1, payload)

	// Tamper payload byte
	encoded[len(encoded)-1] ^= 0xff

	_, err := DecodeCarrierPacket(bytes.NewReader(encoded))
	if err == nil {
		t.Errorf("expected checksum mismatch on tampered payload")
	}
}
