package transport

import (
	"bytes"
	"testing"
)

func TestServerlessFrameRoundtrip(t *testing.T) {
	original := ServerlessFrame{
		StreamID: 101,
		IsEOF:    true,
		Payload:  []byte("HTTP/2 EDGE DATA TUNNEL PAYLOAD"),
	}

	encoded := EncodeServerlessFrame(original)
	reader := bytes.NewReader(encoded)

	decoded, err := DecodeServerlessFrame(reader)
	if err != nil {
		t.Fatalf("failed to decode frame: %v", err)
	}

	if decoded.StreamID != original.StreamID {
		t.Errorf("expected StreamID %d, got %d", original.StreamID, decoded.StreamID)
	}
	if decoded.IsEOF != original.IsEOF {
		t.Errorf("expected IsEOF %v, got %v", original.IsEOF, decoded.IsEOF)
	}
	if !bytes.Equal(decoded.Payload, original.Payload) {
		t.Errorf("payload mismatch")
	}
}

func TestServerlessFrameInvalidMagic(t *testing.T) {
	badData := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	reader := bytes.NewReader(badData)
	_, err := DecodeServerlessFrame(reader)
	if err == nil {
		t.Errorf("expected error on invalid magic")
	}
}
