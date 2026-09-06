package dns

import (
	"bytes"
	"testing"
)

func TestDnsTunnelCodec(t *testing.T) {
	codec := NewDnsTunnelCodec()
	frame := &DnsTunnelFrame{
		SessionID: 0x1234,
		Sequence:  42,
		IsFinal:   true,
		Payload:   []byte("tunnel-data"),
	}

	query := codec.EncodeToQuery(frame, "tunnel.example.com")
	decoded, err := codec.DecodeFromQuery(query, "tunnel.example.com")
	if err != nil {
		t.Fatalf("DecodeFromQuery failed: %v", err)
	}

	if decoded.SessionID != 0x1234 || decoded.Sequence != 42 || !decoded.IsFinal || !bytes.Equal(decoded.Payload, frame.Payload) {
		t.Fatalf("decoded mismatch: %+v", decoded)
	}
}
