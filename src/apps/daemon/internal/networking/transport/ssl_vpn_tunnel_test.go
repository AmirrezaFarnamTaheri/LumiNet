package transport

import (
	"bytes"
	"testing"
	"time"
)

func TestSslVpnFrameRoundTrip(t *testing.T) {
	frame := &SslVpnFrame{
		SessionID: 0x12345678,
		Payload:   []byte("ethernet-frame-over-https"),
	}

	var buf bytes.Buffer
	if err := frame.Encode(&buf); err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decoded, err := DecodeSslVpnFrame(&buf)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if decoded.SessionID != frame.SessionID || !bytes.Equal(decoded.Payload, frame.Payload) {
		t.Fatal("decoded frame does not match")
	}

	nat := NewVirtualNatRouter(50 * time.Millisecond)
	key := NatSessionKey{SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2}, SrcPort: 12345, DstPort: 80, Proto: 6}
	nat.Touch(key)
	if !nat.IsActive(key) {
		t.Fatal("nat entry should be active")
	}
}
