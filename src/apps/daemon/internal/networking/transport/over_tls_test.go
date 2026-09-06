package transport

import (
	"bytes"
	"testing"
)

func TestOverTlsCodec(t *testing.T) {
	codec := NewOverTlsCodec(32)
	payload := []byte("GET / HTTP/1.1\r\n\r\n")
	encoded := codec.EncodeFrame(FrameData, payload, 16)

	ft, decoded, consumed, err := codec.DecodeFrame(encoded)
	if err != nil {
		t.Fatalf("failed decoding: %v", err)
	}
	if ft != FrameData {
		t.Errorf("expected FrameData")
	}
	if !bytes.Equal(decoded, payload) {
		t.Errorf("payload mismatch")
	}
	if consumed != len(encoded) {
		t.Errorf("consumed bytes mismatch: got %d, expected %d", consumed, len(encoded))
	}
}
