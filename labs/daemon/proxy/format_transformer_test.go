package proxy

import (
	"bytes"
	"testing"
)

func TestAlphanumericTransformer(t *testing.T) {
	ft := NewAlphanumericTransformer()
	input := []byte("Hello, FTE World!")

	encoded, err := ft.Encode(input)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decoded, err := ft.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if !bytes.Equal(decoded, input) {
		t.Errorf("Decoded content mismatch: expected %q, got %q", input, decoded)
	}
}

func TestHttpGetRequestTransformer(t *testing.T) {
	ft := NewHttpGetRequestTransformer()
	input := []byte("secret_payload_123")

	encoded, err := ft.Encode(input)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	// Verify it matches HTTP GET request structure
	importStrings := "HTTP/1.1\r\n\r\n"
	if len(encoded) < 20 || encoded[:5] != "GET /" || len(encoded) < len(importStrings) || encoded[len(encoded)-len(importStrings):] != importStrings {
		t.Errorf("Unexpected encoded output: %q", encoded)
	}

	decoded, err := ft.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if !bytes.Equal(decoded, input) {
		t.Errorf("Decoded content mismatch: expected %q, got %q", input, decoded)
	}
}
