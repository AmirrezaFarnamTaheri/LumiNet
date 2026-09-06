package transport

import (
	"bytes"
	"testing"
)

func TestDpiPatternMasker(t *testing.T) {
	masker := NewDpiPatternMasker(5, true)
	clientHello := []byte{0x16, 0x03, 0x01, 0x00, 0x50, 0x01, 0x00, 0x00, 0x4C}

	frags := masker.FragmentPayload(clientHello)
	if len(frags) != 3 {
		t.Fatalf("expected 3 fragments, got %d", len(frags))
	}

	recomb := ReassemblePayload(frags)
	if !bytes.Equal(recomb, clientHello) {
		t.Fatalf("recombined payload mismatch")
	}
}
