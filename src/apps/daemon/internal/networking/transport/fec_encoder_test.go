package transport

import (
	"bytes"
	"testing"
)

func TestPacketFecEncoder(t *testing.T) {
	encoder := NewPacketFecEncoder(3)
	p1 := []byte("packet 1 data")
	p2 := []byte("packet 2 data")
	p3 := []byte("packet 3 data")

	parity, err := encoder.ComputeParity([][]byte{p1, p2, p3})
	if err != nil {
		t.Fatalf("compute parity failed: %v", err)
	}

	// Assume p2 is lost. Recover with p1, p3, and parity
	known := [][]byte{p1, p3}
	recoveredP2 := RecoverSingleMissing(known, parity, len(p2))

	if !bytes.Equal(recoveredP2, p2) {
		t.Fatalf("recovered p2 mismatch: %s vs %s", string(recoveredP2), string(p2))
	}
}
