package transport

import (
	"bytes"
	"testing"
)

func TestEntropyScrambledTunnel(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i + 1)
	}

	tunnel := NewEntropyScrambledTunnel(key, 8, 32)

	// Low-entropy plaintext
	plaintext := make([]byte, 128) // all zeroes
	if CalculateShannonEntropy(plaintext) != 0.0 {
		t.Fatalf("expected 0 entropy for zeroes")
	}

	seed := uint64(123456789)
	scrambled, err := tunnel.ScramblePacket(plaintext, seed)
	if err != nil {
		t.Fatalf("failed to scramble packet: %v", err)
	}

	ent := CalculateShannonEntropy(scrambled)
	if ent < 6.0 {
		t.Fatalf("expected high entropy (>6.0), got %f", ent)
	}

	descrambled, err := tunnel.DescramblePacket(scrambled, seed)
	if err != nil {
		t.Fatalf("failed to descramble packet: %v", err)
	}

	if !bytes.Equal(descrambled, plaintext) {
		t.Fatalf("descrambled data did not match plaintext")
	}
}
