package transport

import (
	"bytes"
	"testing"
	"time"
)

func TestBrutalPacerCalculation(t *testing.T) {
	pacer := NewBrutalPacer(10_000_000, 1_000_000, 50_000_000)
	rate := pacer.UpdateAckFeedback(10_000_000, 0.20)
	if rate != 12_000_000 {
		t.Errorf("expected 12_000_000, got %d", rate)
	}

	delay := pacer.GetPacingDelay(1500)
	if delay <= 0 || delay > 10*time.Millisecond {
		t.Errorf("unexpected pacing delay: %v", delay)
	}
}

func TestSalamanderObfuscatorSymmetry(t *testing.T) {
	key := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	enc := NewSalamanderObfuscator(key)
	dec := NewSalamanderObfuscator(key)

	orig := []byte("LumiNet high-performance censorship-resistant payload")
	buf := make([]byte, len(orig))
	copy(buf, orig)

	enc.ApplyInPlace(buf)
	if bytes.Equal(buf, orig) {
		t.Fatal("data was not obfuscated")
	}

	dec.ApplyInPlace(buf)
	if !bytes.Equal(buf, orig) {
		t.Fatalf("expected %s, got %s", string(orig), string(buf))
	}
}
