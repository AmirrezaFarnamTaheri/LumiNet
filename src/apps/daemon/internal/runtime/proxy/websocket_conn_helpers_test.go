package proxy

import (
	"bytes"
	"testing"
)

func TestVLESSWSResponseStateHeaderIsConsumedExactlyOnce(t *testing.T) {
	var state vlessWSResponseState

	payload, ready, err := state.consume([]byte{0x00, 0x01, 0x7f, 'a', 'b'})
	if err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if !ready || !bytes.Equal(payload, []byte("ab")) {
		t.Fatalf("first payload = %x ready=%v, want 6162 true", payload, ready)
	}

	second := []byte{0x00, 0x00, 'c'}
	payload, ready, err = state.consume(second)
	if err != nil {
		t.Fatalf("second consume: %v", err)
	}
	if !ready || !bytes.Equal(payload, second) {
		t.Fatalf("second payload = %x ready=%v, want unchanged %x true", payload, ready, second)
	}
}

func TestVLESSWSResponseStateAcceptsSplitHeaderWithoutRecursion(t *testing.T) {
	var state vlessWSResponseState

	parts := [][]byte{{0x00}, {0x02, 0xaa}, {0xbb}, []byte("payload")}
	for i, part := range parts[:3] {
		payload, ready, err := state.consume(part)
		if err != nil {
			t.Fatalf("part %d: %v", i, err)
		}
		if ready || len(payload) != 0 {
			t.Fatalf("part %d unexpectedly ready with %x", i, payload)
		}
	}

	payload, ready, err := state.consume(parts[3])
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	if !ready || !bytes.Equal(payload, []byte("payload")) {
		t.Fatalf("payload = %q ready=%v, want payload true", payload, ready)
	}
}

func TestVLESSWSResponseStateRejectsWrongVersion(t *testing.T) {
	var state vlessWSResponseState
	if _, _, err := state.consume([]byte{0x01, 0x00}); err == nil {
		t.Fatal("expected wrong response version to fail")
	}
}
