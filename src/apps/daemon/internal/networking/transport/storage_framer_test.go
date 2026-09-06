package transport

import (
	"bytes"
	"testing"
)

func TestCovertStorageFramer(t *testing.T) {
	framer := &CovertStorageFramer{}
	chunk := &CovertChunk{
		StreamID: 101,
		Sequence: 42,
		IsFin:    false,
		Payload:  []byte("skirk storage frame payload"),
	}

	framed := framer.FrameChunk(chunk)
	if !bytes.HasPrefix(framed, StorageChunkMagic) {
		t.Fatalf("magic missing")
	}

	unframed, consumed, err := framer.UnframeChunk(framed)
	if err != nil {
		t.Fatalf("unframe failed: %v", err)
	}

	if unframed.StreamID != chunk.StreamID || unframed.Sequence != chunk.Sequence {
		t.Fatalf("mismatched stream or seq")
	}
	if !bytes.Equal(unframed.Payload, chunk.Payload) {
		t.Fatalf("mismatched payload")
	}
	if consumed != len(framed) {
		t.Fatalf("consumed size mismatch")
	}
}
