package proxy

import (
	"bytes"
	"testing"
)

func TestFECCodec_EncodeDecode(t *testing.T) {
	codec := NewFECCodec(3, 1)

	shards := [][]byte{
		[]byte("aaa"),
		[]byte("bbb"),
		[]byte("ccc"),
	}

	parity, err := codec.Encode(shards)
	if err != nil {
		t.Fatalf("failed to encode: %v", err)
	}

	if len(parity) != 1 {
		t.Fatalf("expected 1 parity shard, got %d", len(parity))
	}

	// Lost the second shard ("bbb")
	totalShards := [][]byte{
		shards[0],
		nil,
		shards[2],
		parity[0],
	}

	recovered, err := codec.Decode(totalShards, 1)
	if err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	if !bytes.Equal(recovered, shards[1]) {
		t.Errorf("expected recovered shard to be %q, got %q", string(shards[1]), string(recovered))
	}
}
