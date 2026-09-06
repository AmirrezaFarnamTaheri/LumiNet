package transport

import (
	"bytes"
	"testing"
)

func TestHttpChunkCarrier(t *testing.T) {
	carrier := NewHttpChunkCarrier("proxy.luminet.net", "/v1/tunnel", "sess-test")
	hdr := carrier.CreateUplinkHeader()
	if !bytes.HasPrefix(hdr, []byte("POST /v1/tunnel HTTP/1.1")) {
		t.Fatalf("unexpected header: %s", string(hdr))
	}

	data := []byte("relay binary stream chunk")
	enc := EncodeChunk(data)

	dec, consumed, err := DecodeChunk(enc)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if !bytes.Equal(dec, data) {
		t.Fatalf("data mismatch")
	}
	if consumed != len(enc) {
		t.Fatalf("consumed mismatch: %d vs %d", consumed, len(enc))
	}
}
