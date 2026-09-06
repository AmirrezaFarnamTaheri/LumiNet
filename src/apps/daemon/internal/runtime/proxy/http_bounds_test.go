package proxy

import (
	"bytes"
	"testing"
)

func TestReadBoundedProxyHTTPBodyRejectsOversize(t *testing.T) {
	if _, err := readBoundedProxyHTTPBody(bytes.NewReader(make([]byte, 9)), 8, "test response"); err == nil {
		t.Fatal("oversized HTTP body was accepted")
	}
}

func TestReadBoundedProxyHTTPBodyAcceptsLimit(t *testing.T) {
	body, err := readBoundedProxyHTTPBody(bytes.NewReader(make([]byte, 8)), 8, "test response")
	if err != nil || len(body) != 8 {
		t.Fatalf("bounded body = %d bytes, err=%v", len(body), err)
	}
}

func TestZephyrEnvelopeRejectsOversizedPayload(t *testing.T) {
	payload := make([]byte, ZephyrMaxPayloadLen+1)
	if _, err := (&ZephyrEnvelope{SessionID: "s", Payload: payload}).Encode(); err == nil {
		t.Fatal("oversized Zephyr payload was accepted")
	}
}
