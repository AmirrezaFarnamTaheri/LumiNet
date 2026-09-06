package security

import (
	"bytes"
	"testing"
)

func TestDnsArqEncodeDecode(t *testing.T) {
	root := "tunnel.example.com"
	payload := []byte("secret payload")
	query := EncodeArqQuery(root, 5, true, payload)

	decoded, err := DecodeArqQuery(query, root)
	if err != nil {
		t.Fatalf("failed to decode arq query: %v", err)
	}

	if decoded.SeqID != 5 {
		t.Errorf("expected seq 5, got %d", decoded.SeqID)
	}
	if !decoded.IsLast {
		t.Errorf("expected IsLast to be true")
	}
	if !bytes.Equal(decoded.Payload, payload) {
		t.Errorf("payload corrupted")
	}
}
