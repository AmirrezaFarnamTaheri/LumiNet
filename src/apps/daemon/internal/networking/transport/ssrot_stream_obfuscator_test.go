package transport

import (
	"bytes"
	"testing"
)

func TestSsrotStreamObfuscator_PlainOrigin(t *testing.T) {
	config := SsrotConfig{
		Password: "test_secret_key",
		Protocol: SsrotProtocolOrigin,
		Obfs:     SsrotObfsPlain,
	}

	client := NewSsrotStreamObfuscator(config)
	server := NewSsrotStreamObfuscator(config)

	payload := []byte("handshake_data")
	encoded := client.ClientEncodeHandshake("test.example.com", 8080, payload)

	host, port, decodedPayload, err := server.ServerDecodeHandshake(encoded)
	if err != nil {
		t.Fatalf("decode handshake failed: %v", err)
	}

	if host != "test.example.com" {
		t.Errorf("expected host test.example.com, got %s", host)
	}
	if port != 8080 {
		t.Errorf("expected port 8080, got %d", port)
	}
	if !bytes.Equal(decodedPayload, payload) {
		t.Errorf("payload mismatch")
	}

	chunkData := []byte("streaming data chunk")
	chunk := client.EncodeChunk(chunkData)
	decodedChunk, err := server.DecodeChunk(chunk)
	if err != nil {
		t.Fatalf("decode chunk failed: %v", err)
	}
	if !bytes.Equal(decodedChunk, chunkData) {
		t.Errorf("chunk payload mismatch")
	}
}

func TestSsrotStreamObfuscator_HttpSimpleAuth(t *testing.T) {
	config := SsrotConfig{
		Password:  "another_secret",
		Protocol:  SsrotProtocolAuthSha1V4,
		Obfs:      SsrotObfsHttpSimple,
		ObfsParam: "proxy.gateway.net",
	}

	client := NewSsrotStreamObfuscator(config)
	server := NewSsrotStreamObfuscator(config)

	encoded := client.ClientEncodeHandshake("internal.net", 443, []byte("data"))
	host, port, payload, err := server.ServerDecodeHandshake(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if host != "internal.net" || port != 443 || !bytes.Equal(payload, []byte("data")) {
		t.Fatalf("mismatch in decoded handshake")
	}
}
