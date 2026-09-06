package proxyconfig

import (
	"bytes"
	"testing"
)

func TestHybridShadowV2Transport(t *testing.T) {
	config := HybridShadowConfig{
		Cipher:          CipherAes256Gcm,
		PreSharedKey:    []byte("0123456789abcdef0123456789abcdef"),
		ReplayWindowSec: 60,
		SaltLength:      32,
		EnablePadding:   true,
	}

	transport, err := NewHybridShadowV2Transport(config)
	if err != nil {
		t.Fatalf("failed to create transport: %v", err)
	}

	// Test salt generation and subkey derivation
	salt, err := transport.GenerateSalt()
	if err != nil {
		t.Fatalf("failed to generate salt: %v", err)
	}
	if len(salt) != 32 {
		t.Fatalf("expected salt len 32, got %d", len(salt))
	}

	subkey := transport.DeriveSubkey(salt)
	if len(subkey) != 32 {
		t.Fatalf("expected subkey len 32, got %d", len(subkey))
	}

	// Test replay registration
	if !transport.RegisterSalt(salt) {
		t.Fatalf("expected initial salt registration to succeed")
	}
	if transport.RegisterSalt(salt) {
		t.Fatalf("expected replay salt registration to fail")
	}

	// Test frame and unframe
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	framed := transport.FramePayload(salt, payload)

	recoveredSalt, recoveredPayload, err := transport.UnframePayload(framed)
	if err != nil {
		t.Fatalf("failed to unframe payload: %v", err)
	}

	if !bytes.Equal(salt, recoveredSalt) {
		t.Fatalf("salt mismatch")
	}
	if !bytes.Equal(payload, recoveredPayload) {
		t.Fatalf("payload mismatch")
	}
}
