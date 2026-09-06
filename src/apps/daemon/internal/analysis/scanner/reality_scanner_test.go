package scanner

import (
	"context"
	"testing"
)

func TestRealityScanner_Handshake(t *testing.T) {
	scanner := NewRealityScanner()

	res, err := scanner.Scan(context.Background(), "google.com:443", "google.com")
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if !res.HandshakeOK {
		t.Errorf("expected handshake to succeed, got error: %s", res.Error)
	}

	if res.CertSubject == "" {
		t.Errorf("expected cert subject name to be parsed")
	}
}
