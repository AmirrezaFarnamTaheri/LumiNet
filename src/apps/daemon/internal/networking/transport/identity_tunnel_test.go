package transport

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"testing"
)

func TestIdentityTunnelHeaderRoundTrip(t *testing.T) {
	secret := []byte("master-secret-key-12345")
	sub := "user@corp.internal"
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(sub))
	var tok [32]byte
	copy(tok[:], mac.Sum(nil))

	var buf bytes.Buffer
	err := EncodeIdentityTunnelHeader(&buf, 8443, tok, "app.internal.domain")
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decoded, err := DecodeIdentityTunnelHeader(&buf)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}
	if decoded.TargetPort != 8443 {
		t.Errorf("expected port 8443, got %d", decoded.TargetPort)
	}
	if decoded.TargetDomain != "app.internal.domain" {
		t.Errorf("expected app.internal.domain, got %s", decoded.TargetDomain)
	}
	if !VerifyIdentityToken(decoded.AuthToken, secret, sub) {
		t.Fatal("token verification failed")
	}
}
