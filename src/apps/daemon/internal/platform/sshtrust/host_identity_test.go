package sshtrust

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func testPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestParseSHA256AndVerify(t *testing.T) {
	key := testPublicKey(t)
	fp := ssh.FingerprintSHA256(key)
	identity, err := ParseSHA256("  " + fp + "  ")
	if err != nil {
		t.Fatal(err)
	}
	if identity.String() != fp {
		t.Fatalf("canonical fingerprint=%q want %q", identity.String(), fp)
	}
	if err := identity.Callback()("example.test:22", &net.TCPAddr{}, key); err != nil {
		t.Fatalf("matching key rejected: %v", err)
	}
}

func TestHostIdentityRejectsMissingMalformedAndMismatch(t *testing.T) {
	for _, raw := range []string{"", "MD5:abc", "SHA256:", "SHA256:not-base64!"} {
		if _, err := ParseSHA256(raw); err == nil {
			t.Fatalf("ParseSHA256(%q) unexpectedly succeeded", raw)
		}
	}

	expected := testPublicKey(t)
	actual := testPublicKey(t)
	identity, err := ParseSHA256(ssh.FingerprintSHA256(expected))
	if err != nil {
		t.Fatal(err)
	}
	err = identity.Callback()("example.test:22", &net.TCPAddr{}, actual)
	if err == nil || !strings.Contains(err.Error(), "host key mismatch") {
		t.Fatalf("mismatch error=%v", err)
	}
}
