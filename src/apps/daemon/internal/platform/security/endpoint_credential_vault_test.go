package security

import (
	"bytes"
	"testing"
)

func TestEndpointCredentialVault(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = 0x42
	}
	vault := NewEndpointCredentialVault(key)
	secret := []byte("super-vpn-password-123")

	vault.StoreProfile("prof1", "vpn.example.com", 443, "alice", secret, 1000, 300)

	if !vault.IsProfileValid("prof1", 1100) {
		t.Fatal("expected profile to be valid at 1100")
	}

	retrieved, ok := vault.RetrieveSecret("prof1", 1100)
	if !ok || !bytes.Equal(retrieved, secret) {
		t.Fatalf("expected secret %s, got %s", secret, retrieved)
	}

	if vault.IsProfileValid("prof1", 1301) {
		t.Fatal("expected profile to be invalid at 1301")
	}

	_, ok = vault.RetrieveSecret("prof1", 1301)
	if ok {
		t.Fatal("expected retrieve secret to fail at 1301")
	}

	purged := vault.PurgeExpired(1301)
	if purged != 1 {
		t.Fatalf("expected 1 purged, got %d", purged)
	}

	if vault.IsProfileValid("prof1", 1100) {
		t.Fatal("expected profile to be deleted after purge")
	}
}
