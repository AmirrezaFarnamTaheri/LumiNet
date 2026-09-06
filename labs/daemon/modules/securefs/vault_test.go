package securefs

import (
	"bytes"
	"testing"
)

func TestVaultSetGet(t *testing.T) {
	vault, err := OpenVault("super_secret_passphrase", nil)
	if err != nil {
		t.Fatalf("failed to open vault: %v", err)
	}

	key := "wireguard_private_key"
	secretData := []byte("cAByAGkAdgBhAHQAZQBfAGsAZQB5AF8AZABhAHQAYQA=")

	if err := vault.Set(key, secretData); err != nil {
		t.Fatalf("vault Set failed: %v", err)
	}

	retrieved, err := vault.Get(key)
	if err != nil {
		t.Fatalf("vault Get failed: %v", err)
	}

	if !bytes.Equal(retrieved, secretData) {
		t.Errorf("decrypted secret mismatch. Expected %s, got %s", secretData, retrieved)
	}
}

func TestVaultInvalidKey(t *testing.T) {
	vault, err := OpenVault("passphrase", nil)
	if err != nil {
		t.Fatalf("failed to open vault: %v", err)
	}

	_, err = vault.Get("non_existent_key")
	if err == nil {
		t.Error("expected error for non-existent key, got nil")
	}
}
