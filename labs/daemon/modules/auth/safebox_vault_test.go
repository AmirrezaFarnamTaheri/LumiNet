package auth

import (
	"bytes"
	"testing"
)

type TestSecretConfig struct {
	APIKey   string            `json:"api_key"`
	Metadata map[string]string `json:"metadata"`
}

func TestSafeboxVault(t *testing.T) {
	key := []byte("thisisa32bytekeyforaes256gcm1234") // 32 bytes

	vault, err := NewSafeboxVault(key)
	if err != nil {
		t.Fatalf("failed to create vault: %v", err)
	}

	plaintext := []byte("highly-sensitive-secret-credentials")
	ciphertext, err := vault.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	decrypted, err := vault.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("failed to decrypt: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted output does not match plaintext. Got: %s, Want: %s", decrypted, plaintext)
	}

	// Test corrupted ciphertext
	corrupted := make([]byte, len(ciphertext))
	copy(corrupted, ciphertext)
	corrupted[len(corrupted)-1] ^= 0xFF // Flip last bit

	_, err = vault.Decrypt(corrupted)
	if err == nil {
		t.Error("expected decryption of corrupted ciphertext to fail")
	}

	// Test JSON encryption/decryption
	originalConfig := TestSecretConfig{
		APIKey: "supersecretkey123",
		Metadata: map[string]string{
			"env": "production",
		},
	}

	cipherJSON, err := vault.EncryptJSON(originalConfig)
	if err != nil {
		t.Fatalf("failed to encrypt JSON: %v", err)
	}

	var decryptedConfig TestSecretConfig
	err = vault.DecryptJSON(cipherJSON, &decryptedConfig)
	if err != nil {
		t.Fatalf("failed to decrypt JSON: %v", err)
	}

	if decryptedConfig.APIKey != originalConfig.APIKey {
		t.Errorf("APIKey mismatch. Got: %s, Want: %s", decryptedConfig.APIKey, originalConfig.APIKey)
	}

	if decryptedConfig.Metadata["env"] != "production" {
		t.Errorf("Metadata mismatch. Got: %s, Want: production", decryptedConfig.Metadata["env"])
	}
}
