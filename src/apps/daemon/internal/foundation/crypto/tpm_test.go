package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func TestLegacyTPMSealingIsDisabled(t *testing.T) {
	_, _, err := SealKeyToTPM(make([]byte, 32))
	if !errors.Is(err, ErrLegacyTPMSealingDisabled) {
		t.Fatalf("error = %v, want ErrLegacyTPMSealingDisabled", err)
	}
}

func TestTPMPCR7PolicySealing(t *testing.T) {
	if !IsTPMAvailable() {
		t.Skip("TPM not available on this platform/device")
	}

	// 1. Generate a random 32-byte master key
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("Failed to generate random secret: %v", err)
	}

	// 2. Seal the key
	authorization := make([]byte, 32)
	if _, err := rand.Read(authorization); err != nil {
		t.Fatalf("Failed to generate TPM authorization: %v", err)
	}
	pub, priv, err := SealKeyToTPMWithAuthorization(secret, authorization)
	if err != nil {
		t.Fatalf("SealKeyToTPMWithAuthorization failed: %v", err)
	}

	if len(pub) == 0 || len(priv) == 0 {
		t.Fatalf("SealKeyToTPM returned empty blobs")
	}

	// 3. Unseal the key
	unsealed, err := UnsealKeyFromTPMWithAuthorization(pub, priv, authorization)
	if err != nil {
		t.Fatalf("UnsealKeyFromTPMWithAuthorization failed: %v", err)
	}

	if !bytes.Equal(secret, unsealed) {
		t.Fatal("Unsealed secret does not match original secret")
	}
}
