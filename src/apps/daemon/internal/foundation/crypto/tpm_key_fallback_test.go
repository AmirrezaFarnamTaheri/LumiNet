package crypto

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestNonWindowsTPMFailureNeverCreatesPlaintextFallback(t *testing.T) {
	dir := t.TempDir()
	_, err := loadOrCreateNonWindowsKey(dir, true, func([]byte, []byte) ([]byte, error) {
		return nil, errors.New("unseal should not run without a complete legacy pair")
	})
	if !errors.Is(err, ErrTPMKeyMigrationRequired) {
		t.Fatalf("error = %v, want ErrTPMKeyMigrationRequired", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "crypto.key")); !os.IsNotExist(err) {
		t.Fatalf("plaintext fallback was created: %v", err)
	}
}

func TestNonWindowsTPMOutageNeverDowngradesExistingTPMState(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "crypto.pub"), []byte("legacy"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := loadOrCreateNonWindowsKey(dir, false, UnsealKeyFromTPM)
	if !errors.Is(err, ErrTPMKeyMigrationRequired) {
		t.Fatalf("error = %v, want ErrTPMKeyMigrationRequired", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "crypto.key")); !os.IsNotExist(err) {
		t.Fatalf("plaintext fallback was created during TPM outage: %v", err)
	}
}

func TestNonWindowsCorruptTPMBlobPathNeverCreatesPlaintextFallback(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "crypto.pub"), 0700); err != nil {
		t.Fatal(err)
	}
	_, err := loadOrCreateNonWindowsKey(dir, false, UnsealKeyFromTPM)
	if !errors.Is(err, ErrTPMKeyMigrationRequired) {
		t.Fatalf("error = %v, want ErrTPMKeyMigrationRequired", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "crypto.key")); !os.IsNotExist(err) {
		t.Fatalf("plaintext fallback was created for corrupt TPM state: %v", err)
	}
}
