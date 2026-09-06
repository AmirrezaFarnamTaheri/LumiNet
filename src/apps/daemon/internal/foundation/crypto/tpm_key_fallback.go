package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var ErrTPMKeyMigrationRequired = errors.New("TPM-backed configuration key requires explicit envelope migration")

func loadOrCreateNonWindowsKey(dir string, tpmAvailable bool, unseal func([]byte, []byte) ([]byte, error)) ([]byte, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	pubPath := filepath.Join(dir, "crypto.pub")
	privPath := filepath.Join(dir, "crypto.priv")
	keyPath := filepath.Join(dir, "crypto.key")
	pubData, pubErr := os.ReadFile(pubPath)
	privData, privErr := os.ReadFile(privPath)
	pubMissing := errors.Is(pubErr, os.ErrNotExist)
	privMissing := errors.Is(privErr, os.ErrNotExist)
	if pubErr != nil && !pubMissing {
		return nil, fmt.Errorf("%w: read legacy public blob: %v", ErrTPMKeyMigrationRequired, pubErr)
	}
	if privErr != nil && !privMissing {
		return nil, fmt.Errorf("%w: read legacy private blob: %v", ErrTPMKeyMigrationRequired, privErr)
	}
	hasTPMState := !pubMissing || !privMissing

	if tpmAvailable || hasTPMState {
		if !tpmAvailable {
			return nil, fmt.Errorf("%w: TPM unavailable while legacy blobs exist", ErrTPMKeyMigrationRequired)
		}
		if pubErr != nil || privErr != nil {
			return nil, fmt.Errorf("%w: legacy TPM blob pair is incomplete", ErrTPMKeyMigrationRequired)
		}
		unsealedKey, err := unseal(pubData, privData)
		if err != nil {
			return nil, fmt.Errorf("%w: legacy TPM key cannot be opened: %v", ErrTPMKeyMigrationRequired, err)
		}
		if len(unsealedKey) != 32 {
			length := len(unsealedKey)
			zeroBytes(unsealedKey)
			return nil, fmt.Errorf("%w: legacy TPM key length is %d", ErrTPMKeyMigrationRequired, length)
		}
		return unsealedKey, nil
	}

	data, err := os.ReadFile(keyPath)
	if err == nil {
		if len(data) != 32 {
			return nil, fmt.Errorf("existing local configuration key has invalid length %d", len(data))
		}
		return data, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read local configuration key: %w", err)
	}
	newKey := make([]byte, 32)
	if _, err := rand.Read(newKey); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, newKey, 0600); err != nil {
		zeroBytes(newKey)
		return nil, err
	}
	return newKey, nil
}
