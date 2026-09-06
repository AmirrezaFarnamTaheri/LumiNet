//go:build !windows

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
)

var (
	keyOnce sync.Once
	key     []byte
	keyErr  error
)

func getOrCreateKey() ([]byte, error) {
	keyOnce.Do(func() {
		home, err := os.UserHomeDir()
		if err != nil {
			keyErr = err
			return
		}
		key, keyErr = loadOrCreateNonWindowsKey(filepath.Join(home, ".luminet"), IsTPMAvailable(), UnsealKeyFromTPM)
	})

	return key, keyErr
}

// Encrypt encrypts data using AES-GCM with a persistent local key.
func Encrypt(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	k, err := getOrCreateKey()
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Seal appends the ciphertext to nonce
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// Decrypt decrypts data using AES-GCM with a persistent local key.
func Decrypt(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	k, err := getOrCreateKey()
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
