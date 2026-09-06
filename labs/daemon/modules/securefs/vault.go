package securefs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"sync"
)

// Vault represents an encrypted local key-value store using AES-256-GCM.
type Vault struct {
	mu     sync.RWMutex
	key    [32]byte
	store  map[string][]byte
}

// OpenVault derives a 256-bit key using PBKDF2 with salt and passphrase.
func OpenVault(passphrase string, salt []byte) (*Vault, error) {
	if passphrase == "" {
		return nil, errors.New("empty passphrase")
	}
	if len(salt) == 0 {
		salt = []byte("LUMINET_SECURE_FS_SALT")
	}

	derivedKey := pbkdf2.Key([]byte(passphrase), salt, 4096, 32, sha256.New)
	var keyArray [32]byte
	copy(keyArray[:], derivedKey)

	return &Vault{
		key:   keyArray,
		store: make(map[string][]byte),
	}, nil
}

// Set encrypts payload and stores it under key.
func (v *Vault) Set(key string, payload []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	block, err := aes.NewCipher(v.key[:])
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	ciphertext := gcm.Seal(nonce, nonce, payload, nil)
	v.store[key] = ciphertext
	return nil
}

// Get decrypts and returns the stored payload for key.
func (v *Vault) Get(key string) ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	ciphertext, ok := v.store[key]
	if !ok {
		return nil, errors.New("key not found in vault")
	}

	block, err := aes.NewCipher(v.key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("malformed ciphertext")
	}

	nonce, encryptedPayload := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, encryptedPayload, nil)
}
