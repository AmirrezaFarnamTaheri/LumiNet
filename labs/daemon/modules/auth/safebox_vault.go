package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
)

// SafeboxVault stores and encrypts credentials.
type SafeboxVault struct {
	key []byte // 32-byte AES key
}

// NewSafeboxVault creates a new SafeboxVault with a 32-byte key.
func NewSafeboxVault(key []byte) (*SafeboxVault, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be exactly 32 bytes for AES-256")
	}
	return &SafeboxVault{key: key}, nil
}

// Encrypt encrypts a plaintext byte slice using AES-256-GCM.
func (s *SafeboxVault) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
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

	// Ciphertext layout: [nonce][encrypted_payload]
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts an AES-256-GCM ciphertext.
func (s *SafeboxVault) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, encryptedPayload := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, encryptedPayload, nil)
}

// EncryptJSON serializes and encrypts any data structure.
func (s *SafeboxVault) EncryptJSON(data interface{}) ([]byte, error) {
	plaintext, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return s.Encrypt(plaintext)
}

// DecryptJSON decrypts and deserializes ciphertext into a target interface.
func (s *SafeboxVault) DecryptJSON(ciphertext []byte, target interface{}) error {
	plaintext, err := s.Decrypt(ciphertext)
	if err != nil {
		return err
	}
	return json.Unmarshal(plaintext, target)
}
