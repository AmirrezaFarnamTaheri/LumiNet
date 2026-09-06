// Package secrets — file-based fallback secret store using AES-256-GCM encryption.
// Used on platforms without a system keychain or when keychain access fails.
//
// The encryption key is derived from machine identity (hostname+username) using HKDF-SHA256.
// This provides protection against naive file copy attacks, but does NOT replace
// a proper OS keychain on Windows, macOS, or Linux.
package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/hkdf"
)

// FileStore is the file-based fallback secret store.
// Secrets are stored as individual AES-256-GCM encrypted files in a secrets directory.
type FileStore struct {
	mu  sync.Mutex
	dir string
	key []byte // 32-byte AES key derived from machine identity
}

func (*FileStore) ProviderName() string { return "file" }
func (*FileStore) Native() bool         { return false }

// NewFileStore creates a FileStore backed by the given directory.
// The encryption key is derived using HKDF from the provided masterKey material.
func NewFileStore(dir string, masterKey []byte) (*FileStore, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("secrets/file: create dir: %w", err)
	}
	key, err := deriveKey(masterKey)
	if err != nil {
		return nil, err
	}
	return &FileStore{dir: dir, key: key}, nil
}

func (s *FileStore) Put(_ context.Context, ref string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	encrypted, err := s.encrypt(value)
	if err != nil {
		return fmt.Errorf("secrets/file: encrypt %q: %w", ref, err)
	}

	data, _ := json.Marshal(struct {
		Ref  string `json:"ref"`
		Data []byte `json:"data"`
	}{Ref: ref, Data: encrypted})

	path := s.refPath(ref)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("secrets/file: write %q: %w", ref, err)
	}
	return nil
}

func (s *FileStore) Get(_ context.Context, ref string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := s.refPath(ref)
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound{Ref: ref}
		}
		return nil, fmt.Errorf("secrets/file: read %q: %w", ref, err)
	}

	var stored struct {
		Ref  string `json:"ref"`
		Data []byte `json:"data"`
	}
	if err := json.Unmarshal(raw, &stored); err != nil {
		return nil, fmt.Errorf("secrets/file: unmarshal %q: %w", ref, err)
	}

	plaintext, err := s.decrypt(stored.Data)
	if err != nil {
		return nil, fmt.Errorf("secrets/file: decrypt %q: %w", ref, err)
	}
	return plaintext, nil
}

func (s *FileStore) Delete(_ context.Context, ref string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := s.refPath(ref)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("secrets/file: delete %q: %w", ref, err)
	}
	return nil
}

func (s *FileStore) List(_ context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("secrets/file: list dir: %w", err)
	}

	var refs []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sec") {
			refs = append(refs, strings.TrimSuffix(e.Name(), ".sec"))
		}
	}
	return refs, nil
}

// refPath converts a secret ref to a safe filename.
func (s *FileStore) refPath(ref string) string {
	safe := strings.ReplaceAll(ref, "/", "_")
	safe = strings.ReplaceAll(safe, "\\", "_")
	return filepath.Join(s.dir, safe+".sec")
}

// encrypt encrypts plaintext using AES-256-GCM with a random nonce.
// Output: [nonce:12][ciphertext+tag]
func (s *FileStore) encrypt(plaintext []byte) ([]byte, error) {
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
	sealed := gcm.Seal(nonce, nonce, plaintext, nil)
	return sealed, nil
}

// decrypt decrypts ciphertext produced by encrypt.
func (s *FileStore) decrypt(ciphertext []byte) ([]byte, error) {
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
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ct, nil)
}

// deriveKey derives a 32-byte AES key from master key material using HKDF-SHA256.
func deriveKey(masterKey []byte) ([]byte, error) {
	h := hkdf.New(sha256.New, masterKey, []byte("luminet-secrets-v1"), []byte("aes-256-gcm"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, fmt.Errorf("secrets/file: derive key: %w", err)
	}
	return key, nil
}
