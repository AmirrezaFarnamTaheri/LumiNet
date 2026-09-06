// Package crypt1 implements the incy-link-encoder crypt1 encrypted deep-link
// share format, mirroring the TypeScript implementation in crypt1.ts.
//
// # Wire format
//
//	base64url( nonce(12) || ciphertext || authTag(16) )
//
// The nonce is generated freshly per encryption. The 32-byte key is derived
// once via SHA-256 over `<kid>::<passphrase>`. AES-256-GCM is used; the
// 128-bit authentication tag is appended to the ciphertext by Go's stdlib
// (crypto/cipher.gcm).
//
// The control-UI and the daemon must agree on this format byte-for-byte.
// Any change here MUST be accompanied by a bump in the schema version
// ("crypt2") and a corresponding update to the TS side.
package crypt1

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

const (
	nonceLen = 12
	tagLen   = 16
	keyLen   = 32
)

// Payload is the wire shape that gets URL-encoded into the `d=` parameter.
type Payload struct {
	D  string `json:"d"`  // base64url(nonce || ct || tag)
	Kid string `json:"kid"` // key-derivation identifier
	V  string `json:"v"`  // schema version, always "crypt1"
}

// Plaintext is the result of a successful Decrypt.
type Plaintext struct {
	Text string
	Kid  string
}

// Encrypt encrypts plaintext under passphrase + kid and returns the wire
// payload. Each call uses a fresh 12-byte random nonce.
func Encrypt(plaintext, passphrase, kid string) (Payload, error) {
	if passphrase == "" {
		return Payload{}, errors.New("crypt1: passphrase must not be empty")
	}
	if kid == "" {
		kid = "app"
	}
	key, err := deriveKey(passphrase, kid)
	if err != nil {
		return Payload{}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return Payload{}, fmt.Errorf("crypt1: aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Payload{}, fmt.Errorf("crypt1: cipher.NewGCM: %w", err)
	}
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return Payload{}, fmt.Errorf("crypt1: read nonce: %w", err)
	}
	ct := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	buf := make([]byte, 0, len(nonce)+len(ct))
	buf = append(buf, nonce...)
	buf = append(buf, ct...)
	return Payload{
		D:  base64.RawURLEncoding.EncodeToString(buf),
		Kid: kid,
		V:  "crypt1",
	}, nil
}

// Decrypt decrypts a Payload under the given passphrase. Returns an error
// on MAC failure, malformed input, or version mismatch.
func Decrypt(p Payload, passphrase string) (Plaintext, error) {
	if p.V != "crypt1" {
		return Plaintext{}, fmt.Errorf("crypt1: unsupported version %q", p.V)
	}
	if passphrase == "" {
		return Plaintext{}, errors.New("crypt1: passphrase must not be empty")
	}
	raw, err := base64.RawURLEncoding.DecodeString(p.D)
	if err != nil {
		return Plaintext{}, fmt.Errorf("crypt1: base64 decode: %w", err)
	}
	if len(raw) < nonceLen+tagLen {
		return Plaintext{}, errors.New("crypt1: payload too short")
	}
	key, err := deriveKey(passphrase, p.Kid)
	if err != nil {
		return Plaintext{}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return Plaintext{}, fmt.Errorf("crypt1: aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Plaintext{}, fmt.Errorf("crypt1: cipher.NewGCM: %w", err)
	}
	nonce := raw[:nonceLen]
	ct := raw[nonceLen:]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return Plaintext{}, fmt.Errorf("crypt1: auth failed: %w", err)
	}
	return Plaintext{Text: string(pt), Kid: p.Kid}, nil
}

func deriveKey(passphrase, kid string) ([]byte, error) {
	if len(passphrase) > 1024 {
		return nil, errors.New("crypt1: passphrase too long")
	}
	h := sha256.New()
	h.Write([]byte(kid))
	h.Write([]byte("::"))
	h.Write([]byte(passphrase))
	return h.Sum(nil), nil
}

// ConstantTimeEqual is a constant-time byte-slice comparison. Useful for
// callers that want to verify the kid matches without leaking the value.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ---------------------------------------------------------------------------
// Tests (table-driven, runnable with `go test ./...`).
// ---------------------------------------------------------------------------

// These tests are exported as a Test* function so they are picked up by `go test`.
// In a real project they would live in `crypt1_test.go`; we keep them here so
// the file is self-contained.
