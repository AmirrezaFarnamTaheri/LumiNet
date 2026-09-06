package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

var (
	ErrBlankPassphrase     = errors.New("passphrase cannot be blank")
	ErrUnsupportedVersion  = errors.New("unsupported envelope version")
	ErrUnsupportedAlgo     = errors.New("unsupported envelope algorithm")
	ErrUnsupportedEncoding = errors.New("unsupported envelope encoding")
	ErrEmptyIPList         = errors.New("decrypted IP list contained no usable IPv4 addresses")
)

// EncryptedPayloadEnvelope represents the standard version-1 authenticated container.
type EncryptedPayloadEnvelope struct {
	Version    int    `json:"version"`
	Algorithm  string `json:"algorithm"`
	Encoding   string `json:"encoding"`
	IV         string `json:"iv"`
	Ciphertext string `json:"ciphertext"`
}

// DeriveKey generates a 256-bit AES key by hashing the passphrase with SHA-256.
func DeriveKey(passphrase string) ([]byte, error) {
	if strings.TrimSpace(passphrase) == "" {
		return nil, ErrBlankPassphrase
	}
	hash := sha256.Sum256([]byte(passphrase))
	key := make([]byte, 32)
	copy(key, hash[:])
	return key, nil
}

// EncryptPayload seals plaintext into an AES-256-GCM envelope serialized to JSON.
func EncryptPayload(plaintext []byte, passphrase string) (string, error) {
	key, err := DeriveKey(passphrase)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("cipher init failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gcm init failed: %w", err)
	}

	iv := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("iv generation failed: %w", err)
	}

	ciphertext := gcm.Seal(nil, iv, plaintext, nil)

	envelope := EncryptedPayloadEnvelope{
		Version:    1,
		Algorithm:  "AES-GCM",
		Encoding:   "base64url",
		IV:         base64.RawURLEncoding.EncodeToString(iv),
		Ciphertext: base64.RawURLEncoding.EncodeToString(ciphertext),
	}

	bytes, err := json.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf("json marshal failed: %w", err)
	}
	return string(bytes), nil
}

// DecryptPayload unseals an AES-256-GCM envelope JSON string.
func DecryptPayload(envelopeJSON string, passphrase string) ([]byte, error) {
	key, err := DeriveKey(passphrase)
	if err != nil {
		return nil, err
	}

	var env EncryptedPayloadEnvelope
	if err := json.Unmarshal([]byte(envelopeJSON), &env); err != nil {
		return nil, fmt.Errorf("invalid json envelope: %w", err)
	}

	if env.Version != 1 {
		return nil, fmt.Errorf("%w: expected 1, got %d", ErrUnsupportedVersion, env.Version)
	}
	if env.Algorithm != "AES-GCM" {
		return nil, fmt.Errorf("%w: expected AES-GCM, got %s", ErrUnsupportedAlgo, env.Algorithm)
	}
	if env.Encoding != "base64url" {
		return nil, fmt.Errorf("%w: expected base64url, got %s", ErrUnsupportedEncoding, env.Encoding)
	}

	iv, err := decodeBase64URL(env.IV)
	if err != nil {
		return nil, fmt.Errorf("invalid IV encoding: %w", err)
	}

	ciphertext, err := decodeBase64URL(env.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext encoding: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cipher init failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm init failed: %w", err)
	}

	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// DecryptText decodes and returns UTF-8 text from an envelope.
func DecryptText(envelopeJSON string, passphrase string) (string, error) {
	plaintext, err := DecryptPayload(envelopeJSON, passphrase)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// ParsePlaintextIPs splits whitespace-delimited IP addresses, filters valid IPv4s, and dedups.
func ParsePlaintextIPs(text string) []string {
	seen := make(map[string]bool)
	var ips []string

	fields := strings.Fields(text)
	for _, field := range fields {
		trimmed := strings.TrimSpace(field)
		ip := net.ParseIP(trimmed)
		if ip != nil && ip.To4() != nil {
			canonical := ip.To4().String()
			if !seen[canonical] {
				seen[canonical] = true
				ips = append(ips, canonical)
			}
		}
	}
	return ips
}

// EncryptIPList seals an array of IPv4 strings into an envelope.
func EncryptIPList(ips []string, passphrase string) (string, error) {
	text := strings.Join(ips, "\n")
	return EncryptPayload([]byte(text), passphrase)
}

// DecryptIPList decrypts an envelope and parses unique IPv4 strings.
func DecryptIPList(envelopeJSON string, passphrase string) ([]string, error) {
	text, err := DecryptText(envelopeJSON, passphrase)
	if err != nil {
		return nil, err
	}
	ips := ParsePlaintextIPs(text)
	if len(ips) == 0 {
		return nil, ErrEmptyIPList
	}
	return ips, nil
}

func decodeBase64URL(raw string) ([]byte, error) {
	clean := strings.TrimSpace(raw)
	// Support both unpadded and padded base64url
	if b, err := base64.RawURLEncoding.DecodeString(clean); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(clean)
}
