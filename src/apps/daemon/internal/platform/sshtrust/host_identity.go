package sshtrust

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net"
	"strings"

	"golang.org/x/crypto/ssh"
)

// HostIdentity is a validated OpenSSH SHA-256 host-key fingerprint.
// It is intentionally small: callers provide identity, while this module owns
// parsing, canonicalization, and verification semantics.
type HostIdentity struct {
	fingerprint string
}

// ParseSHA256 validates an OpenSSH fingerprint such as SHA256:base64value.
func ParseSHA256(raw string) (HostIdentity, error) {
	value := strings.TrimSpace(raw)
	if !strings.HasPrefix(value, "SHA256:") {
		return HostIdentity{}, fmt.Errorf("SSH host key fingerprint must use SHA256: prefix")
	}
	encoded := strings.TrimPrefix(value, "SHA256:")
	if encoded == "" {
		return HostIdentity{}, fmt.Errorf("SSH host key fingerprint is empty")
	}
	digest, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil || len(digest) != 32 {
		return HostIdentity{}, fmt.Errorf("SSH host key fingerprint must contain a 32-byte SHA-256 digest")
	}
	canonical := "SHA256:" + base64.RawStdEncoding.EncodeToString(digest)
	return HostIdentity{fingerprint: canonical}, nil
}

func (h HostIdentity) String() string { return h.fingerprint }

// Callback returns the only host-key verification policy used by LumiNet SSH
// clients. Fingerprint mismatches fail before user authentication is trusted.
func (h HostIdentity) Callback() ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		got := ssh.FingerprintSHA256(key)
		if len(got) != len(h.fingerprint) || subtle.ConstantTimeCompare([]byte(got), []byte(h.fingerprint)) != 1 {
			return fmt.Errorf("SSH host key mismatch for %s: got %s, want %s", hostname, got, h.fingerprint)
		}
		return nil
	}
}
