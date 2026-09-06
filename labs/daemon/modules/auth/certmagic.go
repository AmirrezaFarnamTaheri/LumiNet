// Package auth provides ACME TLS certificate file-locking and local storage operations.
//
// Ported from certmagic-master (storage.go):
// - File-based distributed lock implementation with heartbeat timestamps
// - Key-value storage interface for TLS certificate assets
// - Stale lock detection with configurable TTL
// - Atomic cert store/load with byte-level validation
package auth

import (
	"context"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/maybeknott/luminet/internal/certs"
)

// CertKeyPrefix is the storage key prefix for all certificate data.
const CertKeyPrefix = "certificates"

// LockStaleDuration is the maximum age of a lock file before it is
// considered stale and may be broken by another process.
const LockStaleDuration = 5 * time.Minute

// LockHeartbeatInterval is how often a lock holder must renew its timestamp.
const LockHeartbeatInterval = 30 * time.Second

// ErrLockTimeout is returned when a lock cannot be acquired within the deadline.
var ErrLockTimeout = certs.ErrLockTimeout

// CertKeyInfo describes a key stored in the cert storage backend.
type CertKeyInfo struct {
	Key        string
	Modified   time.Time
	Size       int64
	IsTerminal bool // false = directory (prefix to other keys)
}

// CertStorage is the interface that all ACME certificate storage backends must implement.
// Keys use forward slash '/' as separator with no leading or trailing slashes.
type CertStorage interface {
	// Store writes value at key, creating or overwriting the existing value.
	Store(ctx context.Context, key string, value []byte) error
	// Load retrieves the value stored at key.
	// Returns fs.ErrNotExist if key does not exist.
	Load(ctx context.Context, key string) ([]byte, error)
	// Delete removes key and any keys prefixed by it.
	Delete(ctx context.Context, key string) error
	// Exists returns true if key exists.
	Exists(ctx context.Context, key string) bool
	// List returns all keys with the given path prefix.
	List(ctx context.Context, prefix string, recursive bool) ([]string, error)
	// Stat returns metadata about key.
	Stat(ctx context.Context, key string) (CertKeyInfo, error)
	// Lock acquires a named distributed lock.
	Lock(ctx context.Context, name string) error
	// Unlock releases a previously acquired lock.
	Unlock(ctx context.Context, name string) error
}

// FileCertStorage implements CertStorage using the local filesystem.
// This is the default storage backend for development and single-node deployments.
type FileCertStorage struct {
	// Path is the root directory where all cert files are stored.
	Path    string
	storage *certs.CertMagicFileStorage
}

// NewFileCertStorage creates a new file-based cert storage rooted at the given path.
func NewFileCertStorage(basePath string) (*FileCertStorage, error) {
	if err := os.MkdirAll(basePath, 0o700); err != nil {
		return nil, fmt.Errorf("certmagic: creating storage dir %q: %w", basePath, err)
	}
	return &FileCertStorage{
		Path:    basePath,
		storage: certs.NewCertMagicFileStorage(basePath),
	}, nil
}

// Store writes value to the file at key, creating parent directories as needed.
func (s *FileCertStorage) Store(ctx context.Context, key string, value []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.storage.Store(ctx, key, value)
}

// Load reads and returns the value stored at key.
func (s *FileCertStorage) Load(ctx context.Context, key string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.storage.Load(ctx, key)
}

// Delete removes the file at key, or the directory tree if key is a prefix.
func (s *FileCertStorage) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.storage.DeletePrefix(ctx, key)
}

// Exists returns true if key corresponds to an existing file or directory.
func (s *FileCertStorage) Exists(ctx context.Context, key string) bool {
	if err := ctx.Err(); err != nil {
		return false
	}
	return s.storage.Exists(ctx, key)
}

// List returns all keys with the given prefix.
func (s *FileCertStorage) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.storage.List(ctx, prefix, recursive)
}

// Stat returns metadata about key.
func (s *FileCertStorage) Stat(ctx context.Context, key string) (CertKeyInfo, error) {
	if err := ctx.Err(); err != nil {
		return CertKeyInfo{}, err
	}
	info, err := s.storage.Stat(ctx, key)
	if os.IsNotExist(err) {
		return CertKeyInfo{}, os.ErrNotExist
	}
	if err != nil {
		return CertKeyInfo{}, err
	}
	return CertKeyInfo{
		Key:        key,
		Modified:   info.ModTime(),
		Size:       info.Size(),
		IsTerminal: !info.IsDir(),
	}, nil
}

// Lock acquires a named file lock, blocking until either the lock is obtained
// or the context is cancelled. The lock file records a heartbeat timestamp
// that is refreshed every LockHeartbeatInterval. If the timestamp is older
// than LockStaleDuration, another process may break the lock.
func (s *FileCertStorage) Lock(ctx context.Context, name string) error {
	return s.storage.Lock(ctx, path.Join("locks", name))
}

// Unlock releases the named lock and cleans up the lock file.
func (s *FileCertStorage) Unlock(ctx context.Context, name string) error {
	return s.storage.Unlock(ctx, path.Join("locks", name))
}

// CertKeyBuilder provides helper methods for constructing cert storage key paths.
type CertKeyBuilder struct{}

// CertsPrefix returns the storage key prefix for the given ACME issuer.
func (keys CertKeyBuilder) CertsPrefix(issuerKey string) string {
	return path.Join(CertKeyPrefix, keys.Safe(issuerKey))
}

// SiteCert returns the storage key for the certificate file for domain.
func (keys CertKeyBuilder) SiteCert(issuerKey, domain string) string {
	safeDomain := keys.Safe(domain)
	return path.Join(keys.CertsPrefix(issuerKey), safeDomain, safeDomain+".crt")
}

// SitePrivateKey returns the storage key for the private key file for domain.
func (keys CertKeyBuilder) SitePrivateKey(issuerKey, domain string) string {
	safeDomain := keys.Safe(domain)
	return path.Join(keys.CertsPrefix(issuerKey), safeDomain, safeDomain+".key")
}

// SiteMeta returns the storage key for the certificate metadata JSON for domain.
func (keys CertKeyBuilder) SiteMeta(issuerKey, domain string) string {
	safeDomain := keys.Safe(domain)
	return path.Join(keys.CertsPrefix(issuerKey), safeDomain, safeDomain+".json")
}

// Safe returns a filesystem-safe version of a storage key component by
// replacing characters that are problematic on various operating systems.
func (keys CertKeyBuilder) Safe(key string) string {
	// Replace wildcards and colons with filesystem-safe equivalents
	key = strings.ReplaceAll(key, "*", "_wildcard_")
	key = strings.ReplaceAll(key, ":", "_colon_")
	return key
}
