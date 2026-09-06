// Package secrets provides a platform-abstracted secret storage interface.
//
// Addresses S-06: DDNS Credential Blast Radius.
// Secrets (API tokens, DDNS keys, node keys) must be stored in the OS keychain,
// not in config JSON or SQLite plaintext. SQLite stores only a SecretRef.
//
// Platform status:
//   - Windows: DPAPI (Data Protection API)
//   - macOS: Keychain Services (requires a cgo-enabled macOS build)
//   - Linux: login-session Secret Service over D-Bus
//   - FileStore: explicit development or recovery use only
package secrets

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// Store is the interface for secret storage.
// All implementations must be safe for concurrent use.
type Store interface {
	// Put stores a named secret value. Overwrites existing entries.
	Put(ctx context.Context, ref string, value []byte) error
	// Get retrieves a named secret value. Returns ErrNotFound if ref is absent.
	Get(ctx context.Context, ref string) ([]byte, error)
	// Delete removes a named secret. No-ops if ref is absent.
	Delete(ctx context.Context, ref string) error
	// List returns all stored secret refs (keys only, not values).
	List(ctx context.Context) ([]string, error)
}

// ProviderStore exposes the stable provider identity used by persisted SecretRef
// values. Provider names are part of the security boundary and are not advisory.
type ProviderStore interface {
	Store
	ProviderName() string
}

// NativeStore identifies providers that can truthfully assert OS-backed storage.
// FileStore implements this interface with Native returning false so development
// and recovery code can still enforce exact provider identity.
type NativeStore interface {
	ProviderStore
	Native() bool
}

// SecretRef is a storable reference to a secret held in the OS keychain.
// Only the ref is persisted in SQLite/config — never the plaintext value.
type SecretRef struct {
	// Provider identifies the keychain backend (e.g., "dpapi", "keychain", "secretservice", "file")
	Provider string `json:"provider"`
	// Ref is the unique key used to retrieve the secret from the backend.
	Ref string `json:"ref"`
}

// DDNSConfig with redacted token stored via SecretRef (not inline string).
// Addresses S-06.
type DDNSConfig struct {
	Enabled  bool      `json:"enabled"`
	Provider string    `json:"provider"`
	Domain   string    `json:"domain"`
	TokenRef SecretRef `json:"token_ref"`
	Interval int       `json:"interval_minutes"`
}

// ErrNotFound is returned when a referenced secret does not exist in the store.
type ErrNotFound struct{ Ref string }

func (e ErrNotFound) Error() string { return "secrets: ref not found: " + e.Ref }

// ErrNativeStoreUnavailable is returned when the current target has no
// production-qualified native provider implementation.
var ErrNativeStoreUnavailable = errors.New("native secret store unavailable")

// ValidateStoreRef enforces the persisted provider/ref binding before any store
// mutation or read. Production callers additionally require a native backend.
func ValidateStoreRef(store Store, ref SecretRef, requireNative bool) error {
	if store == nil {
		return errors.New("secret store is required")
	}
	if ref.Provider == "" || ref.Ref == "" {
		return errors.New("secret provider and reference are required")
	}
	providerStore, ok := store.(ProviderStore)
	if !ok {
		return errors.New("secret store does not expose a provider identity")
	}
	if providerStore.ProviderName() != ref.Provider {
		return fmt.Errorf("secret provider mismatch: record requires %q, store is %q", ref.Provider, providerStore.ProviderName())
	}
	if requireNative {
		native, ok := store.(NativeStore)
		if !ok || !native.Native() {
			return fmt.Errorf("%w: provider %q is not native", ErrNativeStoreUnavailable, providerStore.ProviderName())
		}
	}
	return nil
}

func validNativeRef(ref string) error {
	if ref == "" || strings.IndexByte(ref, 0) >= 0 {
		return errors.New("secrets: reference is required")
	}
	return nil
}

var defaultStore Store
var defaultStoreMu sync.RWMutex

func Register(s Store) {
	defaultStoreMu.Lock()
	defer defaultStoreMu.Unlock()
	defaultStore = s
}

func GetStore() Store {
	defaultStoreMu.RLock()
	defer defaultStoreMu.RUnlock()
	return defaultStore
}

// OpenNativeStore opens the native provider selected by mutually exclusive
// platform build tags. It never falls back to FileStore.
func OpenNativeStore() (NativeStore, error) {
	return newPlatformStore()
}

func init() {
	if store, err := OpenNativeStore(); err == nil {
		Register(store)
	}
}
