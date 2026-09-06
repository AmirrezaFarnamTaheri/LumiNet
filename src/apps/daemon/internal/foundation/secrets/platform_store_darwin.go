//go:build darwin && !cgo

package secrets

import "fmt"

// A macOS build without cgo cannot link Security.framework. Returning
// unavailable is intentional: production must not silently downgrade to
// machine-derived file encryption.
func newPlatformStore() (NativeStore, error) {
	return nil, fmt.Errorf("%w: macOS Keychain provider requires cgo", ErrNativeStoreUnavailable)
}
