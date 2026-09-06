//go:build !windows

package process

import "fmt"

// StartupSupported reports whether this build can mutate OS startup registration.
func StartupSupported() bool { return false }

// IsStartupEnabled is false when startup registration is unavailable.
func IsStartupEnabled() bool { return false }

// EnableStartup fails closed when startup registration is unavailable.
func EnableStartup() error {
	return fmt.Errorf("%w: startup registration", ErrUnsupportedPlatformFeature)
}

// DisableStartup fails closed when startup registration is unavailable.
func DisableStartup() error {
	return fmt.Errorf("%w: startup registration", ErrUnsupportedPlatformFeature)
}
