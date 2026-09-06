//go:build !windows

package system

import (
	"context"
	"fmt"
)

// DNSLeakProtectionSupported reports whether this build can activate DNS leak protection.
func DNSLeakProtectionSupported() bool { return false }

// EnableDnsLeakProtection fails closed when no platform implementation exists.
func EnableDnsLeakProtection(context.Context, string) error {
	return fmt.Errorf("%w: DNS leak protection", ErrUnsupportedPlatformFeature)
}

// DisableDnsLeakProtection is idempotent when protection was never available.
func DisableDnsLeakProtection(context.Context) error { return nil }
