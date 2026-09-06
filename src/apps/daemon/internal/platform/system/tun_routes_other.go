//go:build !windows

package system

import (
	"context"
	"fmt"
)

// TunRoutingSupported reports whether host-route mutation is implemented.
func TunRoutingSupported() bool { return false }

func planTunRouteLease(context.Context, string, string) (*tunRouteLease, error) {
	return nil, fmt.Errorf("%w: TUN host routing", ErrUnsupportedPlatformFeature)
}
func applyTunRouteLease(context.Context, *tunRouteLease) error {
	return fmt.Errorf("%w: TUN host routing", ErrUnsupportedPlatformFeature)
}
func removeTunRouteLease(context.Context, *tunRouteLease) error { return nil }
