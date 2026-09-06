//go:build !linux && !android

package netutil

import (
	"context"
	"net"
)

// setSocketMark is a no-op on non-Linux platforms. SO_MARK is Linux/Android-only.
func setSocketMark(fd uintptr, mark int) error {
	return nil
}

// LinuxSocketTagger is a no-op dialer on non-Linux platforms.
// On Linux/Android it applies SO_MARK; here it dials without modification.
type LinuxSocketTagger struct {
	Mark int
}

// DialContext dials network+address without socket mark (no-op on this platform).
func (t *LinuxSocketTagger) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := &net.Dialer{}
	return dialer.DialContext(ctx, network, address)
}
