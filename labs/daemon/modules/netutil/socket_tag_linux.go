//go:build linux || android

package netutil

import (
	"context"
	"net"
	"syscall"
)

// setSocketMark applies SO_MARK to the socket file descriptor.
// Called by ConfigureDialerWithMark and SocketTagConfig.ApplySocketOptions.
func setSocketMark(fd uintptr, mark int) error {
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark)
}

// LinuxSocketTagger dials TCP/UDP connections with a specific SO_MARK value,
// enabling Android VPN per-app routing or Linux policy routing by fwmark.
type LinuxSocketTagger struct {
	Mark int
}

// DialContext dials network+address applying SO_MARK via kernel socket options.
func (t *LinuxSocketTagger) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := &net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				_ = setSocketMark(fd, t.Mark)
			})
		},
	}
	return dialer.DialContext(ctx, network, address)
}
