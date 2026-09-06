// Package mobilehost owns mobile-host callbacks that must be shared by the
// runtime without making the gobind adapter a runtime-state owner.
package mobilehost

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"syscall"
	"time"
)

// SocketProtector exempts sockets from mobile VPN routing loops.
type SocketProtector interface {
	Protect(fd int) bool
}

// ProcessFinder resolves a mobile connection to its owning process UID.
type ProcessFinder interface {
	FindProcessByConnection(network, srcIP string, srcPort int, destIP string, destPort int) int
}

var (
	protectorMu sync.RWMutex
	protector   SocketProtector
	finderMu    sync.RWMutex
	finder      ProcessFinder
)

// RegisterSocketProtector installs the current mobile host socket callback.
func RegisterSocketProtector(p SocketProtector) {
	protectorMu.Lock()
	protector = p
	protectorMu.Unlock()
	slog.Info("Android socket protector registered successfully")
}

// ProtectSocket asks the current mobile host to exempt fd from VPN routing.
func ProtectSocket(fd int) bool {
	protectorMu.RLock()
	p := protector
	protectorMu.RUnlock()
	return p != nil && p.Protect(fd)
}

// RegisterProcessFinder installs the current mobile host process lookup callback.
func RegisterProcessFinder(p ProcessFinder) {
	finderMu.Lock()
	finder = p
	finderMu.Unlock()
}

// FindProcessConnection returns the owning UID or -1 when no finder is installed.
func FindProcessConnection(network, srcIP string, srcPort int, destIP string, destPort int) int {
	finderMu.RLock()
	p := finder
	finderMu.RUnlock()
	if p == nil {
		return -1
	}
	return p.FindProcessByConnection(network, srcIP, srcPort, destIP, destPort)
}

// Dialer returns a net.Dialer that protects every created socket through the mobile host.
func Dialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout: timeout,
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				ProtectSocket(int(fd))
			})
		},
	}
}

// Dial uses the protected dialer with a background lifetime.
func Dial(network, address string, timeout time.Duration) (net.Conn, error) {
	return DialContext(context.Background(), network, address, timeout)
}

// DialContext uses the protected dialer and caller-owned cancellation.
func DialContext(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	return Dialer(timeout).DialContext(ctx, network, address)
}
