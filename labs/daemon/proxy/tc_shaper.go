package proxy

import (
	"context"
	"fmt"
)

// TcShaper defines the interface for Linux tc-based bandwidth limiting.
type TcShaper interface {
	LimitPort(ctx context.Context, iface string, port int, rateKbps int) error
	ClearPortLimits(ctx context.Context, iface string, port int) error
	ClearAll(ctx context.Context, iface string) error
}

// NewTcShaper returns a platform-specific TcShaper implementation.
func NewTcShaper() TcShaper {
	return newPlatformTcShaper()
}

// CheckPortRange validates if the port is a valid port.
func CheckPortRange(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port: %d", port)
	}
	return nil
}
