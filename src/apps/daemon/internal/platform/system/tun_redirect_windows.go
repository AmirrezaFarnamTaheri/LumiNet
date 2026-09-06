//go:build windows

package system

import (
	"context"
	"fmt"
	"os/exec"
)

// ConfigureWindowsTUNRedirect routes system outbound traffic through the virtual TUN interface.
// Prevents routing loops by adding a direct host route for the remote server IP.
func ConfigureWindowsTUNRedirect(ctx context.Context, tunInterfaceName string, gatewayIP string, remoteServerIP string, dnsServerIP string) error {
	if remoteServerIP != "" {
		cmd := exec.CommandContext(ctx, "route", "add", remoteServerIP, "mask", "255.255.255.255", gatewayIP, "metric", "1")
		if err := cmd.Run(); err != nil {
			// If route already exists, ignore or log
		}
	}

	cmd := exec.CommandContext(ctx, "netsh", "interface", "ip", "set", "interface", tunInterfaceName, "metric=1")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set TUN interface metric: %w", err)
	}

	if dnsServerIP != "" {
		cmd = exec.CommandContext(ctx, "netsh", "interface", "ip", "set", "dns", "name="+tunInterfaceName, "source=static", "address="+dnsServerIP, "register=primary")
		_ = cmd.Run()
	}

	return nil
}

// ClearWindowsTUNRedirect restores default routing parameters.
func ClearWindowsTUNRedirect(ctx context.Context, tunInterfaceName string, remoteServerIP string) error {
	if remoteServerIP != "" {
		cmd := exec.CommandContext(ctx, "route", "delete", remoteServerIP)
		_ = cmd.Run()
	}

	cmd := exec.CommandContext(ctx, "netsh", "interface", "ip", "set", "interface", tunInterfaceName, "metric=auto")
	_ = cmd.Run()

	return nil
}
