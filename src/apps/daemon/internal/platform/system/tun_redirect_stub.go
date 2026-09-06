//go:build !windows

package system

import "context"

func ConfigureWindowsTUNRedirect(ctx context.Context, tunInterfaceName string, gatewayIP string, remoteServerIP string, dnsServerIP string) error {
	return nil
}

func ClearWindowsTUNRedirect(ctx context.Context, tunInterfaceName string, remoteServerIP string) error {
	return nil
}
