//go:build !windows

package system

import "errors"

// SetSystemProxy stub for non-Windows platforms.
func SetSystemProxy(proxyServer string, bypassList string) error {
	return errors.New("system proxy configuration via WinINet is only supported on Windows")
}
