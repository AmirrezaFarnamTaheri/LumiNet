//go:build windows
// +build windows

package system

import (
	"fmt"
	"net"
)

func remapStdinPlatform(fd uintptr) error {
	// syscall.Dup2 is not supported on Windows
	return fmt.Errorf("dup2 is not supported on Windows")
}

func netListenSocks(network, address string) (net.Listener, error) {
	return net.Listen(network, address)
}
