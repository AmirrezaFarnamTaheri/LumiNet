//go:build linux || darwin
// +build linux darwin

package system

import (
	"net"
	"syscall"
)

func remapStdinPlatform(fd uintptr) error {
	return syscall.Dup2(int(fd), int(syscall.Stdin))
}

func netListenSocks(network, address string) (net.Listener, error) {
	return net.Listen(network, address)
}
