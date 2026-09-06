//go:build linux || darwin
// +build linux darwin

package proxy

import (
	"fmt"
	"syscall"
)

const soBindToDevice = 25 // syscall.SO_BINDTODEVICE on Linux

func bindSocketToDevice(fd int, device string) error {
	// Apply socket option for SO_BINDTODEVICE
	err := syscall.SetsockoptString(fd, syscall.SOL_SOCKET, soBindToDevice, device)
	if err != nil {
		return fmt.Errorf("failed to bind socket to device: %w", err)
	}
	return nil
}
