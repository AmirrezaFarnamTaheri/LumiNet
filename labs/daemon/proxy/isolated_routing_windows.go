//go:build windows
// +build windows

package proxy

import "fmt"

func bindSocketToDevice(fd int, device string) error {
	// SO_BINDTODEVICE is not supported on Windows
	return fmt.Errorf("SO_BINDTODEVICE is not supported on Windows")
}
