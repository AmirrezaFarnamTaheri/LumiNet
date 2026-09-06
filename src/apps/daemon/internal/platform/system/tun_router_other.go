//go:build !windows

package system

import (
	"errors"
	"io"
)

func createTunDevice(name string) (io.ReadWriteCloser, error) {
	return nil, errors.New("Wintun is only supported on Windows")
}
