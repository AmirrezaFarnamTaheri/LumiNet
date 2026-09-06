//go:build windows

package system

import "io"

func createTunDevice(name string) (io.ReadWriteCloser, error) {
	return newWintunDevice(name)
}
