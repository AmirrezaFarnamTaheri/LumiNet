//go:build windows

package api

import (
	"net"

	"github.com/Microsoft/go-winio"
)

func listenWindowsPipe(path string) (net.Listener, error) {
	return winio.ListenPipe(path, nil)
}
