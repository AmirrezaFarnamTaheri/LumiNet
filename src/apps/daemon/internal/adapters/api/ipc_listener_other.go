//go:build !windows

package api

import (
	"fmt"
	"net"
)

func listenWindowsPipe(path string) (net.Listener, error) {
	return nil, fmt.Errorf("named pipes not supported on this platform")
}
