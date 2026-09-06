//go:build android || ios

// ipc_listener_mobile.go — IPC listener for Android and iOS.
//
// Both Android and iOS support TCP loopback (127.0.0.1) and Unix domain
// sockets within the app sandbox. We use TCP here because UDS paths are
// more restricted on iOS. The GUI (Flutter) connects to 127.0.0.1:PORT
// over localhost, with the port embedded in the path argument.
//
// On Android, the standard Unix socket path is preferred (faster, no port
// conflict). We try UDS first, then fall back to TCP loopback.
package api

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"strings"
)

// IpcListener implements the IPC listener for mobile platforms.
type IpcListener struct {
	inner net.Listener
	path  string
}

// NewIpcListener creates a mobile-compatible IPC listener.
//
// path format:
//   - "tcp:127.0.0.1:PORT" → TCP loopback (iOS + Android)
//   - "/path/to/socket"    → Unix domain socket (Android, app sandbox)
//   - ":PORT"              → TCP loopback on given port (shorthand)
func NewIpcListener(path string) (*IpcListener, error) {
	var ln net.Listener
	var err error

	switch {
	case strings.HasPrefix(path, "tcp:"):
		addr := strings.TrimPrefix(path, "tcp:")
		ln, err = net.Listen("tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("mobile IPC TCP listen %s: %w", addr, err)
		}

	case strings.HasPrefix(path, "/") && runtime.GOOS == "android":
		// Unix domain socket — available in Android app sandbox.
		ln, err = net.Listen("unix", path)
		if err != nil {
			// Fall back to TCP loopback on a fixed port.
			ln, err = net.Listen("tcp", "127.0.0.1:7777")
			if err != nil {
				return nil, fmt.Errorf("mobile IPC fallback TCP listen: %w", err)
			}
		}

	default:
		// Default: TCP loopback.
		addr := path
		if !strings.Contains(addr, ":") {
			addr = "127.0.0.1:" + addr
		}
		ln, err = net.Listen("tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("mobile IPC TCP listen %s: %w", addr, err)
		}
	}

	return &IpcListener{inner: ln, path: path}, nil
}

// AcceptLoop accepts connections and calls handler for each.
func (i *IpcListener) AcceptLoop(ctx context.Context, handler func(net.Conn)) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		conn, err := i.inner.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		go handler(conn)
	}
}

// Close closes the underlying listener.
func (i *IpcListener) Close() error {
	if i.inner != nil {
		return i.inner.Close()
	}
	return nil
}
