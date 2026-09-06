//go:build !android && !ios

package api

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"time"
)

type IpcListener struct {
	listener net.Listener
	path     string
}

// NewIpcListener creates a new secure local domain socket listener.
func NewIpcListener(path string) (*IpcListener, error) {
	if runtime.GOOS == "windows" {
		// On Windows, use named pipes or local loopback connection security
		// Windows named pipes prefix is standard \\.\pipe\
		pipePath := `\\.\pipe\` + path
		l, err := listenWindowsPipe(pipePath)
		if err != nil {
			return nil, fmt.Errorf("failed to start Windows named pipe listener: %w", err)
		}
		return &IpcListener{listener: l, path: pipePath}, nil
	}

	// Clean up stale Unix domain socket files
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to remove stale unix socket file: %w", err)
	}

	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("failed to start unix domain socket listener: %w", err)
	}

	// Restrict file permissions: Read/Write strictly for the owner (0600)
	if err := os.Chmod(path, 0600); err != nil {
		l.Close()
		return nil, fmt.Errorf("failed to restrict unix socket file permissions: %w", err)
	}

	return &IpcListener{listener: l, path: path}, nil
}

func (i *IpcListener) AcceptLoop(ctx context.Context, handler func(net.Conn)) {
	for {
		conn, err := i.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				timeSleepMs(100)
				continue
			}
		}
		go handler(conn)
	}
}

func (i *IpcListener) Close() error {
	if i.listener != nil {
		err := i.listener.Close()
		if runtime.GOOS != "windows" {
			_ = os.Remove(i.path)
		}
		return err
	}
	return nil
}

func timeSleepMs(ms int) {
	time.Sleep(time.Duration(ms) * time.Millisecond)
}
