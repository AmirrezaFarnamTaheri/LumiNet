//go:build !windows

package api

import (
	"fmt"
	"net"
	"os"
)

const defaultSocketPath = "/tmp/luminet-daemon.sock"

type UnixIPCListener struct {
	listener *net.UnixListener
	sockPath string
}

func NewIPCListener(sockPath string) (IPCListener, error) {
	if sockPath == "" {
		sockPath = defaultSocketPath
	}
	os.Remove(sockPath) // clean up stale socket
	addr, err := net.ResolveUnixAddr("unix", sockPath)
	if err != nil {
		return nil, err
	}
	l, err := net.ListenUnix("unix", addr)
	if err != nil {
		return nil, fmt.Errorf("ipc: listen unix %s: %w", sockPath, err)
	}
	l.SetUnlinkOnClose(true)
	os.Chmod(sockPath, 0600) // owner-only access
	return &UnixIPCListener{listener: l, sockPath: sockPath}, nil
}

func (l *UnixIPCListener) Accept() (net.Conn, error) { return l.listener.Accept() }
func (l *UnixIPCListener) Addr() string              { return l.sockPath }
func (l *UnixIPCListener) Close() error              { return l.listener.Close() }
