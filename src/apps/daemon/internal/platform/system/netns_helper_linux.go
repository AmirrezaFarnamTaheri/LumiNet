//go:build linux

// Package system handles platform-specific parameters, routing, and cert configurations.

package system

import (
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

func switchToNamespaceImpl(name string) error {
	path := formatNamespacePath(name)
	fd, err := os.Open(path)
	if err != nil {
		// Fallback to /var/run/netns
		path = fmt.Sprintf("/var/run/netns/%s", name)
		fd, err = os.Open(path)
		if err != nil {
			return fmt.Errorf("failed to open namespace path: %w", err)
		}
	}
	defer fd.Close()

	// Lock OS thread since Setns changes thread-level namespaces
	runtime.LockOSThread()
	// Note: We deliberately don't UnlockOSThread here because the thread namespace is altered permanently.

	err = unix.Setns(int(fd.Fd()), unix.CLONE_NEWNET)
	if err != nil {
		return fmt.Errorf("setns failed for CLONE_NEWNET: %w", err)
	}

	return nil
}
