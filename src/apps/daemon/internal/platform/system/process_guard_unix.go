//go:build !windows

package system

import (
	"log/slog"
	"os/exec"
)

// ChildProcessGuard is a no-op on non-Windows platforms.
// On Windows it uses a Job Object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.
type ChildProcessGuard struct{}

// NewChildProcessGuard creates a no-op guard on non-Windows platforms.
func NewChildProcessGuard(log *slog.Logger) *ChildProcessGuard {
	_ = log
	return &ChildProcessGuard{}
}

// Adopt is a no-op on non-Windows platforms.
func (g *ChildProcessGuard) Adopt(cmd *exec.Cmd) error {
	return nil
}

// Close is a no-op on non-Windows platforms.
func (g *ChildProcessGuard) Close() error {
	return nil
}
