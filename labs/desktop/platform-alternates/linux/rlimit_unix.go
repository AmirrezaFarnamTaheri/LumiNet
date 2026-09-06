//go:build linux || darwin || freebsd || openbsd || netbsd

package linux

import (
	"fmt"
	"log/slog"
	"syscall"
)

// SetResourceLimits applies open-file and memory limits to the current process.
// Only available on Unix platforms that support RLIMIT_NOFILE and RLIMIT_AS.
func (p *PayloadEditor) SetResourceLimits(maxFiles uint64, maxMemBytes uint64) error {
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &syscall.Rlimit{Cur: maxFiles, Max: maxFiles}); err != nil {
		return fmt.Errorf("PayloadEditor.SetResourceLimits: RLIMIT_NOFILE: %w", err)
	}
	if err := syscall.Setrlimit(syscall.RLIMIT_AS, &syscall.Rlimit{Cur: maxMemBytes, Max: maxMemBytes}); err != nil {
		return fmt.Errorf("PayloadEditor.SetResourceLimits: RLIMIT_AS: %w", err)
	}
	slog.Info("PayloadEditor: resource limits applied", "max_files", maxFiles, "max_mem_bytes", maxMemBytes)
	return nil
}
