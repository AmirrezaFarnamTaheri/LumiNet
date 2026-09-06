//go:build windows

// Package system provides Windows child process lifecycle management.
//
// ChildProcessGuard wraps a Windows Job Object configured with
// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE so that all adopted subprocesses are
// automatically terminated when the parent process exits or the guard is
// disposed — eliminating stale Wintun adapters and orphaned core daemons.
package system

import (
	"fmt"
	"log/slog"
	"os/exec"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ChildProcessGuard prevents orphaned subprocesses by binding them to a
// Windows Job Object that kills all members on close.
type ChildProcessGuard struct {
	mu         sync.Mutex
	handle     windows.Handle
	initFailed bool
	log        *slog.Logger
}

// NewChildProcessGuard creates a new guard and initialises the underlying
// Job Object. If the OS call fails the guard is returned in a degraded state:
// all AddProcess calls will silently no-op rather than returning errors.
func NewChildProcessGuard(log *slog.Logger) *ChildProcessGuard {
	g := &ChildProcessGuard{log: log}
	g.tryCreateJob()
	return g
}

func (g *ChildProcessGuard) tryCreateJob() {
	h, err := windows.CreateJobObject(nil, nil)
	if err != nil || h == 0 {
		g.log.Warn("ChildProcessGuard: CreateJobObjectW failed", "err", err)
		g.initFailed = true
		return
	}

	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE

	if _, err := windows.SetInformationJobObject(
		h,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		g.log.Warn("ChildProcessGuard: SetInformationJobObject failed", "err", err)
		_ = windows.CloseHandle(h)
		g.initFailed = true
		return
	}

	g.handle = h
	g.log.Info("ChildProcessGuard: job object created with KILL_ON_JOB_CLOSE")
}

// Adopt registers a running subprocess under the Job Object.
// If the guard failed to initialise the call is a silent no-op.
func (g *ChildProcessGuard) Adopt(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return fmt.Errorf("process not started")
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if g.initFailed || g.handle == 0 {
		return nil // degraded mode — orphan protection unavailable
	}

	hProcess, err := windows.OpenProcess(
		windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE,
		false,
		uint32(cmd.Process.Pid),
	)
	if err != nil {
		return fmt.Errorf("OpenProcess pid=%d: %w", cmd.Process.Pid, err)
	}
	defer windows.CloseHandle(hProcess)

	if err := windows.AssignProcessToJobObject(g.handle, hProcess); err != nil {
		return fmt.Errorf("AssignProcessToJobObject pid=%d: %w", cmd.Process.Pid, err)
	}

	g.log.Info("ChildProcessGuard: adopted child into kill-on-close job", "pid", cmd.Process.Pid)
	return nil
}

// Close releases the Job Object handle, terminating all adopted child processes.
func (g *ChildProcessGuard) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.handle != 0 {
		err := windows.CloseHandle(g.handle)
		g.handle = 0
		return err
	}
	return nil
}
