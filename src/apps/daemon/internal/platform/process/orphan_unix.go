//go:build !windows

package process

import (
	"context"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
)

// probeProcessGOOS inspects /proc on Linux. Non-Linux unix falls back to `ps`.
func probeProcess(pid int) (bool, string, error) {
	cmdlineBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		if os.IsNotExist(err) {
			return false, "", nil
		}
		// darwin/bsd: fall back to ps
		return probeProcessPS(pid)
	}
	return true, trimProcArgv(string(cmdlineBytes)), nil
}

func probeProcessPS(pid int) (bool, string, error) {
	out, err := runCapture(10*time.Second, "ps", "-p", fmt.Sprint(pid), "-o", "command=")
	if err != nil {
		if strings.Contains(out, "no process") || strings.TrimSpace(out) == "" {
			return false, "", nil
		}
		return false, "", err
	}
	if strings.TrimSpace(out) == "" {
		return false, "", nil
	}
	return true, out, nil
}

// killTreeGOOS kills the process group when available, else the single PID.
func killTree(ctx context.Context, pid int, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() {
		if pgid, pgErr := syscall.Getpgid(pid); pgErr == nil && pgid > 0 {
			if err := syscall.Kill(-pgid, syscall.SIGKILL); err == nil {
				done <- nil
				return
			}
		}
		done <- syscall.Kill(pid, syscall.SIGKILL)
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(timeout):
		return fmt.Errorf("kill timed out after %s", timeout)
	}
}
