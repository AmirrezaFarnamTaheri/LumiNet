//go:build windows

package process

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// runCapture executes a command and returns its combined output.
func runCapture(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var sink bytes.Buffer
	cmd.Stdout = &sink
	cmd.Stderr = &sink
	err := cmd.Run()
	return sink.String(), err
}

// probeProcessWindows shells out to tasklist filtered by PID; the image name
// column doubles as the command-line marker check.
func probeProcess(pid int) (bool, string, error) {
	out, err := runCapture(10*time.Second, "tasklist", "/FI", fmt.Sprintf("PID eq %d", pid), "/FO", "CSV", "/NH")
	if err != nil {
		if strings.Contains(out, "INFO: No tasks") {
			return false, "", nil
		}
		return false, "", err
	}
	trimmed := strings.TrimSpace(out)
	if trimmed == "" || strings.Contains(trimmed, "INFO: No tasks") {
		return false, "", nil
	}
	return true, trimmed, nil
}

// killTreeWindows terminates the PID tree with taskkill /T /F.
func killTree(ctx context.Context, pid int, timeout time.Duration) error {
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, "taskkill", "/F", "/T", "/PID", fmt.Sprint(pid))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("taskkill: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
