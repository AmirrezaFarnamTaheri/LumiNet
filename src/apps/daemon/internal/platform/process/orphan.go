// Orphan reaping for external tunnel engines.
//
// engine keeps the SOCKS port squatted. The reaper validates a pid-file against
// a live process whose command line still matches the engine binary, then
// terminates it before startup proceeds.
package process

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// PidFileReaper owns a pid-file path and an engine-name signature used to
// confirm that a found PID really is a stale engine (never an unrelated user
// process that happened to reuse the number). An empty EngineMarker disables
// command-line confirmation.
type PidFileReaper struct {
	PidFilePath  string
	EngineMarker string
	KillTimeout  time.Duration
}

// Reap removes a stale engine, returning whether it killed anything.
//
// The PID must be alive AND its command line must still carry EngineMarker;
// a recycled PID belonging to something else is left untouched.
func (r PidFileReaper) Reap(ctx context.Context) (bool, error) {
	data, err := os.ReadFile(r.PidFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("read pid file: %w", err)
	}
	pidText := strings.TrimSpace(string(data))
	pid, parseErr := strconv.Atoi(pidText)
	os.Remove(r.PidFilePath) // consumed either way; a fresh run writes anew
	if parseErr != nil || pid <= 0 {
		return false, nil
	}

	alive, cmdline, probeErr := probeProcess(pid)
	if probeErr != nil || !alive {
		return false, nil
	}
	if r.EngineMarker != "" && !strings.Contains(strings.ToLower(cmdline), strings.ToLower(r.EngineMarker)) {
		return false, nil // recycled PID: not ours
	}
	timeout := r.KillTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if err := killTree(ctx, pid, timeout); err != nil {
		return false, fmt.Errorf("kill stale engine %d: %w", pid, err)
	}
	return true, nil
}

// WritePidFile persists the current engine PID atomically enough for crash
// recovery: write-then-rename leaves no partially visible file.
func WritePidFile(path string, pid int) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.Itoa(pid)), 0o644); err != nil {
		return fmt.Errorf("write tmp pid file: %w", err)
	}
	return os.Rename(tmp, path)
}
