package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type hostNetworkWatchdog struct {
	cmd      *exec.Cmd
	done     chan struct{}
	stopping atomic.Bool
	mu       sync.Mutex
	waitErr  error
}

func launchHostNetworkWatchdog(dataDir string) (*hostNetworkWatchdog, error) {
	path, err := resolveHostNetworkWatchdogPath()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(path,
		"--parent-pid", strconv.Itoa(os.Getpid()),
		"--data-dir", dataDir,
	)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = prepareWatchdogSysProcAttr()
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start host-network watchdog: %w", err)
	}

	w := &hostNetworkWatchdog{cmd: cmd, done: make(chan struct{})}
	go func() {
		err := cmd.Wait()
		w.mu.Lock()
		w.waitErr = err
		w.mu.Unlock()
		close(w.done)
	}()

	// Catch immediate startup failures before the daemon becomes reachable.
	timer := time.NewTimer(75 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-w.done:
		exitErr := w.err()
		if exitErr == nil {
			exitErr = errors.New("watchdog exited without an error")
		}
		return nil, fmt.Errorf("host-network watchdog exited during startup: %w", exitErr)
	case <-timer.C:
		return w, nil
	}
}

func resolveHostNetworkWatchdogPath() (string, error) {
	if configured := os.Getenv("LUMINET_WATCHDOG_PATH"); configured != "" {
		if _, err := os.Stat(configured); err != nil {
			return "", fmt.Errorf("configured watchdog %q is unavailable: %w", configured, err)
		}
		return configured, nil
	}

	name := "watchdog"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if executable, err := os.Executable(); err == nil {
		sibling := filepath.Join(filepath.Dir(executable), name)
		if info, statErr := os.Stat(sibling); statErr == nil && !info.IsDir() {
			return sibling, nil
		}
	}
	if path, err := exec.LookPath(name); err == nil {
		return path, nil
	}
	return "", fmt.Errorf("host-network watchdog not found; place %s beside the daemon or set LUMINET_WATCHDOG_PATH", name)
}

func monitorHostNetworkWatchdog(ctx context.Context, w *hostNetworkWatchdog, cancel context.CancelCauseFunc) {
	select {
	case <-ctx.Done():
		return
	case <-w.done:
		if w.stopping.Load() {
			return
		}
		err := w.err()
		if err == nil {
			err = errors.New("watchdog exited without an error")
		}
		cancel(fmt.Errorf("host-network watchdog exited unexpectedly: %w", err))
	}
}

func (w *hostNetworkWatchdog) Stop() error {
	if w == nil {
		return nil
	}
	w.stopping.Store(true)
	select {
	case <-w.done:
		return nil
	default:
	}
	if w.cmd != nil && w.cmd.Process != nil {
		if err := w.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return fmt.Errorf("stop host-network watchdog: %w", err)
		}
	}
	select {
	case <-w.done:
		// A forced termination normally reports a non-zero wait status; it is
		// expected because ownership was explicitly transferred back to parent.
		return nil
	case <-time.After(2 * time.Second):
		return errors.New("timed out waiting for host-network watchdog to stop")
	}
}

func (w *hostNetworkWatchdog) err() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.waitErr
}
