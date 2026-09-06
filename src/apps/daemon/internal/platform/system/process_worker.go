
package system

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
)

// ProcessWorker supervises background proxy processes (e.g. xray, sing-box).
type ProcessWorker struct {
	BinaryPath string
	Args       []string
	mu         sync.Mutex
	cmd        *exec.Cmd
	cancel     context.CancelFunc
	active     bool
	LogChan    chan string
}

// NewProcessWorker creates a new worker instance.
func NewProcessWorker(bin string, args []string) *ProcessWorker {
	return &ProcessWorker{
		BinaryPath: bin,
		Args:       args,
		LogChan:    make(chan string, 100),
	}
}

// Start spawns the process and monitors its output in the background.
func (w *ProcessWorker) Start() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.active {
		return errors.New("process_worker: already running")
	}

	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel

	w.cmd = exec.CommandContext(ctx, w.BinaryPath, w.Args...)

	stdout, err := w.cmd.StdoutPipe()
	if err != nil {
		cancel()
		return err
	}
	stderr, err := w.cmd.StderrPipe()
	if err != nil {
		cancel()
		return err
	}

	if err := w.cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("process_worker: start failed: %w", err)
	}

	w.active = true

	// Spin off logging pipes
	go w.pipeLogs(stdout)
	go w.pipeLogs(stderr)

	// Wait monitor
	go func() {
		_ = w.cmd.Wait()
		w.mu.Lock()
		w.active = false
		w.mu.Unlock()
	}()

	return nil
}

func (w *ProcessWorker) pipeLogs(rd io.Reader) {
	scanner := bufio.NewScanner(rd)
	for scanner.Scan() {
		w.LogChan <- scanner.Text()
	}
}

// Stop terminates the supervised process.
func (w *ProcessWorker) Stop() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.active {
		return nil
	}

	if w.cancel != nil {
		w.cancel()
	}

	w.active = false
	return nil
}

// IsRunning returns true if the process is active.
func (w *ProcessWorker) IsRunning() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.active
}
