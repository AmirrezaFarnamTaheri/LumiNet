
package system

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

// ArgoTunnel manages the lifecycle of a cloudflared Argo tunnel daemon.
type ArgoTunnel struct {
	Token      string // Argo tunnel token
	LocalPort  int    // Local port to expose (e.g. 8080)
	cmd        *exec.Cmd
	cancelFunc context.CancelFunc
}

// NewArgoTunnel creates a new tunnel orchestrator.
func NewArgoTunnel(token string, localPort int) *ArgoTunnel {
	return &ArgoTunnel{
		Token:     token,
		LocalPort: localPort,
	}
}

// Start spawns the cloudflared daemon in the background.
func (t *ArgoTunnel) Start() error {
	if t.cmd != nil {
		return errors.New("argo_tunnel: tunnel already running")
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.cancelFunc = cancel

	// Command: cloudflared tunnel --no-autoupdate run --token [token]
	// Or exposing local port: cloudflared tunnel --url http://localhost:[port]
	var args []string
	if t.Token != "" {
		args = []string{"tunnel", "--no-autoupdate", "run", "--token", t.Token}
	} else {
		// Quick tunnel mode
		args = []string{"tunnel", "--url", fmt.Sprintf("http://localhost:%d", t.LocalPort)}
	}

	t.cmd = exec.CommandContext(ctx, "cloudflared", args...)

	// Spawn the daemon
	err := t.cmd.Start()
	if err != nil {
		cancel()
		t.cmd = nil
		return fmt.Errorf("argo_tunnel: failed to start cloudflared: %w", err)
	}

	return nil
}

// Stop gracefully kills the cloudflared process.
func (t *ArgoTunnel) Stop() error {
	if t.cmd == nil {
		return nil
	}
	if t.cancelFunc != nil {
		t.cancelFunc()
	}

	// Wait for process to exit or kill it
	done := make(chan error, 1)
	go func() {
		done <- t.cmd.Wait()
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = t.cmd.Process.Kill()
	}

	t.cmd = nil
	return nil
}
