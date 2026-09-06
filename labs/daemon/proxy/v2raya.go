// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: v2rayA-main
// Target path: server/internal/proxy/v2raya.go

package proxy

import (
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/exec"
	"sync"
)

// V2rayA represents the v2rayA web GUI client orchestrator.
type V2rayA struct {
	mu          sync.Mutex
	cmd         *exec.Cmd
	Address     string
	Port        int
	ConfigDir   string
	RoutingMode string // "rule", "global", "direct"
}

// NewV2rayA instantiates a v2rayA controller.
func NewV2rayA() *V2rayA {
	return &V2rayA{
		Address:     "127.0.0.1",
		Port:        2017,
		ConfigDir:   "/etc/v2raya",
		RoutingMode: "rule",
	}
}

// Start launches the v2rayA backend service process.
func (va *V2rayA) Start(binaryPath string) error {
	va.mu.Lock()
	defer va.mu.Unlock()

	if va.cmd != nil && va.cmd.Process != nil {
		return fmt.Errorf("v2rayA service already running")
	}

	// Prepare directories
	_ = os.MkdirAll(va.ConfigDir, 0755)

	args := []string{
		"--address", va.Address,
		"--port", fmt.Sprintf("%d", va.Port),
		"--config", va.ConfigDir,
	}

	cmd := exec.Command(binaryPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Set environmental controls
	cmd.Env = append(os.Environ(),
		"V2RAYA_LOG_FILE=/dev/null",
	)

	if err := cmd.Start(); err != nil {
		return err
	}

	va.cmd = cmd
	log.Printf("v2rayA service started on %s:%d", va.Address, va.Port)
	return nil
}

// Stop terminates the running v2rayA service.
func (va *V2rayA) Stop() error {
	va.mu.Lock()
	defer va.mu.Unlock()

	if va.cmd == nil || va.cmd.Process == nil {
		return nil
	}

	err := va.cmd.Process.Kill()
	_, _ = va.cmd.Process.Wait()
	va.cmd = nil
	slog.Info("v2rayA service stopped")
	return err
}

// Configure applies runtime orchestration settings.
func (va *V2rayA) Configure(address string, port int, routingMode string) {
	va.mu.Lock()
	defer va.mu.Unlock()
	va.Address = address
	va.Port = port
	va.RoutingMode = routingMode
}
