//go:build linux

package proxy

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type linuxSystemdManager struct{}

func newPlatformSystemdManager() SystemdManager {
	return &linuxSystemdManager{}
}

func (m *linuxSystemdManager) InstallService(ctx context.Context, s *SystemdService) error {
	if s.Name == "" {
		return fmt.Errorf("service name cannot be empty")
	}

	content := s.GenerateUnit()
	path := filepath.Join("/etc/systemd/system", fmt.Sprintf("%s.service", s.Name))

	// Write systemd unit file
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write systemd unit file %s: %w", path, err)
	}

	// Reload daemon
	cmdReload := exec.CommandContext(ctx, "systemctl", "daemon-reload")
	if out, err := cmdReload.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to reload systemd daemon: %w (%s)", err, strings.TrimSpace(string(out)))
	}

	// Enable service
	cmdEnable := exec.CommandContext(ctx, "systemctl", "enable", s.Name)
	if out, err := cmdEnable.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to enable service %s: %w (%s)", s.Name, err, strings.TrimSpace(string(out)))
	}

	// Start service
	cmdStart := exec.CommandContext(ctx, "systemctl", "start", s.Name)
	if out, err := cmdStart.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to start service %s: %w (%s)", s.Name, err, strings.TrimSpace(string(out)))
	}

	return nil
}

func (m *linuxSystemdManager) UninstallService(ctx context.Context, name string) error {
	if name == "" {
		return fmt.Errorf("service name cannot be empty")
	}

	path := filepath.Join("/etc/systemd/system", fmt.Sprintf("%s.service", name))

	// Stop service (ignore errors if it wasn't running)
	_ = exec.CommandContext(ctx, "systemctl", "stop", name).Run()

	// Disable service (ignore errors)
	_ = exec.CommandContext(ctx, "systemctl", "disable", name).Run()

	// Remove file
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove systemd file %s: %w", path, err)
	}

	// Reload daemon
	_ = exec.CommandContext(ctx, "systemctl", "daemon-reload").Run()

	return nil
}
