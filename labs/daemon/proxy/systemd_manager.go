package proxy

import (
	"context"
	"fmt"
	"strings"
)

// SystemdService defines the parameters for generating a systemd service file.
type SystemdService struct {
	Name             string
	Description      string
	ExecStart        string
	WorkingDirectory string
	Restart          string
	User             string
}

// GenerateUnit generates the contents of a systemd .service unit file.
func (s *SystemdService) GenerateUnit() string {
	var sb strings.Builder
	sb.WriteString("[Unit]\n")
	sb.WriteString(fmt.Sprintf("Description=%s\n", s.Description))
	sb.WriteString("After=network.target\n\n")

	sb.WriteString("[Service]\n")
	if s.User != "" {
		sb.WriteString(fmt.Sprintf("User=%s\n", s.User))
	}
	if s.WorkingDirectory != "" {
		sb.WriteString(fmt.Sprintf("WorkingDirectory=%s\n", s.WorkingDirectory))
	}
	sb.WriteString(fmt.Sprintf("ExecStart=%s\n", s.ExecStart))
	if s.Restart != "" {
		sb.WriteString(fmt.Sprintf("Restart=%s\n", s.Restart))
	} else {
		sb.WriteString("Restart=always\n")
	}
	sb.WriteString("RestartSec=5\n\n")

	sb.WriteString("[Install]\n")
	sb.WriteString("WantedBy=multi-user.target\n")

	return sb.String()
}

// SystemdManager manages systemd services on the host.
type SystemdManager interface {
	InstallService(ctx context.Context, service *SystemdService) error
	UninstallService(ctx context.Context, name string) error
}

// NewSystemdManager returns a platform-specific SystemdManager.
func NewSystemdManager() SystemdManager {
	return newPlatformSystemdManager()
}
