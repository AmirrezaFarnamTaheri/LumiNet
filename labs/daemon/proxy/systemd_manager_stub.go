//go:build !linux

package proxy

import (
	"context"
	"fmt"
)

type stubSystemdManager struct{}

func newPlatformSystemdManager() SystemdManager {
	return &stubSystemdManager{}
}

func (m *stubSystemdManager) InstallService(ctx context.Context, service *SystemdService) error {
	return fmt.Errorf("systemd is only supported on Linux")
}

func (m *stubSystemdManager) UninstallService(ctx context.Context, name string) error {
	return fmt.Errorf("systemd is only supported on Linux")
}
