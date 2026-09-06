// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: x-ui-pro
// Target path: server/internal/proxy/xui_pro.go

package proxy

import (
	"context"
	"log/slog"
)

// XUIPro extends XUIPanelManager with advanced multi-inbound and fallback configurations.
type XUIPro struct {
	Manager *XUIPanelManager
}

// NewXUIPro instantiates a new XUIPro wrapper.
func NewXUIPro(dbPath string) *XUIPro {
	return &XUIPro{
		Manager: NewXUIPanelManager(dbPath),
	}
}

// ApplyAdvancedConfig configures fallback rules and port forwarding.
func (x *XUIPro) ApplyAdvancedConfig(ctx context.Context) error {
	slog.Info("XUIPro", "status", "Applying advanced multi-inbound and fallback configurations")
	return x.Manager.MigrateDatabase()
}
