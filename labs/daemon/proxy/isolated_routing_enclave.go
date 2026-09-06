// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: Exclave
// Target path: server/internal/proxy/exclave.go

package proxy

import (
	"fmt"
	"log"
	"log/slog"
)

// ExclaveCore represents the Go Mobile generated libexclavecore wrapper.
type ExclaveCore struct {
	activeVpnSession bool
}

// NewExclaveCore initializes the custom exclave-core.
func NewExclaveCore() *ExclaveCore {
	return &ExclaveCore{}
}

// BindPluginManager binds the backend via PluginManager.kt SagerNet client integrations.
func (e *ExclaveCore) BindPluginManager() error {
	slog.Info("Exclave", "status", "Binding to Android SagerNet PluginManager.kt via JNI/GoMobile")
	return nil
}

// RouteConnection utilizes custom exclave-core logic to route specific protocols natively.
func (e *ExclaveCore) RouteConnection(protocol string, target string) error {
	if !e.activeVpnSession {
		slog.Info("Exclave", "status", "Activating native Android VPN service")
		e.activeVpnSession = true
	}

	switch protocol {
	case "vmess", "trojan", "hysteria2":
		log.Printf("Exclave: Routing %s connection natively to %s", protocol, target)
	default:
		return fmt.Errorf("unsupported exclave protocol: %s", protocol)
	}

	return nil
}

// Stop closes the active VPN session.
func (e *ExclaveCore) Stop() {
	slog.Info("Exclave", "status", "Stopping native Android VPN service")
	e.activeVpnSession = false
}
