// Ported from: sysproxy-main (Windows) + sysproxy-darwin (macOS)
// Target path: server/internal/system/sysproxy_manager.go
//
// Platform-agnostic system proxy manager. Delegates to OS-specific backends:
//   - sysproxy_windows.go  (WinInet InternetSetOptionW)
//   - sysproxy_darwin.go   (networksetup SCDynamicStore)
//   - Linux via gsettings/xfconf or KDE kwriteconfig5

package system

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ProxyConfig holds the system-wide proxy configuration.
type ProxyConfig struct {
	// HTTPProxy is the HTTP proxy address (host:port).
	HTTPProxy string
	// HTTPSProxy is the HTTPS proxy address (host:port).
	HTTPSProxy string
	// SOCKSProxy is the SOCKS5 proxy address (host:port).
	SOCKSProxy string
	// NoProxy is a comma-separated list of hosts/domains to bypass.
	NoProxy string
	// Enabled indicates whether system proxy is active.
	Enabled bool
	// PAC is an optional PAC script URL (overrides explicit proxy if set).
	PAC string
}

// Validate checks that the proxy addresses are well-formed.
func (c *ProxyConfig) Validate() error {
	for _, addr := range []string{c.HTTPProxy, c.HTTPSProxy, c.SOCKSProxy} {
		if addr == "" {
			continue
		}
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return fmt.Errorf("invalid proxy address %q: %w", addr, err)
		}
		if host == "" {
			return fmt.Errorf("proxy address %q has empty host", addr)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("proxy address %q has invalid port", addr)
		}
	}
	return nil
}

// NoProxyList parses the NoProxy comma-separated list into individual entries.
func (c *ProxyConfig) NoProxyList() []string {
	if c.NoProxy == "" {
		return nil
	}
	parts := strings.Split(c.NoProxy, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// SysproxyManager manages system-wide proxy settings via OS APIs.
type SysproxyManager struct {
	current *ProxyConfig
}

// NewSysproxyManager creates a new manager instance.
func NewSysproxyManager() *SysproxyManager {
	return &SysproxyManager{}
}

// Set applies the given proxy configuration system-wide.
// Delegates to the OS-specific implementation in sysproxy_windows.go / sysproxy_darwin.go.
func (m *SysproxyManager) Set(cfg ProxyConfig) error {
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("sysproxy_manager: invalid config: %w", err)
	}
	if err := osSetProxy(cfg); err != nil {
		return fmt.Errorf("sysproxy_manager: os set proxy: %w", err)
	}
	m.current = &cfg
	return nil
}

// Clear removes system-wide proxy settings.
func (m *SysproxyManager) Clear() error {
	if err := osClearProxy(); err != nil {
		return fmt.Errorf("sysproxy_manager: clear proxy: %w", err)
	}
	m.current = nil
	return nil
}

// Get returns the currently active proxy configuration, if any.
func (m *SysproxyManager) Get() (*ProxyConfig, error) {
	return osGetProxy()
}

// Toggle enables proxy if disabled, disables if enabled.
func (m *SysproxyManager) Toggle() error {
	cfg, err := m.Get()
	if err != nil {
		return err
	}
	if cfg == nil || !cfg.Enabled {
		if m.current != nil {
			return m.Set(*m.current)
		}
		return errors.New("sysproxy_manager: no saved config to re-enable")
	}
	return m.Clear()
}

// DefaultNoProxy returns a sensible default bypass list for LAN addresses.
func DefaultNoProxy() string {
	return "localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
}
