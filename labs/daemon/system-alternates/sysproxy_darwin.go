//go:build darwin

// Ported from: sysproxy-main (macOS backend)
// Target path: server/internal/system/sysproxy_darwin.go

package system

import (
	"fmt"
	"os/exec"
	"strings"
)

// osSetProxy sets the system proxy on macOS using networksetup.
func osSetProxy(cfg ProxyConfig) error {
	services, err := macNetworkServices()
	if err != nil {
		return err
	}
	for _, svc := range services {
		if cfg.HTTPProxy != "" {
			host, port := splitHostPort(cfg.HTTPProxy)
			if err := exec.Command("networksetup", "-setwebproxy", svc, host, port).Run(); err != nil {
				return fmt.Errorf("networksetup -setwebproxy %s: %w", svc, err)
			}
		}
		if cfg.HTTPSProxy != "" {
			host, port := splitHostPort(cfg.HTTPSProxy)
			if err := exec.Command("networksetup", "-setsecurewebproxy", svc, host, port).Run(); err != nil {
				return fmt.Errorf("networksetup -setsecurewebproxy %s: %w", svc, err)
			}
		}
		if cfg.SOCKSProxy != "" {
			host, port := splitHostPort(cfg.SOCKSProxy)
			if err := exec.Command("networksetup", "-setsocksfirewallproxy", svc, host, port).Run(); err != nil {
				return fmt.Errorf("networksetup -setsocksfirewallproxy %s: %w", svc, err)
			}
		}
		if cfg.NoProxy != "" {
			bypasses := strings.Join(cfg.NoProxyList(), " ")
			if err := exec.Command("networksetup", "-setproxybypassdomains", svc, bypasses).Run(); err != nil {
				return fmt.Errorf("networksetup -setproxybypassdomains %s: %w", svc, err)
			}
		}
	}
	return nil
}

// osClearProxy disables all proxy settings on macOS.
func osClearProxy() error {
	services, err := macNetworkServices()
	if err != nil {
		return err
	}
	for _, svc := range services {
		_ = exec.Command("networksetup", "-setwebproxystate", svc, "off").Run()
		_ = exec.Command("networksetup", "-setsecurewebproxystate", svc, "off").Run()
		_ = exec.Command("networksetup", "-setsocksfirewallproxystate", svc, "off").Run()
	}
	return nil
}

// osGetProxy reads the current proxy settings from the first active network service.
func osGetProxy() (*ProxyConfig, error) {
	services, err := macNetworkServices()
	if err != nil || len(services) == 0 {
		return nil, err
	}
	out, err := exec.Command("networksetup", "-getwebproxy", services[0]).Output()
	if err != nil {
		return nil, err
	}
	cfg := &ProxyConfig{}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "Enabled: Yes") {
			cfg.Enabled = true
		}
		if strings.HasPrefix(line, "Server:") {
			cfg.HTTPProxy = strings.TrimSpace(strings.TrimPrefix(line, "Server:"))
		}
	}
	return cfg, nil
}

func macNetworkServices() ([]string, error) {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil, fmt.Errorf("networksetup -listallnetworkservices: %w", err)
	}
	var services []string
	for i, line := range strings.Split(string(out), "\n") {
		if i == 0 || strings.TrimSpace(line) == "" || strings.HasPrefix(line, "*") {
			continue
		}
		services = append(services, strings.TrimSpace(line))
	}
	return services, nil
}

func splitHostPort(addr string) (string, string) {
	idx := strings.LastIndex(addr, ":")
	if idx < 0 {
		return addr, "0"
	}
	return addr[:idx], addr[idx+1:]
}
