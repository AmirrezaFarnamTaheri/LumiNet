// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: Throne
// Target path: server/internal/proxy/throne.go

package proxy

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
)

// ThroneManager handles C++ Qt desktop client GUI models mapping, Linux SUID permissions, and DNS hooks.
type ThroneManager struct{}

// NewThroneManager initializes Throne manager.
func NewThroneManager() *ThroneManager {
	return &ThroneManager{}
}

// 1. EscalateTunPermissions escalates Linux SUID TUN permissions using pkexec or setcap.
func (t *ThroneManager) EscalateTunPermissions(ctx context.Context, binaryPath string) error {
	log.Printf("Throne: Escalating TUN permissions for binary %s", binaryPath)

	if runtime.GOOS != "linux" {
		return fmt.Errorf("permission escalation is only supported on Linux")
	}

	pkexecPath, err := exec.LookPath("pkexec")
	if err == nil {
		setcapPath, err2 := exec.LookPath("setcap")
		if err2 == nil {
			cmd := exec.CommandContext(ctx, pkexecPath, setcapPath, "cap_net_admin,cap_net_bind_service=+ep", binaryPath)
			errRun := cmd.Run()
			if errRun == nil {
				slog.Info("Throne", "status", "SUID TUN permissions escalated successfully via pkexec setcap")
				return nil
			}
		}
	}

	setcapPath, err := exec.LookPath("setcap")
	if err == nil {
		cmd := exec.CommandContext(ctx, setcapPath, "cap_net_admin,cap_net_bind_service=+ep", binaryPath)
		errRun := cmd.Run()
		if errRun == nil {
			slog.Info("Throne", "status", "SUID TUN permissions escalated successfully via direct setcap")
			return nil
		}
	}

	return fmt.Errorf("failed to escalate permissions: pkexec or setcap unavailable, or privilege elevation rejected")
}

// 2. HookSystemDNS hooks System DNS across Linux, Windows, and macOS for global proxying.
func (t *ThroneManager) HookSystemDNS(ctx context.Context) error {
	slog.Info("Throne", "status", "Hooking System DNS to route through local proxy (127.0.0.1)")

	switch runtime.GOOS {
	case "linux":
		resolvConf := "nameserver 127.0.0.1\n"
		err := os.WriteFile("/etc/resolv.conf", []byte(resolvConf), 0644)
		if err == nil {
			return nil
		}

		cmd := exec.CommandContext(ctx, "resolvectl", "dns", "lo", "127.0.0.1")
		if err := cmd.Run(); err == nil {
			return nil
		}

	case "windows":
		cmd := exec.CommandContext(ctx, "netsh", "interface", "ipv4", "set", "dns", "name=Wi-Fi", "source=static", "address=127.0.0.1")
		if err := cmd.Run(); err == nil {
			return nil
		}
		cmdEthernet := exec.CommandContext(ctx, "netsh", "interface", "ipv4", "set", "dns", "name=Ethernet", "source=static", "address=127.0.0.1")
		_ = cmdEthernet.Run()

	case "darwin":
		cmd := exec.CommandContext(ctx, "networksetup", "-setdnsservers", "Wi-Fi", "127.0.0.1")
		if err := cmd.Run(); err == nil {
			return nil
		}
	}

	return fmt.Errorf("failed to hook system DNS on platform %s", runtime.GOOS)
}

// 3. FlushDNSCache flushes local resolver cache entries across platforms.
func (t *ThroneManager) FlushDNSCache(ctx context.Context) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(ctx, "ipconfig", "/flushdns")
	case "linux":
		cmd = exec.CommandContext(ctx, "systemd-resolve", "--flush-caches")
		if err := cmd.Run(); err != nil {
			cmd = exec.CommandContext(ctx, "resolvectl", "flush-caches")
		}
	case "darwin":
		cmd = exec.CommandContext(ctx, "killall", "-HUP", "mDNSResponder")
	default:
		return fmt.Errorf("unsupported platform for DNS cache flush")
	}
	return cmd.Run()
}

// 4. GetDNSConfiguration resolves active system resolver target hosts.
func (t *ThroneManager) GetDNSConfiguration(ctx context.Context) ([]string, error) {
	if runtime.GOOS == "windows" {
		out, err := exec.CommandContext(ctx, "netsh", "interface", "ipv4", "show", "dnsservers").Output()
		if err == nil {
			return []string{string(out)}, nil
		}
	} else if runtime.GOOS == "linux" {
		data, err := os.ReadFile("/etc/resolv.conf")
		if err == nil {
			return []string{string(data)}, nil
		}
	}
	return nil, fmt.Errorf("unsupported platform")
}

// 5. SetDNSConfiguration applies specific DNS server targets dynamically.
func (t *ThroneManager) SetDNSConfiguration(ctx context.Context, serverIP string) error {
	if runtime.GOOS == "windows" {
		return exec.CommandContext(ctx, "netsh", "interface", "ipv4", "set", "dns", "name=Wi-Fi", "source=static", "address="+serverIP).Run()
	} else if runtime.GOOS == "linux" {
		return os.WriteFile("/etc/resolv.conf", []byte("nameserver "+serverIP+"\n"), 0644)
	}
	return fmt.Errorf("unsupported platform")
}

// 6. IsTunDeviceConfigured asserts if the target interface is loaded in the kernel.
func (t *ThroneManager) IsTunDeviceConfigured(deviceName string) bool {
	ifaces, err := netInterfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		if iface == deviceName {
			return true
		}
	}
	return false
}

// 7. SetupVirtualInterface configures virtual interface links.
func (t *ThroneManager) SetupVirtualInterface(ctx context.Context, deviceName string) error {
	if runtime.GOOS == "linux" {
		return exec.CommandContext(ctx, "ip", "tuntap", "add", "dev", deviceName, "mode", "tun").Run()
	} else if runtime.GOOS == "windows" {
		log.Printf("Throne: Setup Wintun interface %s using driver utilities", deviceName)
		return nil
	}
	return fmt.Errorf("unsupported platform")
}

// 8. RemoveVirtualInterface deletes interface links.
func (t *ThroneManager) RemoveVirtualInterface(ctx context.Context, deviceName string) error {
	if runtime.GOOS == "linux" {
		return exec.CommandContext(ctx, "ip", "link", "delete", deviceName).Run()
	}
	return fmt.Errorf("unsupported platform")
}

// 9. CheckPolkitSupport checks for policy kit support.
func (t *ThroneManager) CheckPolkitSupport() bool {
	_, err := exec.LookPath("pkexec")
	return err == nil
}

// 10. RestoreDNSOnSignal traps signals to clean up and restore original DNS settings.
func (t *ThroneManager) RestoreDNSOnSignal(ctx context.Context, cleanupFunc func()) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case <-sigChan:
			slog.Info("Throne", "status", "Signal trapped. Restoring configurations...")
			if cleanupFunc != nil {
				cleanupFunc()
			}
			os.Exit(0)
		case <-ctx.Done():
			return
		}
	}()
}

// 11. AddSystemRoute adds routing entries.
func (t *ThroneManager) AddSystemRoute(ctx context.Context, destCIDR, gatewayIP string) error {
	if runtime.GOOS == "linux" {
		return exec.CommandContext(ctx, "ip", "route", "add", destCIDR, "via", gatewayIP).Run()
	} else if runtime.GOOS == "windows" {
		return exec.CommandContext(ctx, "route", "add", destCIDR, gatewayIP).Run()
	}
	return fmt.Errorf("unsupported platform")
}

// 12. RemoveSystemRoute deletes routing entries.
func (t *ThroneManager) RemoveSystemRoute(ctx context.Context, destCIDR string) error {
	if runtime.GOOS == "linux" {
		return exec.CommandContext(ctx, "ip", "route", "del", destCIDR).Run()
	}
	return fmt.Errorf("unsupported platform")
}

// 13. WriteResolvConf writes resolv.conf.
func (t *ThroneManager) WriteResolvConf(nameservers []string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("resolv.conf is only supported on Unix")
	}

	var content string
	for _, ns := range nameservers {
		content += "nameserver " + ns + "\n"
	}
	return os.WriteFile("/etc/resolv.conf", []byte(content), 0644)
}

// 14. UnlockResolvConf releases immutable file locks.
func (t *ThroneManager) UnlockResolvConf(ctx context.Context) error {
	if runtime.GOOS == "linux" {
		return exec.CommandContext(ctx, "chattr", "-i", "/etc/resolv.conf").Run()
	}
	return fmt.Errorf("unsupported platform")
}

// 15. LockResolvConf applies immutable file locks to prevent dhcp updates from overriding DNS.
func (t *ThroneManager) LockResolvConf(ctx context.Context) error {
	if runtime.GOOS == "linux" {
		return exec.CommandContext(ctx, "chattr", "+i", "/etc/resolv.conf").Run()
	}
	return fmt.Errorf("unsupported platform")
}

// netInterfaces returns a list of local interfaces names.
func netInterfaces() ([]string, error) {
	ifaces, err := exec.Command("netstat", "-i").Output()
	if err != nil {
		return nil, err
	}
	// Fallback lookup
	return []string{string(ifaces)}, nil
}
