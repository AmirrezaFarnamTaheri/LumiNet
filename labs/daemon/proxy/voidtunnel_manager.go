package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// VoidTunnelState represents the persistent state of VoidTunnel for recovery.
type VoidTunnelState struct {
	OriginalGateway   string `json:"original_gateway"`
	OriginalInterface string `json:"original_interface"`
	RemoteServerIP    string `json:"remote_server_ip"`
	Active            bool   `json:"active"`
}

// VoidTunnelManager manages system-wide VPN setup via virtual TUN and tun2socks.
type VoidTunnelManager struct {
	socksPort         int
	tunDevice         string
	tunIP             string
	tunNetmask        string
	tunGateway        string
	tun2socksPath     string
	statePath         string
	cleanupScriptPath string
	cmd               *exec.Cmd
	mu                sync.Mutex
	state             VoidTunnelState
}

// NewVoidTunnelManager creates a new VoidTunnelManager.
func NewVoidTunnelManager(socksPort int) *VoidTunnelManager {
	home, _ := os.UserHomeDir()
	statePath := filepath.Join(home, ".config", "voidtunnel", "tun_state.json")
	cleanupPath := "/root/reverse-tunnel/cleanup.sh"
	if runtime.GOOS == "windows" {
		cleanupPath = filepath.Join(home, "AppData", "Local", "Temp", "cleanup.bat")
	}

	return &VoidTunnelManager{
		socksPort:         socksPort,
		tunDevice:         "tun0",
		tunIP:             "10.0.0.1",
		tunNetmask:        "24",
		tunGateway:        "10.0.0.2",
		tun2socksPath:     "tun2socks",
		statePath:         statePath,
		cleanupScriptPath: cleanupPath,
	}
}

// GetDefaultGateway parses 'ip route show default' to find the native gateway and interface.
func (m *VoidTunnelManager) GetDefaultGateway() (string, string, error) {
	if runtime.GOOS != "linux" {
		return "", "", errors.New("unsupported platform for route detection")
	}

	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return "", "", err
	}

	parts := strings.Fields(string(out))
	if len(parts) >= 5 && parts[0] == "default" && parts[1] == "via" {
		gateway := parts[2]
		for i, part := range parts {
			if part == "dev" && i+1 < len(parts) {
				return gateway, parts[i+1], nil
			}
		}
	}

	return "", "", errors.New("default gateway not found")
}

// EnableTUN configures Linux routing tables and creates the virtual TUN interface.
func (m *VoidTunnelManager) EnableTUN(remoteServerIP string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if runtime.GOOS != "linux" {
		return errors.New("VoidTunnel is only supported on Linux")
	}

	gw, dev, err := m.GetDefaultGateway()
	if err != nil {
		return fmt.Errorf("detect gateway: %w", err)
	}

	m.state = VoidTunnelState{
		OriginalGateway:   gw,
		OriginalInterface: dev,
		RemoteServerIP:    remoteServerIP,
		Active:            true,
	}

	// 1. Disable IPv6 to prevent AAAA leaks
	exec.Command("sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1").Run()
	exec.Command("sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=1").Run()

	// 2. Create TUN interface
	if err := exec.Command("ip", "tuntap", "add", "dev", m.tunDevice, "mode", "tun").Run(); err != nil {
		return fmt.Errorf("ip tuntap add: %w", err)
	}

	// 3. Configure IP & MTU
	exec.Command("ip", "addr", "add", fmt.Sprintf("%s/%s", m.tunIP, m.tunNetmask), "dev", m.tunDevice).Run()
	exec.Command("ip", "link", "set", m.tunDevice, "mtu", "1400").Run()
	exec.Command("ip", "link", "set", m.tunDevice, "up").Run()

	// 4. Update route paths: server IP bypasses TUN, default route points to TUN
	exec.Command("ip", "route", "add", fmt.Sprintf("%s/32", remoteServerIP), "via", gw, "dev", dev).Run()
	exec.Command("ip", "route", "del", "default").Run()
	exec.Command("ip", "route", "add", "default", "via", m.tunGateway, "dev", m.tunDevice).Run()

	// Write persistent state & generate emergency script
	m.writeState()
	m.generateCleanupScript()

	return nil
}

// StartTun2socks spawns the tun2socks command proxy relay loop.
func (m *VoidTunnelManager) StartTun2socks() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cmd != nil {
		return errors.New("tun2socks is already running")
	}

	// Set file descriptor limits (rlimit RLIMIT_NOFILE)
	m.setFileLimit()

	// Spawn tun2socks child process
	args := []string{
		"-device", m.tunDevice,
		"-proxy", fmt.Sprintf("socks5://127.0.0.1:%d", m.socksPort),
		"-udp-timeout", "30s",
		"-tcp-sndbuf", "16384",
		"-tcp-rcvbuf", "16384",
		"-loglevel", "warning",
	}

	cmd := exec.Command(m.tun2socksPath, args...)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("tun2socks start: %w", err)
	}

	m.cmd = cmd
	return nil
}

// Stop terminates tun2socks and tears down TUN configurations.
func (m *VoidTunnelManager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cmd != nil {
		if m.cmd.Process != nil {
			m.cmd.Process.Kill()
		}
		m.cmd.Wait()
		m.cmd = nil
	}

	if runtime.GOOS == "linux" && m.state.Active {
		// Restore default routing and enable IPv6
		exec.Command("ip", "route", "del", "default").Run()
		exec.Command("ip", "route", "add", "default", "via", m.state.OriginalGateway, "dev", m.state.OriginalInterface).Run()
		exec.Command("ip", "route", "del", fmt.Sprintf("%s/32", m.state.RemoteServerIP)).Run()
		exec.Command("ip", "tuntap", "del", "dev", m.tunDevice, "mode", "tun").Run()
		exec.Command("sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0").Run()
		exec.Command("sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=0").Run()

		m.state.Active = false
		m.writeState()
	}

	return nil
}

func (m *VoidTunnelManager) writeState() {
	dir := filepath.Dir(m.statePath)
	os.MkdirAll(dir, 0755)
	data, _ := json.MarshalIndent(m.state, "", "  ")
	os.WriteFile(m.statePath, data, 0644)
}

func (m *VoidTunnelManager) generateCleanupScript() {
	dir := filepath.Dir(m.cleanupScriptPath)
	os.MkdirAll(dir, 0755)

	script := fmt.Sprintf(`#!/bin/bash
# Emergency VoidTunnel Cleanup Script
ip route del default
ip route add default via %s dev %s
ip route del %s/32 via %s dev %s
ip tuntap del dev %s mode tun
sysctl -w net.ipv6.conf.all.disable_ipv6=0
sysctl -w net.ipv6.conf.default.disable_ipv6=0
rm -f %s
`, m.state.OriginalGateway, m.state.OriginalInterface,
		m.state.RemoteServerIP, m.state.OriginalGateway, m.state.OriginalInterface,
		m.tunDevice, m.statePath)

	os.WriteFile(m.cleanupScriptPath, []byte(script), 0755)
}

// setFileLimit helper compiles on Windows too (noop).
func (m *VoidTunnelManager) setFileLimit() {
	setFileLimitPlatform()
}

// mock helper for non-linux to pipe outputs
func (m *VoidTunnelManager) SetTun2socksPath(p string) {
	m.tun2socksPath = p
}

// Close implements io.Closer
func (m *VoidTunnelManager) Close() error {
	return m.Stop()
}
