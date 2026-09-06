//go:build linux


package system

import (
	"fmt"
	"os/exec"
)

// BridgeRouter configures a Linux virtual bridge interface and NAT routing rules.
type BridgeRouter struct {
	BridgeName string // e.g. "br0"
	Iface1     string // e.g. "eth0"
	Iface2     string // e.g. "eth1"
	Subnet     string // e.g. "192.168.10.1/24"
}

// NewBridgeRouter creates a new bridge manager.
func NewBridgeRouter(bridge, if1, if2, subnet string) *BridgeRouter {
	return &BridgeRouter{
		BridgeName: bridge,
		Iface1:     if1,
		Iface2:     if2,
		Subnet:     subnet,
	}
}

// Up creates the bridge interface, attaches interface cards, and sets IP.
func (b *BridgeRouter) Up() error {
	// 1. Create bridge interface
	// ip link add name br0 type bridge
	if err := exec.Command("ip", "link", "add", "name", b.BridgeName, "type", "bridge").Run(); err != nil {
		return fmt.Errorf("bridge_router: create bridge: %w", err)
	}

	// 2. Attach interface 1
	// ip link set eth0 master br0
	if err := exec.Command("ip", "link", "set", b.Iface1, "master", b.BridgeName).Run(); err != nil {
		_ = b.Down()
		return fmt.Errorf("bridge_router: bind %s to bridge: %w", b.Iface1, err)
	}

	// 3. Attach interface 2
	if err := exec.Command("ip", "link", "set", b.Iface2, "master", b.BridgeName).Run(); err != nil {
		_ = b.Down()
		return fmt.Errorf("bridge_router: bind %s to bridge: %w", b.Iface2, err)
	}

	// 4. Set IP address on bridge
	// ip addr add 192.168.10.1/24 dev br0
	if err := exec.Command("ip", "addr", "add", b.Subnet, "dev", b.BridgeName).Run(); err != nil {
		_ = b.Down()
		return fmt.Errorf("bridge_router: set subnet address: %w", err)
	}

	// 5. Bring bridge interface up
	if err := exec.Command("ip", "link", "set", "dev", b.BridgeName, "up").Run(); err != nil {
		_ = b.Down()
		return fmt.Errorf("bridge_router: bring bridge up: %w", err)
	}

	// 6. Enable IP forwarding
	if err := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run(); err != nil {
		return fmt.Errorf("bridge_router: enable ipv4 forwarding: %w", err)
	}

	return nil
}

// Down tears down the bridge interface.
func (b *BridgeRouter) Down() error {
	_ = exec.Command("ip", "link", "set", "dev", b.BridgeName, "down").Run()
	if err := exec.Command("ip", "link", "delete", "name", b.BridgeName, "type", "bridge").Run(); err != nil {
		return fmt.Errorf("bridge_router: delete bridge: %w", err)
	}
	return nil
}
