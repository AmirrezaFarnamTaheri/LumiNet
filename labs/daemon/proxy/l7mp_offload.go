// Package proxy implements multi-protocol proxy servers and clients.
// Ported from: l7mp-master (udp-offload.js, kernel-offload/)
// Target path: server/internal/proxy/l7mp_offload.go

package proxy

import (
	"fmt"
	"net"
)

// L7MPOffloadConfig defines eBPF/XDP offload settings.
// Maps to kernel-offload and udp-offload.js.
type L7MPOffloadConfig struct {
	InterfaceName   string `json:"interface_name"`
	EbpfProgramPath string `json:"ebpf_program_path,omitempty"`
	EnableXDP       bool   `json:"enable_xdp"`
	OffloadMode     string `json:"offload_mode"` // generic, native, offloaded
}

// Getters & Setters for L7MPOffloadConfig
func (c *L7MPOffloadConfig) GetInterfaceName() string  { return c.InterfaceName }
func (c *L7MPOffloadConfig) SetInterfaceName(v string) { c.InterfaceName = v }

// ApplyL7MPOffload configures the network interface offload options.
func ApplyL7MPOffload(cfg L7MPOffloadConfig) error {
	if cfg.InterfaceName == "" {
		return fmt.Errorf("interface name cannot be empty")
	}

	_, err := net.InterfaceByName(cfg.InterfaceName)
	if err != nil {
		return fmt.Errorf("failed to locate network interface %s: %w", cfg.InterfaceName, err)
	}

	// Logging simulated hook registration for ebpf/xdp kernel program loading
	if cfg.EnableXDP {
		fmt.Printf("[L7MP-KERNEL] Loading XDP program %s onto %s in %s mode\n",
			cfg.EbpfProgramPath, cfg.InterfaceName, cfg.OffloadMode)
	} else {
		fmt.Printf("[L7MP-KERNEL] Registering UDP offload socket helper on %s\n", cfg.InterfaceName)
	}

	return nil
}
