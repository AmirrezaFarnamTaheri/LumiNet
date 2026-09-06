// SPDX-License-Identifier: MIT
//
// Randmap egress config (roadmap item 4). Mirrors the JSON shape of
// lumicore's `system::randmap_egress::RandmapEgressSettings` exactly, so
// the daemon serialises this struct and hands it to the Rust facade
// unchanged. Empty/zero value = feature disabled (both families off).

package config

import (
	"fmt"
	"net"
)

// RandmapV4Mode is the IPv4 randomisation mode.
// Values mirror lumicore RandmapV4Mode serde renames.
type RandmapV4Mode string

const (
	RandmapV4SubnetPreserving RandmapV4Mode = "subnet_preserving"
	RandmapV4Global           RandmapV4Mode = "global"
	RandmapV4PortOnly         RandmapV4Mode = "port_only"
)

// RandmapV4Config configures the IPv4 randmap engine.
type RandmapV4Config struct {
	Mode          RandmapV4Mode `json:"mode,omitempty"`
	RandomisePort bool          `json:"randomise_port,omitempty"`
	PortMin       int           `json:"port_min,omitempty"`
	PortMax       int           `json:"port_max,omitempty"`
}

// RandmapV6Config configures the IPv6 randmap engine.
type RandmapV6Config struct {
	MangleSource      bool   `json:"mangle_source,omitempty"`
	MangleDestination bool   `json:"mangle_destination,omitempty"`
	PrefixNet         string `json:"prefix_net,omitempty"`
	PrefixMask        string `json:"prefix_mask,omitempty"`
	PortMin           int    `json:"port_min,omitempty"`
	PortMax           int    `json:"port_max,omitempty"`
}

// RandmapEgressConfig is the top-level egress randomisation option.
// Omitted families are disabled.
type RandmapEgressConfig struct {
	IPv4 *RandmapV4Config `json:"ipv4,omitempty"`
	IPv6 *RandmapV6Config `json:"ipv6,omitempty"`
}

// Enabled reports whether any family is configured.
func (c *RandmapEgressConfig) Enabled() bool {
	return c != nil && (c.IPv4 != nil || c.IPv6 != nil)
}

// Validate checks port ranges, modes and prefix syntax before the config
// reaches the engine. It must reject the same inputs the Rust facade
// rejects so config errors surface at load time, not at packet time.
func (c *RandmapEgressConfig) Validate() error {
	if !c.Enabled() {
		return nil
	}
	checkRange := func(min, max int, what string) error {
		if min == 0 && max == 0 {
			return nil // defaults apply engine-side
		}
		if min < 0 || max < 0 {
			return fmt.Errorf("randmap_egress: %s ports must be non-negative", what)
		}
		if min > max {
			return fmt.Errorf("randmap_egress: %s port_min (%d) > port_max (%d)", what, min, max)
		}
		if max > 65535 {
			return fmt.Errorf("randmap_egress: %s port_max (%d) exceeds 65535", what, max)
		}
		return nil
	}
	if c.IPv4 != nil {
		switch c.IPv4.Mode {
		case "", RandmapV4SubnetPreserving, RandmapV4Global, RandmapV4PortOnly:
		default:
			return fmt.Errorf("randmap_egress: ipv4.mode %q is not a valid mode", c.IPv4.Mode)
		}
		if err := checkRange(c.IPv4.PortMin, c.IPv4.PortMax, "ipv4"); err != nil {
			return err
		}
	}
	if c.IPv6 != nil {
		if !c.IPv6.MangleSource && !c.IPv6.MangleDestination {
			return fmt.Errorf("randmap_egress: ipv6 configured but neither mangle_source nor mangle_destination is set")
		}
		if err := checkRange(c.IPv6.PortMin, c.IPv6.PortMax, "ipv6"); err != nil {
			return err
		}
		if (c.IPv6.PrefixNet == "") != (c.IPv6.PrefixMask == "") {
			return fmt.Errorf("randmap_egress: ipv6 prefix_net and prefix_mask must be set together")
		}
		if c.IPv6.PrefixNet != "" {
			if err := validateV6Addr(c.IPv6.PrefixNet); err != nil {
				return fmt.Errorf("randmap_egress: ipv6.prefix_net: %w", err)
			}
			if err := validateV6Addr(c.IPv6.PrefixMask); err != nil {
				return fmt.Errorf("randmap_egress: ipv6.prefix_mask: %w", err)
			}
		}
	}
	return nil
}

// validateV6Addr parses an IPv6 address (net.ParseIP accepts v4 too; we
// require the parsed form to be 16 bytes).
func validateV6Addr(s string) error {
	ip := net.ParseIP(s)
	if ip == nil || ip.To16() == nil || ip.To4() != nil {
		return fmt.Errorf("not a valid IPv6 address: %q", s)
	}
	return nil
}
