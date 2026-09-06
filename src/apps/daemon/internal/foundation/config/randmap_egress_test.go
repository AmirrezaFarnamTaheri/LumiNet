package config

import (
	"net"
	"testing"
)

func mustV6(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("bad fixture addr %q", s)
	}
	return ip
}

func TestRandmapEgressValidateDisabled(t *testing.T) {
	var c *RandmapEgressConfig
	if c.Enabled() {
		t.Fatal("nil config must be disabled")
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("nil config must validate: %v", err)
	}
	empty := &RandmapEgressConfig{}
	if empty.Enabled() {
		t.Fatal("empty config must be disabled")
	}
	if err := empty.Validate(); err != nil {
		t.Fatalf("empty config must validate: %v", err)
	}
}

func TestRandmapEgressValidateValid(t *testing.T) {
	mustV6(t, "2001:db8::") // sanity: fixture addresses parse
	c := &RandmapEgressConfig{
		IPv4: &RandmapV4Config{Mode: RandmapV4Global, RandomisePort: true, PortMin: 32768, PortMax: 60999},
		IPv6: &RandmapV6Config{
			MangleSource: true,
			PrefixNet:    "2001:db8::",
			PrefixMask:   "ffff:ffff:ffff::",
			PortMin:      1024,
			PortMax:      65535,
		},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestRandmapEgressValidateErrors(t *testing.T) {

	// Explicit checks keep failures readable:
	if err := (&RandmapEgressConfig{IPv4: &RandmapV4Config{PortMin: 60000, PortMax: 40000}}).Validate(); err == nil {
		t.Error("inverted v4 range accepted")
	}
	if err := (&RandmapEgressConfig{IPv4: &RandmapV4Config{Mode: "warp"}}).Validate(); err == nil {
		t.Error("invalid v4 mode accepted")
	}
	if err := (&RandmapEgressConfig{IPv4: &RandmapV4Config{PortMax: 70000}}).Validate(); err == nil {
		t.Error("port_max > 65535 accepted")
	}
	if err := (&RandmapEgressConfig{IPv6: &RandmapV6Config{PortMin: 1024, PortMax: 2048}}).Validate(); err == nil {
		t.Error("ipv6 with no mangle endpoints accepted")
	}
	if err := (&RandmapEgressConfig{IPv6: &RandmapV6Config{MangleSource: true, PrefixNet: "2001:db8::"}}).Validate(); err == nil {
		t.Error("prefix_net without prefix_mask accepted")
	}
	if err := (&RandmapEgressConfig{IPv6: &RandmapV6Config{MangleSource: true, PrefixNet: "nope", PrefixMask: "::"}}).Validate(); err == nil {
		t.Error("bad prefix_net accepted")
	}
}
