//go:build linux

// Package system provides system-level configuration, orchestration, and proxying tools.
package system

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
)

// RouterIptables configures transparent routing via iptables + dnsmasq.
type RouterIptables struct {
	Interface     string
	ProxyPort     uint16
	DNSPort       uint16
	ExcludeRanges []string
}

func NewRouterIptables() *RouterIptables {
	return &RouterIptables{
		Interface:     "br-lan",
		ProxyPort:     12345,
		DNSPort:       5353,
		ExcludeRanges: []string{"192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"},
	}
}

// ConfigureLinuxTransparentRouting installs iptables REDIRECT rules for TCP/DNS.
func (r *RouterIptables) ConfigureLinuxTransparentRouting(ctx context.Context) error {
	for _, cidr := range r.ExcludeRanges {
		if err := r.ipt(ctx, "-t", "nat", "-A", "PREROUTING", "-d", cidr, "-j", "RETURN"); err != nil {
			return err
		}
	}
	if err := r.ipt(ctx, "-t", "nat", "-A", "PREROUTING",
		"-i", r.Interface, "-p", "udp", "--dport", "53",
		"-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", r.DNSPort)); err != nil {
		return err
	}
	if err := r.ipt(ctx, "-t", "nat", "-A", "PREROUTING",
		"-i", r.Interface, "-p", "tcp",
		"-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", r.ProxyPort)); err != nil {
		return err
	}
	slog.Info("RouterIptables: configured", "if", r.Interface, "proxy", r.ProxyPort, "dns", r.DNSPort)
	return nil
}

// Flush clears the PREROUTING nat chain.
func (r *RouterIptables) Flush(ctx context.Context) error {
	return r.ipt(ctx, "-t", "nat", "-F", "PREROUTING")
}

func (r *RouterIptables) ipt(ctx context.Context, args ...string) error {
	if out, err := exec.CommandContext(ctx, "iptables", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("iptables %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
