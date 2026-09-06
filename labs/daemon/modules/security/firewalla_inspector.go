// Package security handles intrusion detection and firewall hooks.
package security

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
)

// FirewallaInspector inspects ARP tables and blocks suspicious IPs via iptables.
type FirewallaInspector struct {
	Interface  string
	BlockedIPs []string
}

func NewFirewallaInspector() *FirewallaInspector { return &FirewallaInspector{Interface: "eth0"} }

// Inspect runs arp -n and logs duplicate MACs (ARP spoof indicator).
func (f *FirewallaInspector) Inspect(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "arp", "-n")
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("FirewallaInspector.Inspect: %w", err)
	}
	macToIPs := make(map[string][]string)
	for _, line := range strings.Split(string(out), "\n") {
		fs := strings.Fields(line)
		if len(fs) < 3 || fs[2] == "<incomplete>" {
			continue
		}
		macToIPs[fs[2]] = append(macToIPs[fs[2]], fs[0])
	}
	for mac, ips := range macToIPs {
		if len(ips) > 1 {
			slog.Warn("FirewallaInspector: ARP spoof?", "mac", mac, "ips", strings.Join(ips, ","))
		}
	}
	return nil
}

// BlockIP adds an iptables DROP rule for ip.
func (f *FirewallaInspector) BlockIP(ctx context.Context, ip string) error {
	cmd := exec.CommandContext(ctx, "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
	if o, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("BlockIP %s: %w (%s)", ip, err, strings.TrimSpace(string(o)))
	}
	f.BlockedIPs = append(f.BlockedIPs, ip)
	slog.Info("FirewallaInspector: blocked", "ip", ip)
	return nil
}