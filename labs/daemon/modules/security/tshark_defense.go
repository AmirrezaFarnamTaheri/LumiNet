// Package security handles intrusion detection and firewall hooks.
package security

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
)

// TsharkDefense detects port scans via tshark and optionally blocks via UFW.
type TsharkDefense struct {
	Interface  string
	UFWEnabled bool
	BlockedIPs map[string]struct{}
}

func NewTsharkDefense() *TsharkDefense {
	return &TsharkDefense{Interface: "eth0", BlockedIPs: make(map[string]struct{})}
}

// Sniff captures packets and returns IPs with suspicious SYN patterns.
func (t *TsharkDefense) Sniff(ctx context.Context, capCount int) ([]string, error) {
	if capCount <= 0 {
		capCount = 100
	}
	cmd := exec.CommandContext(ctx, "tshark",
		"-i", t.Interface, "-c", fmt.Sprintf("%d", capCount),
		"-T", "fields", "-e", "ip.src",
		"-Y", "tcp.flags.syn==1 && tcp.flags.ack==0",
	)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("TsharkDefense.Sniff: %w", err)
	}
	synCount := make(map[string]int)
	for _, line := range strings.Split(string(out), "\n") {
		ip := strings.TrimSpace(line)
		if ip != "" {
			synCount[ip]++
		}
	}
	var suspicious []string
	for ip, n := range synCount {
		if n >= 10 {
			slog.Warn("TsharkDefense: scan detected", "src", ip, "syns", n)
			suspicious = append(suspicious, ip)
			if t.UFWEnabled {
				if err2 := t.blockUFW(ctx, ip); err2 != nil {
					slog.Error("TsharkDefense: block failed", "ip", ip, "err", err2)
				}
			}
		}
	}
	return suspicious, nil
}

func (t *TsharkDefense) blockUFW(ctx context.Context, ip string) error {
	if o, err := exec.CommandContext(ctx, "ufw", "deny", "from", ip).CombinedOutput(); err != nil {
		return fmt.Errorf("ufw deny %s: %w (%s)", ip, err, strings.TrimSpace(string(o)))
	}
	t.BlockedIPs[ip] = struct{}{}
	slog.Info("TsharkDefense: UFW blocked", "ip", ip)
	return nil
}