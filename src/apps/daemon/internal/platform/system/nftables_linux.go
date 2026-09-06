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

// NftablesLinux configures transparent proxy routing via nftables.
type NftablesLinux struct {
	Table        string
	Chain        string
	ProxyPort    uint16
	ExcludedUIDs []int
}

func NewNftablesLinux() *NftablesLinux {
	return &NftablesLinux{Table: "luminet", Chain: "prerouting", ProxyPort: 12345}
}

// Route installs nftables REDIRECT rules for transparent TCP proxying.
func (n *NftablesLinux) Route(ctx context.Context) error {
	cmds := [][]string{
		{"nft", "add", "table", "ip", n.Table},
		{"nft", "add", "chain", "ip", n.Table, n.Chain,
			"{ type nat hook prerouting priority -100; }"},
	}
	for _, uid := range n.ExcludedUIDs {
		cmds = append(cmds, []string{"nft", "add", "rule", "ip", n.Table, n.Chain,
			"meta", "skuid", fmt.Sprintf("%d", uid), "return"})
	}
	cmds = append(cmds, []string{"nft", "add", "rule", "ip", n.Table, n.Chain,
		"ip", "protocol", "tcp", "redirect", "to",
		fmt.Sprintf(":%d", n.ProxyPort)})
	for _, args := range cmds {
		if out, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("NftablesLinux.Route: %v: %w (%s)", args, err, strings.TrimSpace(string(out)))
		}
	}
	slog.Info("NftablesLinux: routing configured", "table", n.Table, "port", n.ProxyPort)
	return nil
}

// Flush removes the luminet nftables table.
func (n *NftablesLinux) Flush(ctx context.Context) error {
	if out, err := exec.CommandContext(ctx, "nft", "delete", "table", "ip", n.Table).
		CombinedOutput(); err != nil {
		return fmt.Errorf("NftablesLinux.Flush: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	slog.Info("NftablesLinux: table flushed", "table", n.Table)
	return nil
}
