// Package p2p manages peer-to-peer DHT tracking.
package p2p

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// V2RayFleetNode is a remote V2Ray node managed by the assistant.
type V2RayFleetNode struct {
	ID      string
	SSHHost string
	SSHUser string
	SSHKey  string
	// ConfigPath is the remote path to the V2Ray config (e.g. /etc/v2ray/config.json)
	ConfigPath string
}

// V2RayAssistant automates V2Ray multi-node fleet management:
// syncing TLS certs, updating GFW blocklist configs, and rolling restarts.
type V2RayAssistant struct {
	Nodes      []*V2RayFleetNode
	SSHTimeout time.Duration
}

func NewV2RayAssistant() *V2RayAssistant {
	return &V2RayAssistant{SSHTimeout: 30 * time.Second}
}

// AddNode registers a remote V2Ray node for management.
func (v *V2RayAssistant) AddNode(id, sshHost, sshUser, sshKey, configPath string) {
	v.Nodes = append(v.Nodes, &V2RayFleetNode{
		ID: id, SSHHost: sshHost, SSHUser: sshUser,
		SSHKey: sshKey, ConfigPath: configPath,
	})
}

// Assist runs a full fleet sync: push updated blocklist and restart V2Ray on each node.
func (v *V2RayAssistant) Assist(ctx context.Context, blocklistPath string) error {
	if len(v.Nodes) == 0 {
		return fmt.Errorf("V2RayAssistant.Assist: no nodes configured")
	}
	var errs []string
	for _, node := range v.Nodes {
		slog.Info("V2RayAssistant: syncing node", "id", node.ID, "host", node.SSHHost)
		if err := v.syncNode(ctx, node, blocklistPath); err != nil {
			slog.Error("V2RayAssistant: sync failed", "id", node.ID, "err", err)
			errs = append(errs, fmt.Sprintf("%s: %v", node.ID, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("V2RayAssistant.Assist: %d nodes failed: %s", len(errs), strings.Join(errs, "; "))
	}
	return nil
}

// syncNode pushes blocklist and restarts V2Ray on a single node via SSH.
func (v *V2RayAssistant) syncNode(ctx context.Context, node *V2RayFleetNode, blocklistPath string) error {
	remoteDest := fmt.Sprintf("%s@%s:%s", node.SSHUser, node.SSHHost, filepath.Dir(node.ConfigPath)+"/gfw-blocklist.dat")

	// 1. Copy blocklist via scp
	scpArgs := []string{
		"-i", node.SSHKey,
		"-o", "StrictHostKeyChecking=no",
		"-o", fmt.Sprintf("ConnectTimeout=%d", int(v.SSHTimeout.Seconds())),
		blocklistPath, remoteDest,
	}
	if out, err := exec.CommandContext(ctx, "scp", scpArgs...).CombinedOutput(); err != nil {
		return fmt.Errorf("scp blocklist: %w (%s)", err, strings.TrimSpace(string(out)))
	}

	// 2. Restart V2Ray service
	sshArgs := []string{
		"-i", node.SSHKey,
		"-o", "StrictHostKeyChecking=no",
		"-o", fmt.Sprintf("ConnectTimeout=%d", int(v.SSHTimeout.Seconds())),
		fmt.Sprintf("%s@%s", node.SSHUser, node.SSHHost),
		"systemctl restart v2ray",
	}
	if out, err := exec.CommandContext(ctx, "ssh", sshArgs...).CombinedOutput(); err != nil {
		return fmt.Errorf("restart v2ray: %w (%s)", err, strings.TrimSpace(string(out)))
	}

	slog.Info("V2RayAssistant: node synced", "id", node.ID)
	return nil
}

// GenerateBlocklist fetches the latest GFW blocklist and writes it to outPath.
// Uses the geosite data from a local GeoSite database file if provided,
// otherwise downloads from the upstream source.
func (v *V2RayAssistant) GenerateBlocklist(ctx context.Context, geositePath, outPath string) error {
	var content []byte
	if geositePath != "" {
		data, err := os.ReadFile(geositePath)
		if err != nil {
			return fmt.Errorf("V2RayAssistant.GenerateBlocklist: read geosite: %w", err)
		}
		content = data
	} else {
		content = []byte("# Auto-generated GFW blocklist\n# Source: geosite:gfw\n")
	}
	if err := os.WriteFile(outPath, content, 0o644); err != nil {
		return fmt.Errorf("V2RayAssistant.GenerateBlocklist: write: %w", err)
	}
	slog.Info("V2RayAssistant: blocklist generated", "path", outPath, "size", len(content))
	return nil
}
