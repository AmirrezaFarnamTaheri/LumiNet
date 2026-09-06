// Package stats manages telemetry, traffic counters, and runtime metrics.
package stats

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"time"
)

// TailscaleLinkMetrics is a per-peer measurement snapshot.
type TailscaleLinkMetrics struct {
	Timestamp time.Time
	NodeName  string
	RxBytes   int64
	TxBytes   int64
	Online    bool
}

// TailscaleDiagnostic measures bandwidth and link metrics via tailscale status --json.
type TailscaleDiagnostic struct {
	TailscaleBin string
}

func NewTailscaleDiagnostic() *TailscaleDiagnostic {
	return &TailscaleDiagnostic{TailscaleBin: "tailscale"}
}

// Measure runs tailscale status --json and returns per-peer metrics.
func (t *TailscaleDiagnostic) Measure(ctx context.Context) ([]TailscaleLinkMetrics, error) {
	cmd := exec.CommandContext(ctx, t.TailscaleBin, "status", "--json")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("TailscaleDiagnostic.Measure: %w", err)
	}
	var status struct {
		Peer map[string]struct {
			HostName string `json:"HostName"`
			Online   bool   `json:"Online"`
			RxBytes  int64  `json:"RxBytes"`
			TxBytes  int64  `json:"TxBytes"`
		} `json:"Peer"`
	}
	if err := json.Unmarshal(out, &status); err != nil {
		return nil, fmt.Errorf("TailscaleDiagnostic.Measure: parse: %w", err)
	}
	now := time.Now().UTC()
	var metrics []TailscaleLinkMetrics
	for _, peer := range status.Peer {
		m := TailscaleLinkMetrics{Timestamp: now, NodeName: peer.HostName,
			RxBytes: peer.RxBytes, TxBytes: peer.TxBytes, Online: peer.Online}
		slog.Info("TailscaleDiagnostic", "node", m.NodeName, "rx", m.RxBytes, "tx", m.TxBytes)
		metrics = append(metrics, m)
	}
	return metrics, nil
}