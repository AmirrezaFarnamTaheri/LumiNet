// Package stats manages telemetry, traffic counters, and runtime metrics.
package stats

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"
)

// ProxyProcessMetrics is a snapshot of proxy process performance.
type ProxyProcessMetrics struct {
	Timestamp   time.Time
	PID         int
	CPUPercent  float64
	MemRSSBytes int64
}

// ProcessProxyMonitor samples process metrics for a named proxy service.
type ProcessProxyMonitor struct {
	ProcessName    string
	SampleInterval time.Duration
}

func NewProcessProxyMonitor() *ProcessProxyMonitor {
	return &ProcessProxyMonitor{ProcessName: "luminet", SampleInterval: 5 * time.Second}
}

// Sample captures one performance snapshot using ps.
func (p *ProcessProxyMonitor) Sample(ctx context.Context) (*ProxyProcessMetrics, error) {
	cmd := exec.CommandContext(ctx, "ps", "-C", p.ProcessName, "-o", "pid,pcpu,rss", "--no-headers")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("ProcessProxyMonitor.Sample: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 || lines[0] == "" {
		return nil, fmt.Errorf("ProcessProxyMonitor.Sample: process %q not found", p.ProcessName)
	}
	m := &ProxyProcessMetrics{Timestamp: time.Now().UTC()}
	fmt.Sscanf(lines[0], "%d %f %d", &m.PID, &m.CPUPercent, &m.MemRSSBytes)
	m.MemRSSBytes *= 1024
	return m, nil
}

// Monitor runs a background sampling loop, calling onSample per tick.
func (p *ProcessProxyMonitor) Monitor(ctx context.Context, onSample func(*ProxyProcessMetrics)) {
	ticker := time.NewTicker(p.SampleInterval)
	defer ticker.Stop()
	slog.Info("ProcessProxyMonitor: started", "process", p.ProcessName)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m, err := p.Sample(ctx)
			if err != nil {
				slog.Warn("ProcessProxyMonitor: sample error", "err", err)
				continue
			}
			onSample(m)
		}
	}
}