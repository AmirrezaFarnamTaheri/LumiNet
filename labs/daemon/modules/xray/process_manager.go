// Ported from: Sanaei-3xui-v2ray-main
// Target path: server/internal/xray/process_manager.go

package xray

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sync"
)

// ErrTrafficStatsUnavailable reports that this process manager has no stats client.
var ErrTrafficStatsUnavailable = errors.New("xray_manager: traffic statistics are unavailable")

// XrayProcessManager handles xray daemon lifecycle and gRPC traffic updates.
type XrayProcessManager struct {
	mu         sync.Mutex
	cmd        *exec.Cmd
	configPath string
	grpcAddr   string // e.g. "127.0.0.1:10085"
	cancel     context.CancelFunc
}

// NewXrayProcessManager creates a new process manager.
func NewXrayProcessManager(configPath, grpcAddr string) *XrayProcessManager {
	return &XrayProcessManager{
		configPath: configPath,
		grpcAddr:   grpcAddr,
	}
}

// Start launches the xray binary pointing to the generated config.json.
func (m *XrayProcessManager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cmd != nil {
		return fmt.Errorf("xray_manager: process is already running")
	}

	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel

	// Command: xray -config [configPath]
	m.cmd = exec.CommandContext(ctx, "xray", "-config", m.configPath)
	if err := m.cmd.Start(); err != nil {
		cancel()
		m.cmd = nil
		return fmt.Errorf("xray_manager: start process failed: %w", err)
	}

	return nil
}

// Stop terminates the xray binary.
func (m *XrayProcessManager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cmd == nil {
		return
	}

	if m.cancel != nil {
		m.cancel()
	}

	_ = m.cmd.Wait()
	m.cmd = nil
}

// QueryTrafficStats issues a gRPC call to Xray's StatsService to retrieve user bytes.
func (m *XrayProcessManager) QueryTrafficStats(ctx context.Context) (rx, tx int64, err error) {
	if err := ctx.Err(); err != nil {
		return 0, 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return 0, 0, ErrTrafficStatsUnavailable
}
