// Package system provides platform and system orchestration routines for LumiNet.
//
// Spawns Tor child processes under LumiNet's control, attaches to the
// control port, and issues `__TakeOwnership` so the Tor daemon shuts down
// automatically when our control connection closes — preventing orphaned
// tor processes even on hard LumiNet exit.

package system

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"github.com/maybeknott/luminet/internal/foundation/boundedio"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// TorProcess represents a Tor child process managed by LumiNet.
//
// The process is launched with a per-instance DataDirectory / torrc and
// is owned by LumiNet via the `__TakeOwnership` control-port command.
// When Close() is called or the owning context is cancelled, the control
// connection is dropped and Tor commits an orderly shutdown.
type TorProcess struct {
	mu               sync.Mutex
	binaryPath       string
	dataDir          string
	socksPort        int
	controlPort      int
	cmd              *exec.Cmd
	cancel           context.CancelFunc
	configPath       string
	stopped          bool
	isolateDestAddr  bool
	isolateDestPort  bool
	reducedPadding   bool
	circuitPadding   bool
	reachablePorts   string
	bridges          []string
	obfs4ProxyPath   string
	transportPlugins []TorTransportPlugin
}

// TorProcessConfig configures a Tor child process launch.
type TorProcessConfig struct {
	BinaryPath       string
	DataDir          string
	SocksPort        int
	ControlPort      int
	CookieAuthPath   string // path to the CookieAuth file (optional; defaults to dataDir/control_auth_cookie)
	IsolateDestAddr  bool
	IsolateDestPort  bool
	ReducedPadding   bool
	CircuitPadding   bool
	ReachablePorts   string
	Bridges          []string
	Obfs4ProxyPath   string
	TransportPlugins []TorTransportPlugin
}

// NewTorProcess creates an unstarted TorProcess handle.
func NewTorProcess(cfg TorProcessConfig) *TorProcess {
	return &TorProcess{
		binaryPath:       cfg.BinaryPath,
		dataDir:          cfg.DataDir,
		socksPort:        cfg.SocksPort,
		controlPort:      cfg.ControlPort,
		isolateDestAddr:  cfg.IsolateDestAddr,
		isolateDestPort:  cfg.IsolateDestPort,
		reducedPadding:   cfg.ReducedPadding,
		circuitPadding:   cfg.CircuitPadding,
		reachablePorts:   cfg.ReachablePorts,
		bridges:          append([]string(nil), cfg.Bridges...),
		obfs4ProxyPath:   cfg.Obfs4ProxyPath,
		transportPlugins: cloneTorTransportPlugins(cfg.TransportPlugins),
	}
}

// Start launches the Tor child process with a per-instance torrc and blocks
// until the SOCKS port becomes reachable (or the timeout expires).
func (p *TorProcess) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cmd != nil {
		return errors.New("tor_process: already started")
	}
	if p.binaryPath == "" {
		return errors.New("tor_process: binary path required")
	}
	if _, err := os.Stat(p.binaryPath); err != nil {
		return fmt.Errorf("tor_process: binary not found: %w", err)
	}

	if err := os.MkdirAll(p.dataDir, 0700); err != nil {
		return fmt.Errorf("tor_process: mkdir data dir: %w", err)
	}

	p.configPath = filepath.Join(p.dataDir, "torrc")
	if err := p.writeTorrc(); err != nil {
		return err
	}

	ctrlCtx, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	cmd := exec.CommandContext(ctrlCtx, p.binaryPath, "-f", p.configPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("tor_process: start failed: %w", err)
	}
	p.cmd = cmd

	// Spin a monitor goroutine to clear state on process exit.
	go func() {
		_ = cmd.Wait()
		p.mu.Lock()
		p.cmd = nil
		p.stopped = true
		p.mu.Unlock()
	}()

	// Wait for the SOCKS port to accept connections.
	if err := p.waitForSocks(ctx, 30*time.Second); err != nil {
		_ = p.stopLocked()
		return err
	}
	return nil
}

func (p *TorProcess) writeTorrc() error {
	builder := NewTorConfigBuilder().
		SocksPort(p.socksPort, p.isolateDestAddr, p.isolateDestPort).
		ControlPort(p.controlPort).
		DataDirectory(p.dataDir).
		CookieAuth(filepath.Join(p.dataDir, "control_auth_cookie")).
		AvoidDiskWrites()

	if p.reducedPadding {
		builder.ConnectionPadding(true)
		builder.CircuitPadding(true, true)
	} else {
		builder.ConnectionPadding(false)
		builder.CircuitPadding(true, false)
	}

	if p.reachablePorts != "" {
		builder.ReachableAddresses(p.reachablePorts)
	}

	if len(p.bridges) > 0 {
		plugins := cloneTorTransportPlugins(p.transportPlugins)
		if len(plugins) == 0 && p.obfs4ProxyPath != "" {
			plugins = []TorTransportPlugin{{Name: "obfs4", Executable: p.obfs4ProxyPath}}
		}
		builder.BridgesWithTransports(p.bridges, plugins)
	}

	content, err := builder.BuildValidated()
	if err != nil {
		return fmt.Errorf("tor_process: invalid torrc: %w", err)
	}
	return os.WriteFile(p.configPath, []byte(content), 0600)
}

func cloneTorTransportPlugins(in []TorTransportPlugin) []TorTransportPlugin {
	out := make([]TorTransportPlugin, len(in))
	for i, plugin := range in {
		out[i] = plugin
		out[i].Args = append([]string(nil), plugin.Args...)
	}
	return out
}

func (p *TorProcess) waitForSocks(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	addr := fmt.Sprintf("127.0.0.1:%d", p.socksPort)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				return errors.New("tor_process: timed out waiting for SOCKS port")
			}
			if dialable(addr) {
				return nil
			}
		}
	}
}

// Stop terminates the Tor process by cancelling the owning context and, if
// that fails, by killing the OS process directly.
func (p *TorProcess) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stopLocked()
}

func (p *TorProcess) stopLocked() error {
	if p.cancel != nil {
		p.cancel()
		p.cancel = nil
	}
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
	}
	if p.configPath != "" {
		_ = os.Remove(p.configPath)
	}
	p.stopped = true
	return nil
}

// PID returns the OS process id of the Tor child, or 0 if not running.
func (p *TorProcess) PID() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cmd != nil && p.cmd.Process != nil {
		return p.cmd.Process.Pid
	}
	return 0
}

// SocksPort returns the local SOCKS5 port this process is listening on.
func (p *TorProcess) SocksPort() int { return p.socksPort }

// ControlPort returns the local control port for SAFECOOKIE / TAKEOWNERSHIP.
func (p *TorProcess) ControlPort() int { return p.controlPort }

// SendTakeOwnership attaches to the Tor control port, performs SAFECOOKIE
// auth via the injected [`TorController`], and issues `__TakeOwnership` so
// the Tor process self-terminates when our control connection drops.
// See tor-spec control-spec.txt §4.5.1 `TAKEOWNERSHIP`.
func (p *TorProcess) SendTakeOwnership(controller *TorController) error {
	if controller == nil {
		return errors.New("tor_process: nil controller")
	}
	if err := controller.Connect(); err != nil {
		return fmt.Errorf("tor_process: control connect: %w", err)
	}
	if err := controller.TakeOwnership("__luminet"); err != nil {
		return fmt.Errorf("tor_process: TAKEOWNERSHIP: %w", err)
	}
	return nil
}

// BootstrapProgress returns Tor bootstrap progress (0..100) by querying
// the control port through `controller`. Safe to call from any goroutine.
func (p *TorProcess) BootstrapProgress(controller *TorController) (int, error) {
	if controller == nil {
		return 0, errors.New("tor_process: nil controller")
	}
	return controller.BootstrapProgress()
}

// dialable returns true if a TCP connection to `addr` succeeds quickly.
func dialable(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 1*time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// readCookieAuthFile reads the SAFECOOKIE challenge cookie from the Tor
// data directory. The cookie is 32 bytes per control-spec.
func (p *TorProcess) readCookieAuthFile() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	path := filepath.Join(p.dataDir, "control_auth_cookie")
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("tor_process: read cookie: %w", err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("tor_process: cookie length %d, want 32", len(b))
	}
	return b, nil
}

// scannerForReply constructs a bufio.Reader helper that reads a single
// terminated control reply. Kept for parity with control_filter.go.
func scannerForReply(s *bufio.Reader) string {
	line, _ := boundedio.ReadLine(s, maxTorControlLineBytes)
	return line
}

// RetryPolicy parameterizes the StartWithRetry loop. WipeCache=true removes
// stale `cached-consensus*` / `cached-cert*` files in dataDir before each
// retry — a poisoned or stale consensus is the most common cause of Tor
// bootstrap failure after a network change.
type RetryPolicy struct {
	MaxAttempts    int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	WipeCache      bool
}

// DefaultRetryPolicy returns 3 attempts with exponential backoff 1s -> 2s -> 4s
// (capped at 10s) and cache-wiping enabled.
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxAttempts:    3,
		InitialBackoff: 1 * time.Second,
		MaxBackoff:     10 * time.Second,
		WipeCache:      true,
	}
}

// StartWithRetry calls Start with the given policy. Between attempts it
// sleeps for an exponential backoff (InitialBackoff * 2^(attempt-1), capped
// at MaxBackoff). When WipeCache is set, cached-consensus* and cached-cert*
// files in dataDir are removed before each retry so Tor re-fetches a fresh
// consensus rather than getting stuck on a stale one. Returns nil on
// success or the last error if all attempts fail.
func (p *TorProcess) StartWithRetry(ctx context.Context, policy RetryPolicy) error {
	if policy.MaxAttempts <= 0 {
		policy = DefaultRetryPolicy()
	}
	var lastErr error
	for attempt := 1; attempt <= policy.MaxAttempts; attempt++ {
		err := p.Start(ctx)
		if err == nil {
			return nil
		}
		lastErr = err
		if attempt == policy.MaxAttempts {
			break
		}
		if policy.WipeCache {
			_ = p.wipeConsensusCache()
		}
		backoff := policy.InitialBackoff << (attempt - 1)
		if backoff > policy.MaxBackoff {
			backoff = policy.MaxBackoff
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
	}
	return fmt.Errorf("tor_process: start failed after %d attempts: %w", policy.MaxAttempts, lastErr)
}

// wipeConsensusCache removes stale Tor consensus cache files in dataDir.
// Errors are swallowed because a missing file is also the desired state.
func (p *TorProcess) wipeConsensusCache() error {
	patterns := []string{"cached-consensus*", "cached-cert*", "cached-desc*"}
	var firstErr error
	for _, pat := range patterns {
		full := filepath.Join(p.dataDir, pat)
		matches, err := filepath.Glob(full)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		for _, m := range matches {
			if err := os.Remove(m); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}
