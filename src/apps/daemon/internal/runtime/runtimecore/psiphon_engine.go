package runtimecore

import (
	"context"
	"encoding/json"
	"fmt"
	hostprocess "github.com/maybeknott/luminet/internal/platform/process"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// psiphonEngine owns one long-lived psiphon-tunnel-core subprocess.
type psiphonEngine struct {
	mu            sync.Mutex
	isRunning     bool
	binaryPath    string
	socksPort     int
	upstreamProxy string
	cmd           *exec.Cmd
	cancel        context.CancelFunc
	done          chan struct{}
	configPath    string
}

func newPsiphonEngine(socksPort int) *psiphonEngine {
	return &psiphonEngine{socksPort: socksPort}
}

func (e *psiphonEngine) SetUpstreamProxy(proxyURL string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.upstreamProxy = proxyURL
}

func (e *psiphonEngine) FindBinary() (string, error) {
	if e.binaryPath != "" {
		if _, err := os.Stat(e.binaryPath); err == nil {
			return e.binaryPath, nil
		}
	}
	for _, bin := range []string{"psiphon-tunnel-core.exe", "psiphon-tunnel-core", `./bin/psiphon/psiphon-tunnel-core.exe`, `./bin/psiphon/psiphon-tunnel-core`} {
		if path, err := exec.LookPath(bin); err == nil {
			e.binaryPath = path
			return path, nil
		}
		if _, err := os.Stat(bin); err == nil {
			abs, err := filepath.Abs(bin)
			if err == nil {
				e.binaryPath = abs
				return abs, nil
			}
			e.binaryPath = bin
			return bin, nil
		}
	}
	return "", fmt.Errorf("failed to locate psiphon-tunnel-core in PATH or repository-local bin directory")
}

func (e *psiphonEngine) Start() error {
	e.mu.Lock()
	if e.isRunning {
		e.mu.Unlock()
		return nil
	}
	binary, err := e.FindBinary()
	if err != nil {
		e.mu.Unlock()
		return err
	}
	configMap := map[string]interface{}{
		"LocalSocksProxyPort":               e.socksPort,
		"PropagationChannelId":              "LUMINET_DESKTOP",
		"SponsorId":                         "LUMINET",
		"TunnelWholeDevice":                 false,
		"NetworkConnectivityCheckerEnabled": false,
	}
	if e.upstreamProxy != "" {
		configMap["UpstreamProxyURL"] = e.upstreamProxy
	}
	configData, err := json.Marshal(configMap)
	if err != nil {
		e.mu.Unlock()
		return fmt.Errorf("failed to marshal psiphon config: %w", err)
	}
	conf, err := os.CreateTemp("", fmt.Sprintf("luminet-psiphon-%d-*.json", e.socksPort))
	if err != nil {
		e.mu.Unlock()
		return fmt.Errorf("create psiphon config: %w", err)
	}
	confPath := conf.Name()
	if _, err := conf.Write(configData); err != nil {
		_ = conf.Close()
		e.mu.Unlock()
		_ = os.Remove(confPath)
		return fmt.Errorf("write psiphon config: %w", err)
	}
	if err := conf.Close(); err != nil {
		e.mu.Unlock()
		_ = os.Remove(confPath)
		return fmt.Errorf("close psiphon config: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, binary, "-config", confPath)
	cmd.SysProcAttr = hostprocess.GetDaemonSysProcAttr()
	if err := cmd.Start(); err != nil {
		cancel()
		e.mu.Unlock()
		_ = os.Remove(confPath)
		return fmt.Errorf("failed to start Psiphon core: %w", err)
	}
	done := make(chan struct{})
	e.cmd, e.cancel, e.done = cmd, cancel, done
	e.configPath, e.isRunning = confPath, true
	e.mu.Unlock()

	go e.monitorProcess(cmd, confPath, done)
	return e.confirmStartup(cmd, done)
}

func (e *psiphonEngine) monitorProcess(cmd *exec.Cmd, confPath string, done chan struct{}) {
	_ = cmd.Wait()
	_ = os.Remove(confPath)
	e.mu.Lock()
	if e.cmd == cmd {
		e.isRunning = false
		e.cmd, e.cancel, e.done = nil, nil, nil
		e.configPath = ""
	}
	e.mu.Unlock()
	close(done)
}

func (e *psiphonEngine) confirmStartup(cmd *exec.Cmd, done <-chan struct{}) error {
	timer := time.NewTimer(300 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-done:
		return fmt.Errorf("Psiphon process exited during startup")
	case <-timer.C:
		e.mu.Lock()
		running := e.cmd == cmd && e.isRunning
		e.mu.Unlock()
		if !running {
			return fmt.Errorf("Psiphon process exited during startup")
		}
		return nil
	}
}

func (e *psiphonEngine) Stop() {
	e.mu.Lock()
	if !e.isRunning {
		e.mu.Unlock()
		return
	}
	cmd, cancel, done := e.cmd, e.cancel, e.done
	e.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	if done != nil {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}
}

func (e *psiphonEngine) IsRunning() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.isRunning
}
