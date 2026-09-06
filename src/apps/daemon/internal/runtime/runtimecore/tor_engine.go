package runtimecore

import (
	"context"
	"fmt"
	hostprocess "github.com/maybeknott/luminet/internal/platform/process"
	system "github.com/maybeknott/luminet/internal/platform/system"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// torEngine owns one long-lived Tor subprocess.
type torEngine struct {
	mu                  sync.Mutex
	isRunning           bool
	binaryPath          string
	socksPort           int
	controlPort         int
	bridges             []string
	transportPlugins    []system.TorTransportPlugin
	cmd                 *exec.Cmd
	cancel              context.CancelFunc
	done                chan struct{}
	configPath          string
	dataDir             string
	startupTimeout      time.Duration
	startupPollInterval time.Duration
	bootstrapProbe      func(controlAddr, cookiePath string) (int, error)
}

func newTorEngine(socksPort, controlPort int) *torEngine {
	return &torEngine{
		socksPort:           socksPort,
		controlPort:         controlPort,
		startupTimeout:      60 * time.Second,
		startupPollInterval: 250 * time.Millisecond,
		bootstrapProbe:      probeTorBootstrap,
	}
}

func (e *torEngine) ConfigureBridges(bridges []string, obfs4ProxyPath string) {
	plugins := []system.TorTransportPlugin{}
	if obfs4ProxyPath != "" {
		plugins = append(plugins, system.TorTransportPlugin{Name: "obfs4", Executable: obfs4ProxyPath})
	}
	e.ConfigureBridgesWithTransports(bridges, plugins)
}

// ConfigureBridgesWithTransports configures Tor bridges and their explicit
// client pluggable transports. This keeps the runtime bridge seam transport-
// agnostic while preserving ConfigureBridges for legacy obfs4 callers.
func (e *torEngine) ConfigureBridgesWithTransports(bridges []string, plugins []system.TorTransportPlugin) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.bridges = append([]string(nil), bridges...)
	e.transportPlugins = cloneRuntimeTorTransportPlugins(plugins)
}

func (e *torEngine) FindBinary() (string, error) {
	if e.binaryPath != "" {
		if _, err := os.Stat(e.binaryPath); err == nil {
			return e.binaryPath, nil
		}
	}
	for _, bin := range []string{"tor.exe", "tor", `./bin/tor/tor.exe`, `./bin/tor/tor`} {
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
	return "", fmt.Errorf("failed to locate tor binary in PATH or repository-local bin directory")
}

func (e *torEngine) Start() error {
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
	dataDir, err := os.MkdirTemp("", fmt.Sprintf("luminet-tor-data-%d-*", e.socksPort))
	if err != nil {
		e.mu.Unlock()
		return fmt.Errorf("create Tor data directory: %w", err)
	}
	conf, err := os.CreateTemp("", fmt.Sprintf("luminet-torrc-%d-*", e.socksPort))
	if err != nil {
		e.mu.Unlock()
		_ = os.RemoveAll(dataDir)
		return fmt.Errorf("create torrc: %w", err)
	}
	confPath := conf.Name()
	builder := system.NewTorConfigBuilder().
		SocksPort(e.socksPort, false, false).
		ControlPort(e.controlPort).
		CookieAuth(filepath.Join(dataDir, "control_auth_cookie")).
		DataDirectory(dataDir).
		AvoidDiskWrites().
		ExtraLine("AvoidDiscoveredRendezvousPoints 1")
	if len(e.bridges) > 0 {
		builder.BridgesWithTransports(e.bridges, cloneRuntimeTorTransportPlugins(e.transportPlugins))
	}
	torrcContent, err := builder.BuildValidated()
	if err != nil {
		_ = conf.Close()
		e.mu.Unlock()
		_ = os.Remove(confPath)
		_ = os.RemoveAll(dataDir)
		return fmt.Errorf("build torrc: %w", err)
	}
	if _, err := conf.WriteString(torrcContent); err != nil {
		_ = conf.Close()
		e.mu.Unlock()
		_ = os.Remove(confPath)
		_ = os.RemoveAll(dataDir)
		return fmt.Errorf("write torrc: %w", err)
	}
	if err := conf.Close(); err != nil {
		e.mu.Unlock()
		_ = os.Remove(confPath)
		_ = os.RemoveAll(dataDir)
		return fmt.Errorf("close torrc: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, binary, "-f", confPath)
	cmd.SysProcAttr = hostprocess.GetDaemonSysProcAttr()
	if err := cmd.Start(); err != nil {
		cancel()
		e.mu.Unlock()
		_ = os.Remove(confPath)
		_ = os.RemoveAll(dataDir)
		return fmt.Errorf("failed to start Tor process: %w", err)
	}

	done := make(chan struct{})
	e.cmd, e.cancel, e.done = cmd, cancel, done
	e.configPath, e.dataDir = confPath, dataDir
	e.isRunning = true
	e.mu.Unlock()

	go e.monitorProcess(cmd, confPath, dataDir, done)
	if err := e.confirmStartup(cmd, done); err != nil {
		e.stopCommand(cmd)
		return err
	}
	return nil
}

func (e *torEngine) monitorProcess(cmd *exec.Cmd, confPath, dataDir string, done chan struct{}) {
	_ = cmd.Wait()
	_ = os.Remove(confPath)
	_ = os.RemoveAll(dataDir)
	e.mu.Lock()
	if e.cmd == cmd {
		e.isRunning = false
		e.cmd, e.cancel, e.done = nil, nil, nil
		e.configPath, e.dataDir = "", ""
	}
	e.mu.Unlock()
	close(done)
}

func (e *torEngine) confirmStartup(cmd *exec.Cmd, done <-chan struct{}) error {
	timeout := e.startupTimeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	poll := e.startupPollInterval
	if poll <= 0 {
		poll = 250 * time.Millisecond
	}
	probe := e.bootstrapProbe
	if probe == nil {
		probe = probeTorBootstrap
	}

	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(poll)
	defer ticker.Stop()

	var lastErr error
	check := func() (bool, error) {
		e.mu.Lock()
		running := e.cmd == cmd && e.isRunning
		controlPort := e.controlPort
		cookiePath := filepath.Join(e.dataDir, "control_auth_cookie")
		e.mu.Unlock()
		if !running {
			return false, fmt.Errorf("Tor process exited during startup")
		}
		progress, err := probe(fmt.Sprintf("127.0.0.1:%d", controlPort), cookiePath)
		if err != nil {
			lastErr = err
			return false, nil
		}
		if progress < 0 || progress > 100 {
			lastErr = fmt.Errorf("invalid Tor bootstrap progress %d", progress)
			return false, nil
		}
		return progress == 100, nil
	}

	// Probe immediately so an already-ready local Tor does not pay one poll interval.
	if ready, err := check(); err != nil {
		return err
	} else if ready {
		return nil
	}

	for {
		select {
		case <-done:
			return fmt.Errorf("Tor process exited during startup")
		case <-ticker.C:
			ready, err := check()
			if err != nil {
				return err
			}
			if ready {
				return nil
			}
		case <-deadline.C:
			if lastErr != nil {
				return fmt.Errorf("Tor bootstrap did not reach 100%% within %s: %w", timeout, lastErr)
			}
			return fmt.Errorf("Tor bootstrap did not reach 100%% within %s", timeout)
		}
	}
}

func probeTorBootstrap(controlAddr, cookiePath string) (int, error) {
	controller := system.NewTorController(controlAddr, cookiePath)
	if err := controller.Connect(); err != nil {
		return 0, err
	}
	defer controller.Close()
	return controller.BootstrapProgress()
}

func (e *torEngine) stopCommand(cmd *exec.Cmd) {
	e.mu.Lock()
	if e.cmd != cmd {
		e.mu.Unlock()
		return
	}
	cancel, done := e.cancel, e.done
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

func (e *torEngine) Stop() {
	e.mu.Lock()
	if !e.isRunning {
		e.mu.Unlock()
		return
	}
	cmd := e.cmd
	e.mu.Unlock()
	e.stopCommand(cmd)
}

func (e *torEngine) IsRunning() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.isRunning
}

// rotateIdentity asks the running Tor control port for a fresh circuit identity.
// The operation is deliberately one-shot: scheduling remains with the caller so
// Tor's own NEWNYM rate limiting remains authoritative.
func (e *torEngine) rotateIdentity() error {
	e.mu.Lock()
	if !e.isRunning || e.dataDir == "" || e.controlPort <= 0 {
		e.mu.Unlock()
		return fmt.Errorf("Tor engine is not running")
	}
	controlPort := e.controlPort
	cookiePath := filepath.Join(e.dataDir, "control_auth_cookie")
	e.mu.Unlock()

	controller := system.NewTorController(fmt.Sprintf("127.0.0.1:%d", controlPort), cookiePath)
	if err := controller.Connect(); err != nil {
		return fmt.Errorf("connect Tor control port: %w", err)
	}
	defer controller.Close()
	if err := controller.SignalNewNym(); err != nil {
		return fmt.Errorf("signal Tor NEWNYM: %w", err)
	}
	return nil
}

func cloneRuntimeTorTransportPlugins(in []system.TorTransportPlugin) []system.TorTransportPlugin {
	out := make([]system.TorTransportPlugin, len(in))
	for i, plugin := range in {
		out[i] = plugin
		out[i].Args = append([]string(nil), plugin.Args...)
	}
	return out
}
