package runtimecore

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	hostprocess "github.com/maybeknott/luminet/internal/platform/process"
)

var defaultSSTPPPPOptions = []string{
	"usepeerdns",
	"require-mppe",
	"require-mschap-v2",
	"refuse-eap",
	"refuse-pap",
	"refuse-chap",
	"refuse-mschap",
	"nobsdcomp",
	"nodeflate",
}

// sstpEngine owns one system-tunnel SSTP client process. Unlike Tor and
// Psiphon it exposes no local SOCKS port; sstpc launches pppd and configures a
// PPP interface according to the supplied PPP options.
type sstpEngine struct {
	mu               sync.Mutex
	isRunning        bool
	binaryPath       string
	server           string
	username         string
	password         string
	upstreamProxy    string
	caCert           string
	allowCertWarning bool
	pppOptions       []string
	cmd              *exec.Cmd
	cancel           context.CancelFunc
	done             chan struct{}
}

func newSSTPEngine(req Request) *sstpEngine {
	return &sstpEngine{
		server: req.Server, username: req.Username, password: req.Password,
		upstreamProxy: req.UpstreamProxy, caCert: req.CACert,
		allowCertWarning: req.AllowCertWarning,
		pppOptions:       append([]string(nil), req.PPPOptions...),
	}
}

func (e *sstpEngine) FindBinary() (string, error) {
	if e.binaryPath != "" {
		if _, err := os.Stat(e.binaryPath); err == nil {
			return e.binaryPath, nil
		}
	}
	for _, bin := range []string{"sstpc", `./bin/sstp/sstpc`, `./bin/sstp/sstpc.exe`} {
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
	return "", fmt.Errorf("failed to locate sstpc in PATH or repository-local bin directory")
}

func (e *sstpEngine) commandArgs() []string {
	args := []string{"--log-stderr", "--log-level", "2", "--save-server-route", "--tls-ext"}
	if e.username != "" {
		args = append(args, "--user", e.username)
	}
	if e.password != "" {
		args = append(args, "--password", e.password)
	}
	if e.upstreamProxy != "" {
		args = append(args, "--proxy", e.upstreamProxy)
	}
	if e.caCert != "" {
		args = append(args, "--ca-cert", e.caCert)
	}
	if e.allowCertWarning {
		args = append(args, "--cert-warn")
	}
	args = append(args, e.server)
	ppp := e.pppOptions
	if len(ppp) == 0 {
		ppp = defaultSSTPPPPOptions
	}
	return append(args, ppp...)
}

func (e *sstpEngine) Start() error {
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
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, binary, e.commandArgs()...)
	cmd.SysProcAttr = hostprocess.GetDaemonSysProcAttr()
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		cancel()
		e.mu.Unlock()
		return fmt.Errorf("start sstpc: %w", err)
	}
	done := make(chan struct{})
	e.cmd, e.cancel, e.done, e.isRunning = cmd, cancel, done, true
	e.mu.Unlock()

	go e.monitorProcess(cmd, done)
	return e.confirmStartup(cmd, done)
}

func (e *sstpEngine) monitorProcess(cmd *exec.Cmd, done chan struct{}) {
	_ = cmd.Wait()
	e.mu.Lock()
	if e.cmd == cmd {
		e.isRunning = false
		e.cmd, e.cancel, e.done = nil, nil, nil
	}
	e.mu.Unlock()
	close(done)
}

func (e *sstpEngine) confirmStartup(cmd *exec.Cmd, done <-chan struct{}) error {
	timer := time.NewTimer(500 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-done:
		return fmt.Errorf("sstpc exited during startup")
	case <-timer.C:
		e.mu.Lock()
		running := e.cmd == cmd && e.isRunning
		e.mu.Unlock()
		if !running {
			return fmt.Errorf("sstpc exited during startup")
		}
		return nil
	}
}

func (e *sstpEngine) Stop() {
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
	_ = hostprocess.KillDaemonProcess(cmd)
	if done != nil {
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
	}
}

func (e *sstpEngine) IsRunning() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.isRunning
}

func normalizeSSTPServer(server string) (string, error) {
	server = strings.TrimSpace(server)
	if server == "" {
		return "", fmt.Errorf("%w: SSTP server is required", ErrInvalidRequest)
	}
	if strings.ContainsAny(server, "\r\n\x00") {
		return "", fmt.Errorf("%w: SSTP server contains control characters", ErrInvalidRequest)
	}
	if len(server) > 512 {
		return "", fmt.Errorf("%w: SSTP server is too long", ErrInvalidRequest)
	}
	return server, nil
}
