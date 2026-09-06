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

// ikev2Engine owns a single non-interactive strongSwan charon-cmd process.
// It intentionally supports the public-key IKEv2 profile only: charon-cmd
// obtains EAP/PSK secrets from a controlling TTY, which is unsuitable for a
// daemon child process.  Certificate/private-key paths remain caller-owned.
type ikev2Engine struct {
	mu             sync.Mutex
	isRunning      bool
	binaryPath     string
	server         string
	identity       string
	remoteIdentity string
	certificate    string
	privateKey     string
	localTS        string
	remoteTS       string
	ikeProposals   []string
	espProposals   []string
	cmd            *exec.Cmd
	cancel         context.CancelFunc
	done           chan struct{}
}

func newIKEv2Engine(req Request) *ikev2Engine {
	return &ikev2Engine{
		server: req.Server, identity: req.Identity, remoteIdentity: req.RemoteIdentity,
		certificate: req.Certificate, privateKey: req.PrivateKey,
		localTS: req.LocalTS, remoteTS: req.RemoteTS,
		ikeProposals: append([]string(nil), req.IKEProposals...),
		espProposals: append([]string(nil), req.ESPProposals...),
	}
}

func (e *ikev2Engine) FindBinary() (string, error) {
	if e.binaryPath != "" {
		if _, err := os.Stat(e.binaryPath); err == nil {
			return e.binaryPath, nil
		}
	}
	for _, bin := range []string{"charon-cmd", `./bin/strongswan/charon-cmd`, `./bin/strongswan/charon-cmd.exe`} {
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
	return "", fmt.Errorf("failed to locate charon-cmd in PATH or repository-local bin directory")
}

func (e *ikev2Engine) commandArgs() []string {
	args := []string{"--debug", "1", "--host", e.server, "--identity", e.identity, "--profile", "ikev2-pub", "--cert", e.certificate, "--priv", e.privateKey}
	if e.remoteIdentity != "" {
		args = append(args, "--remote-identity", e.remoteIdentity)
	}
	if e.localTS != "" {
		args = append(args, "--local-ts", e.localTS)
	}
	if e.remoteTS != "" {
		args = append(args, "--remote-ts", e.remoteTS)
	}
	for _, proposal := range e.ikeProposals {
		args = append(args, "--ike-proposal", proposal)
	}
	for _, proposal := range e.espProposals {
		args = append(args, "--esp-proposal", proposal)
	}
	return args
}

func (e *ikev2Engine) Start() error {
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
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		cancel()
		e.mu.Unlock()
		return fmt.Errorf("start charon-cmd: %w", err)
	}
	done := make(chan struct{})
	e.cmd, e.cancel, e.done, e.isRunning = cmd, cancel, done, true
	e.mu.Unlock()
	go e.monitorProcess(cmd, done)
	return e.confirmStartup(cmd, done)
}

func (e *ikev2Engine) monitorProcess(cmd *exec.Cmd, done chan struct{}) {
	_ = cmd.Wait()
	e.mu.Lock()
	if e.cmd == cmd {
		e.isRunning = false
		e.cmd, e.cancel, e.done = nil, nil, nil
	}
	e.mu.Unlock()
	close(done)
}

func (e *ikev2Engine) confirmStartup(cmd *exec.Cmd, done <-chan struct{}) error {
	timer := time.NewTimer(750 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-done:
		return fmt.Errorf("charon-cmd exited during startup")
	case <-timer.C:
		e.mu.Lock()
		running := e.cmd == cmd && e.isRunning
		e.mu.Unlock()
		if !running {
			return fmt.Errorf("charon-cmd exited during startup")
		}
		return nil
	}
}

func (e *ikev2Engine) Stop() {
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

func (e *ikev2Engine) IsRunning() bool { e.mu.Lock(); defer e.mu.Unlock(); return e.isRunning }

func normalizeIKEv2Request(req Request) (Request, error) {
	clean := func(label, value string, required bool) (string, error) {
		value = strings.TrimSpace(value)
		if required && value == "" {
			return "", fmt.Errorf("%w: IKEv2 %s is required", ErrInvalidRequest, label)
		}
		if len(value) > 1024 || strings.ContainsAny(value, "\r\n\x00") {
			return "", fmt.Errorf("%w: invalid IKEv2 %s", ErrInvalidRequest, label)
		}
		return value, nil
	}
	var err error
	if req.Server, err = clean("server", req.Server, true); err != nil {
		return Request{}, err
	}
	if req.Identity, err = clean("identity", req.Identity, true); err != nil {
		return Request{}, err
	}
	if req.RemoteIdentity, err = clean("remote identity", req.RemoteIdentity, false); err != nil {
		return Request{}, err
	}
	if req.Certificate, err = clean("certificate path", req.Certificate, true); err != nil {
		return Request{}, err
	}
	if req.PrivateKey, err = clean("private key path", req.PrivateKey, true); err != nil {
		return Request{}, err
	}
	if req.LocalTS, err = clean("local traffic selector", req.LocalTS, false); err != nil {
		return Request{}, err
	}
	if req.RemoteTS, err = clean("remote traffic selector", req.RemoteTS, false); err != nil {
		return Request{}, err
	}
	if len(req.IKEProposals) > 8 || len(req.ESPProposals) > 8 {
		return Request{}, fmt.Errorf("%w: too many IKEv2 proposals", ErrInvalidRequest)
	}
	validateProposals := func(kind string, proposals []string) error {
		for _, p := range proposals {
			if strings.TrimSpace(p) == "" || len(p) > 256 || strings.ContainsAny(p, "\r\n\x00") {
				return fmt.Errorf("%w: invalid %s proposal", ErrInvalidRequest, kind)
			}
		}
		return nil
	}
	if err := validateProposals("IKE", req.IKEProposals); err != nil {
		return Request{}, err
	}
	if err := validateProposals("ESP", req.ESPProposals); err != nil {
		return Request{}, err
	}
	req.SocksPort, req.ControlPort = 0, 0
	return req, nil
}
