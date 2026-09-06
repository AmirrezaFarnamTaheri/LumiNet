// Package xray provides Xray process lifecycle management for LumiNet.
// Ported from 3ax-ui-main/xray/process.go + 3ax-ui-main/xray/log_writer.go.
//
// Key peer-logics transplanted verbatim (PL-002):
//   1. JSON config marshalling: json.MarshalIndent → os.WriteFile
//   2. Binary naming: "xray-{GOOS}-{GOARCH}"
//   3. Windows "exit status 1" suppression in goroutine error handler
//   4. Version parsing: exec -version → bytes.Split(output, " ")[1]
//   5. API port discovery: scan InboundConfigs for tag == "api"
//   6. GC finalizer: runtime.SetFinalizer(p, stopProcess)
//   7. Log writer: crash detection + structured level routing
package xray

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// ── Path helpers ──────────────────────────────────────────────────────────────

// xrayBinDir is the directory where the Xray binary and config live.
// Override via SetBinDir for testing.
var xrayBinDir = filepath.Join("bin", "xray")

// SetBinDir overrides the binary directory (for testing or custom installs).
func SetBinDir(dir string) { xrayBinDir = dir }

// GetBinaryName returns the Xray binary filename for the current OS and architecture.
// Mirrors GetBinaryName() from 3ax-ui/xray/process.go verbatim.
func GetBinaryName() string {
	return fmt.Sprintf("xray-%s-%s", runtime.GOOS, runtime.GOARCH)
}

// GetBinaryPath returns the full path to the Xray binary executable.
func GetBinaryPath() string {
	return filepath.Join(xrayBinDir, GetBinaryName())
}

// GetConfigPath returns the path to the Xray JSON configuration file.
func GetConfigPath() string {
	return filepath.Join(xrayBinDir, "config.json")
}

// GetLogDir returns the log directory path.
func GetLogDir() string {
	return filepath.Join(xrayBinDir, "..", "log")
}

// ── Config types ──────────────────────────────────────────────────────────────

// InboundConfig is a minimal representation of an Xray inbound used for
// API port discovery and config marshalling.
type InboundConfig struct {
	Tag      string `json:"tag"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol,omitempty"`
	Listen   string `json:"listen,omitempty"`
}

// Config is a minimal Xray JSON configuration used for marshalling + API port discovery.
// Extend with additional Xray fields as needed.
type Config struct {
	// InboundConfigs must contain an entry with Tag == "api" for API port discovery.
	InboundConfigs []InboundConfig `json:"inbounds"`
	// Raw allows embedding arbitrary additional Xray JSON fields.
	Raw map[string]json.RawMessage `json:"-"`
}

// MarshalJSON serialises the Config, merging Raw fields with the inbounds.
func (c *Config) MarshalJSON() ([]byte, error) {
	m := make(map[string]any, len(c.Raw)+1)
	for k, v := range c.Raw {
		m[k] = v
	}
	m["inbounds"] = c.InboundConfigs
	return json.Marshal(m)
}

// ── LogWriter ─────────────────────────────────────────────────────────────────

// LogWriter processes and filters log output from the Xray process.
// Ported from 3ax-ui/xray/log_writer.go with go-logging replaced by slog.
type LogWriter struct {
	lastLine string
}

// NewLogWriter returns a new LogWriter.
func NewLogWriter() *LogWriter { return &LogWriter{} }

// LastLine returns the most recent log line captured from the process.
func (lw *LogWriter) LastLine() string { return lw.lastLine }

var (
	crashRegex  = regexp.MustCompile(`(?i)(panic|exception|stack trace|fatal error)`)
	xrayLogLine = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d{6}) \[([^\]]+)\] (.+)$`)
)

// Write implements io.Writer for capturing Xray stdout/stderr.
// Mirrors LogWriter.Write() from 3ax-ui verbatim, routing levels to slog.
func (lw *LogWriter) Write(m []byte) (n int, err error) {
	message := strings.TrimSpace(string(m))
	msgLower := strings.ToLower(message)

	// Windows: suppress noisy "exit status 1" from graceful kill.
	// Mirrors the suppression in 3ax-ui/xray/log_writer.go.
	if runtime.GOOS == "windows" && strings.Contains(msgLower, "exit status 1") {
		return len(m), nil
	}

	// Crash detection → write crash report.
	if crashRegex.MatchString(message) {
		slog.Error("xray: core crash detected", "output", message)
		lw.lastLine = message
		_ = writeCrashReport(m)
		return len(m), nil
	}

	// Parse individual log lines.
	for _, line := range strings.Split(message, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lineLower := strings.ToLower(line)
		// Filter noisy TLS handshake and connection-ends messages to Debug.
		if strings.Contains(lineLower, "tls handshake error") ||
			strings.Contains(lineLower, "connection ends") {
			slog.Debug("xray: " + line)
			lw.lastLine = ""
			continue
		}

		if matches := xrayLogLine.FindStringSubmatch(line); len(matches) > 3 {
			level := matches[2]
			body := matches[3]
			if strings.Contains(strings.ToLower(body), "failed") {
				slog.Error("xray: " + body)
			} else {
				switch level {
				case "Debug":
					slog.Debug("xray: " + body)
				case "Info":
					slog.Info("xray: " + body)
				case "Warning":
					slog.Warn("xray: " + body)
				case "Error":
					slog.Error("xray: " + body)
				default:
					slog.Debug("xray: " + line)
				}
			}
			lw.lastLine = ""
		} else {
			if strings.Contains(lineLower, "failed") {
				slog.Error("xray: " + line)
			} else {
				slog.Debug("xray: " + line)
			}
			lw.lastLine = line
		}
	}
	return len(m), nil
}

// writeCrashReport writes the crash output to a timestamped file in the bin dir.
func writeCrashReport(m []byte) error {
	name := fmt.Sprintf("core_crash_%s.log", time.Now().Format("20060102_150405"))
	path := filepath.Join(xrayBinDir, name)
	return os.WriteFile(path, m, 0o640)
}

// ── Process ───────────────────────────────────────────────────────────────────

// stopProcess is the GC finalizer target.
// Mirrors stopProcess() from 3ax-ui/xray/process.go verbatim.
func stopProcess(p *Process) { _ = p.Stop() }

// Process wraps an Xray subprocess and provides lifecycle management.
// Ported from 3ax-ui/xray/process.go; import paths remapped to luminet module.
type Process struct {
	cmd *exec.Cmd

	version string
	apiPort int

	onlineClients []string

	config     *Config
	configPath string // if non-empty, use instead of GetConfigPath() and remove on Stop
	logWriter  *LogWriter
	exitErr    error
	startTime  time.Time
}

// NewProcess creates a managed Xray Process with GC finalizer.
// Mirrors NewProcess() from 3ax-ui/xray/process.go verbatim.
func NewProcess(cfg *Config) *Process {
	p := &Process{
		version:   "Unknown",
		config:    cfg,
		logWriter: NewLogWriter(),
		startTime: time.Now(),
	}
	runtime.SetFinalizer(p, stopProcess)
	return p
}

// NewTestProcess creates a Process that writes config to a custom path and removes it on Stop.
// Mirrors NewTestProcess() from 3ax-ui/xray/process.go verbatim.
func NewTestProcess(cfg *Config, configPath string) *Process {
	p := NewProcess(cfg)
	p.configPath = configPath
	return p
}

// IsRunning reports whether the Xray subprocess is currently running.
// Mirrors IsRunning() from 3ax-ui/xray/process.go verbatim.
func (p *Process) IsRunning() bool {
	return p.cmd != nil && p.cmd.Process != nil && p.cmd.ProcessState == nil
}

// GetErr returns the last subprocess error.
func (p *Process) GetErr() error { return p.exitErr }

// GetResult returns the last captured log line or error string.
func (p *Process) GetResult() string {
	if len(p.logWriter.lastLine) == 0 && p.exitErr != nil {
		return p.exitErr.Error()
	}
	return p.logWriter.lastLine
}

// GetVersion returns the Xray version string (populated after Start).
func (p *Process) GetVersion() string { return p.version }

// GetAPIPort returns the gRPC API port discovered from the config (populated after Start).
func (p *Process) GetAPIPort() int { return p.apiPort }

// GetConfig returns the config used by this Process.
func (p *Process) GetConfig() *Config { return p.config }

// GetOnlineClients returns the currently-online client email list.
func (p *Process) GetOnlineClients() []string { return p.onlineClients }

// SetOnlineClients updates the online-client list.
func (p *Process) SetOnlineClients(users []string) { p.onlineClients = users }

// GetUptime returns the process uptime in seconds.
func (p *Process) GetUptime() uint64 { return uint64(time.Since(p.startTime).Seconds()) }

// refreshAPIPort scans InboundConfigs for tag == "api" to discover the gRPC API port.
// Mirrors refreshAPIPort() from 3ax-ui/xray/process.go verbatim.
func (p *Process) refreshAPIPort() {
	for _, inbound := range p.config.InboundConfigs {
		if inbound.Tag == "api" {
			p.apiPort = inbound.Port
			break
		}
	}
}

// refreshVersion runs `xray -version` and captures the version string.
// Mirrors refreshVersion() from 3ax-ui/xray/process.go verbatim.
func (p *Process) refreshVersion() {
	cmd := exec.Command(GetBinaryPath(), "-version")
	data, err := cmd.Output()
	if err != nil {
		p.version = "Unknown"
		return
	}
	parts := bytes.Split(data, []byte(" "))
	if len(parts) <= 1 {
		p.version = "Unknown"
	} else {
		p.version = strings.TrimSpace(string(parts[1]))
	}
}

// Start launches the Xray subprocess.
// Ported from 3ax-ui/xray/process.go Start() verbatim, with go-logging → slog.
func (p *Process) Start() (err error) {
	if p.IsRunning() {
		return errors.New("xray is already running")
	}

	defer func() {
		if err != nil {
			slog.Error("xray: failed to start process", "error", err)
			p.exitErr = err
		}
	}()

	// Marshal config to JSON.
	data, err := json.MarshalIndent(p.config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal xray config: %w", err)
	}

	// Ensure log directory exists.
	if mkErr := os.MkdirAll(GetLogDir(), 0o770); mkErr != nil {
		slog.Warn("xray: failed to create log dir", "error", mkErr)
	}

	// Write config file.
	cfgPath := GetConfigPath()
	if p.configPath != "" {
		cfgPath = p.configPath
	}
	if err = os.WriteFile(cfgPath, data, fs.ModePerm); err != nil {
		return fmt.Errorf("failed to write xray config: %w", err)
	}

	cmd := exec.Command(GetBinaryPath(), "-c", cfgPath)
	p.cmd = cmd
	cmd.Stdout = p.logWriter
	cmd.Stderr = p.logWriter

	// Start the subprocess and monitor in background.
	go func() {
		runErr := cmd.Run()
		if runErr != nil {
			// Windows: killing the process produces "exit status 1" — not a real error.
			// Mirrors the Windows suppression from 3ax-ui/xray/process.go verbatim.
			if runtime.GOOS == "windows" {
				if strings.Contains(strings.ToLower(runErr.Error()), "exit status 1") {
					p.exitErr = runErr
					return
				}
			}
			slog.Error("xray: process exited with error", "error", runErr)
			p.exitErr = runErr
		}
	}()

	p.refreshVersion()
	p.refreshAPIPort()
	return nil
}

// Stop terminates the Xray subprocess.
// Ported from 3ax-ui/xray/process.go Stop() verbatim.
func (p *Process) Stop() error {
	if !p.IsRunning() {
		return errors.New("xray is not running")
	}

	// Remove temporary test config file so the main config.json is never touched.
	if p.configPath != "" && p.configPath != GetConfigPath() {
		if _, statErr := os.Stat(p.configPath); statErr == nil {
			_ = os.Remove(p.configPath)
		}
	}

	// Windows: Kill(); Linux/macOS: SIGTERM.
	// Mirrors Stop() from 3ax-ui/xray/process.go verbatim.
	if runtime.GOOS == "windows" {
		return p.cmd.Process.Kill()
	}
	return p.cmd.Process.Signal(syscall.SIGTERM)
}

// Restart stops the process (if running) then starts it again.
func (p *Process) Restart() error {
	if p.IsRunning() {
		if err := p.Stop(); err != nil {
			return fmt.Errorf("stop failed: %w", err)
		}
		// Brief pause to allow the OS to reclaim the port.
		time.Sleep(500 * time.Millisecond)
	}
	return p.Start()
}
