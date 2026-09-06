package relayclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

// CoreEngineType designates the underlying tunnel transport mechanism.
type CoreEngineType string

const (
	EngineAppsScript   CoreEngineType = "apps_script"
	EngineDriveStorage CoreEngineType = "drive_storage"
)

// CoreLifecycleState represents the supervisor operational status.
type CoreLifecycleState string

const (
	StateStopped  CoreLifecycleState = "stopped"
	StateStarting CoreLifecycleState = "starting"
	StateRunning  CoreLifecycleState = "running"
	StateError    CoreLifecycleState = "error"
)

// LogSeverity defines log telemetry classification.
type LogSeverity string

const (
	LogInfo  LogSeverity = "info"
	LogWarn  LogSeverity = "warn"
	LogError LogSeverity = "error"
	LogOAuth LogSeverity = "oauth"
)

// LogEntry represents a single timestamped telemetry event.
type LogEntry struct {
	Level     LogSeverity `json:"level"`
	Message   string      `json:"message"`
	Timestamp string      `json:"timestamp"`
}

// OAuthFlowState tracks interactive OAuth2 authorization.
type OAuthFlowState string

const (
	OAuthNone            OAuthFlowState = "none"
	OAuthWaitingForInput OAuthFlowState = "waiting"
	OAuthDone            OAuthFlowState = "done"
)

var (
	wslNoiseRegexes = []*regexp.Regexp{
		regexp.MustCompile(`(?i)^wsl:`),
		regexp.MustCompile(`(?i)localhost proxy`),
		regexp.MustCompile(`(?i)NAT mode does not support`),
		regexp.MustCompile(`(?i)not mirrored into WSL`),
	}

	binaryInfoRegexes = []*regexp.Regexp{
		regexp.MustCompile(`\bCARRIER\s+INFO\b`),
		regexp.MustCompile(`\bCLIENT\s+INFO\b`),
		regexp.MustCompile(`\bSERVER\s+INFO\b`),
		regexp.MustCompile(`\bSOCKS\s+INFO\b`),
		regexp.MustCompile(`(?i)\bINFO\b.*relay returned`),
		regexp.MustCompile(`(?i)\bINFO\b.*non-batch payload`),
		regexp.MustCompile(`^\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\s`),
		regexp.MustCompile(`(?i)Zero-Config|Flow-Data|OAuth|Trading code|refresh token|Google Drive|FlowDriver|tunnel.*up|session.*new`),
	}

	requestLineRegexes = []*regexp.Regexp{
		regexp.MustCompile(`(?i)poll\s+ok|POST.*exec|relay\s+request|script\.google\.com|urlFetch`),
		regexp.MustCompile(`(?i)SOCKS\s+INFO\s+new\s+session`),
		regexp.MustCompile(`(?i)CARRIER\s+INFO\s+relay\s+ok`),
		regexp.MustCompile(`(?i)drive.*upload|drive.*download|new\s+session|request\s+forwarded`),
	}

	oauthURLRegex = regexp.MustCompile(`https://accounts\.google\.com/[^\s"']+`)
)

// IsWSLNoise checks if a line is a known virtualisation/WSL info message.
func IsWSLNoise(line string) bool {
	for _, re := range wslNoiseRegexes {
		if re.MatchString(line) {
			return true
		}
	}
	return false
}

// IsBinaryInfoPattern checks if a stderr line is standard Go/custom info rather than an error.
func IsBinaryInfoPattern(line string) bool {
	for _, re := range binaryInfoRegexes {
		if re.MatchString(line) {
			return true
		}
	}
	return false
}

// IsRequestForwardLine checks if a line indicates an active forwarded connection.
func IsRequestForwardLine(line string) bool {
	for _, re := range requestLineRegexes {
		if re.MatchString(line) {
			return true
		}
	}
	return false
}

// ExtractOAuthURL retrieves a Google OAuth2 authorization URL from stdout/stderr.
func ExtractOAuthURL(line string) (string, bool) {
	match := oauthURLRegex.FindString(line)
	if match != "" {
		return match, true
	}
	return "", false
}

// ClassifyStderrLine classifies a stderr line, demoting noise/Go info to LogInfo or extracting OAuth.
func ClassifyStderrLine(line string) (LogSeverity, string) {
	if url, ok := ExtractOAuthURL(line); ok {
		return LogOAuth, url
	}
	if IsWSLNoise(line) || IsBinaryInfoPattern(line) {
		return LogInfo, ""
	}
	return LogError, ""
}

// CoreSupervisor manages the lifecycles, log streaming, and telemetry of multiple tunnel cores.
type CoreSupervisor struct {
	mu        sync.RWMutex
	processes map[string]*ManagedCore
	deadLogs  map[string][]LogEntry
}

// ManagedCore represents a running or monitored tunnel process.
type ManagedCore struct {
	mu                sync.Mutex
	ID                string
	EngineType        CoreEngineType
	State             CoreLifecycleState
	PID               int
	LogRing           []LogEntry
	MaxLogs           int
	RequestCount      int
	PendingFlushCount int
	OAuthState        OAuthFlowState
	Listeners         map[chan LogEntry]struct{}
	StdinWriter       func(string) error
}

func NewCoreSupervisor() *CoreSupervisor {
	return &CoreSupervisor{
		processes: make(map[string]*ManagedCore),
		deadLogs:  make(map[string][]LogEntry),
	}
}

// RegisterCore registers or tracks a core process.
func (s *CoreSupervisor) RegisterCore(id string, engineType CoreEngineType, pid int, stdinWriter func(string) error) *ManagedCore {
	s.mu.Lock()
	defer s.mu.Unlock()

	core := &ManagedCore{
		ID:          id,
		EngineType:  engineType,
		State:       StateRunning,
		PID:         pid,
		LogRing:     make([]LogEntry, 0, 500),
		MaxLogs:     500,
		OAuthState:  OAuthNone,
		Listeners:   make(map[chan LogEntry]struct{}),
		StdinWriter: stdinWriter,
	}
	s.processes[id] = core
	return core
}

// PushLog processes and appends an incoming log line for a monitored core.
func (s *CoreSupervisor) PushLog(id string, isStderr bool, rawLine string) LogEntry {
	s.mu.RLock()
	core, exists := s.processes[id]
	s.mu.RUnlock()

	line := strings.TrimRight(rawLine, "\r\n")
	var level LogSeverity
	var oauthURL string

	if isStderr {
		level, oauthURL = ClassifyStderrLine(line)
	} else {
		if url, ok := ExtractOAuthURL(line); ok {
			level = LogOAuth
			oauthURL = url
		} else {
			level = LogInfo
		}
	}

	entry := LogEntry{
		Level:     level,
		Message:   line,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	if !exists {
		return entry
	}

	core.mu.Lock()
	defer core.mu.Unlock()

	if oauthURL != "" && core.OAuthState == OAuthNone {
		core.OAuthState = OAuthWaitingForInput
	}

	if len(core.LogRing) >= core.MaxLogs {
		core.LogRing = core.LogRing[1:]
	}
	core.LogRing = append(core.LogRing, entry)

	if IsRequestForwardLine(line) {
		core.RequestCount++
		core.PendingFlushCount++
	}

	for ch := range core.Listeners {
		select {
		case ch <- entry:
		default:
		}
	}

	return entry
}

// Subscribe returns a channel receiving real-time log entries and an unsubscribe closure.
func (s *CoreSupervisor) Subscribe(id string) (<-chan LogEntry, func(), error) {
	s.mu.RLock()
	core, exists := s.processes[id]
	dead, hasDead := s.deadLogs[id]
	s.mu.RUnlock()

	ch := make(chan LogEntry, 100)

	if !exists {
		if hasDead {
			for _, entry := range dead {
				ch <- entry
			}
		}
		close(ch)
		return ch, func() {}, nil
	}

	core.mu.Lock()
	for _, entry := range core.LogRing {
		select {
		case ch <- entry:
		default:
		}
	}
	core.Listeners[ch] = struct{}{}
	core.mu.Unlock()

	unsub := func() {
		core.mu.Lock()
		delete(core.Listeners, ch)
		core.mu.Unlock()
	}

	return ch, unsub, nil
}

// SendStdin writes input directly to the running core's standard input (e.g. OAuth callback).
func (s *CoreSupervisor) SendStdin(id string, input string) error {
	s.mu.RLock()
	core, exists := s.processes[id]
	s.mu.RUnlock()

	if !exists {
		return errors.New("core not running")
	}

	core.mu.Lock()
	defer core.mu.Unlock()

	if core.StdinWriter == nil {
		return errors.New("core does not support stdin writing")
	}

	if err := core.StdinWriter(input); err != nil {
		return err
	}

	core.OAuthState = OAuthDone
	entry := LogEntry{
		Level:     LogInfo,
		Message:   "[supervisor] OAuth callback forwarded to core stdin",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	core.LogRing = append(core.LogRing, entry)
	for ch := range core.Listeners {
		select {
		case ch <- entry:
		default:
		}
	}
	return nil
}

// GetRecentLogs retrieves the recent in-memory log buffer for a core.
func (s *CoreSupervisor) GetRecentLogs(id string, limit int) []LogEntry {
	s.mu.RLock()
	core, exists := s.processes[id]
	dead, hasDead := s.deadLogs[id]
	s.mu.RUnlock()

	var logs []LogEntry
	if exists {
		core.mu.Lock()
		logs = make([]LogEntry, len(core.LogRing))
		copy(logs, core.LogRing)
		core.mu.Unlock()
	} else if hasDead {
		logs = make([]LogEntry, len(dead))
		copy(logs, dead)
	}

	if limit <= 0 || limit >= len(logs) {
		return logs
	}
	return logs[len(logs)-limit:]
}

// UnregisterCore archives the final log buffer and removes the active process tracking.
func (s *CoreSupervisor) UnregisterCore(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if core, exists := s.processes[id]; exists {
		core.mu.Lock()
		s.deadLogs[id] = append([]LogEntry(nil), core.LogRing...)
		for ch := range core.Listeners {
			close(ch)
		}
		core.Listeners = nil
		core.mu.Unlock()
		delete(s.processes, id)
	}
}

// ── Relay Core Configuration Synthesizers ─────────────────────────────────────

// AppsScriptRelayConfig defines settings for Google Apps Script SOCKS5 relay.
type AppsScriptRelayConfig struct {
	SocksHost  string      `json:"socks_host"`
	SocksPort  int         `json:"socks_port"`
	GoogleHost string      `json:"google_host"`
	SNI        interface{} `json:"sni"` // string or []string
	ScriptKeys []string    `json:"script_keys"`
	TunnelKey  string      `json:"tunnel_key"`
	SocksUser  string      `json:"socks_user,omitempty"`
	SocksPass  string      `json:"socks_pass,omitempty"`
}

// GenerateAppsScriptConfigJSON synthesizes JSON for GooseRelay core.
func GenerateAppsScriptConfigJSON(cfg AppsScriptRelayConfig) ([]byte, error) {
	if cfg.SocksPort <= 0 || cfg.SocksPort > 65535 {
		return nil, fmt.Errorf("invalid socks port: %d", cfg.SocksPort)
	}
	if cfg.GoogleHost == "" {
		cfg.GoogleHost = "216.239.38.120"
	}
	if cfg.SNI == nil || cfg.SNI == "" {
		cfg.SNI = "www.google.com"
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// DriveStorageTransport holds transport routing parameters for Google Drive proxy.
type DriveStorageTransport struct {
	TargetIP           string `json:"TargetIP"`
	SNI                string `json:"SNI"`
	HostHeader         string `json:"HostHeader"`
	InsecureSkipVerify bool   `json:"InsecureSkipVerify"`
}

// DriveStorageRelayConfig defines settings for Google Drive API storage tunnel.
type DriveStorageRelayConfig struct {
	ListenAddr     string                `json:"listen_addr"`
	StorageType    string                `json:"storage_type"`
	GoogleFolderID string                `json:"google_folder_id,omitempty"`
	RefreshRateMs  int                   `json:"refresh_rate_ms"`
	FlushRateMs    int                   `json:"flush_rate_ms"`
	Transport      DriveStorageTransport `json:"transport"`
}

// GenerateDriveStorageConfigJSON synthesizes JSON for FlowDriver core.
func GenerateDriveStorageConfigJSON(cfg DriveStorageRelayConfig) ([]byte, error) {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:1080"
	}
	cfg.StorageType = "google"
	if cfg.RefreshRateMs <= 0 {
		cfg.RefreshRateMs = 200
	}
	if cfg.FlushRateMs <= 0 {
		cfg.FlushRateMs = 300
	}
	if cfg.Transport.TargetIP == "" {
		cfg.Transport.TargetIP = "216.239.38.120:443"
	}
	if cfg.Transport.SNI == "" {
		cfg.Transport.SNI = "google.com"
	}
	if cfg.Transport.HostHeader == "" {
		cfg.Transport.HostHeader = "www.googleapis.com"
	}
	return json.MarshalIndent(cfg, "", "  ")
}
