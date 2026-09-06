package system

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultTunnelHealthURL        = "https://www.cloudflare.com/cdn-cgi/trace"
	DefaultTunnelHealthInterval   = 30 * time.Second
	DefaultTunnelHealthTimeout    = 10 * time.Second
	DefaultTunnelFailureThreshold = 3
	DefaultTunnelCooldown         = 5 * time.Minute
)

// TunnelMonitorConfig controls the health watchdog parameters.
type TunnelMonitorConfig struct {
	Enabled          bool          `json:"enabled"`
	URL              string        `json:"url"`
	ProxyURL         string        `json:"proxy_url"`
	Interval         time.Duration `json:"interval"`
	Timeout          time.Duration `json:"timeout"`
	FailureThreshold int           `json:"failure_threshold"`
	Cooldown         time.Duration `json:"cooldown"`
}

// TunnelRecoveryFunc represents the callback to invoke upon unrecoverable health failure.
type TunnelRecoveryFunc func(ctx context.Context) error

// TunnelMonitor periodically checks network/tunnel connectivity and triggers recovery on sustained failures.
type TunnelMonitor struct {
	cfg          TunnelMonitorConfig
	client       *http.Client
	recoverFn    TunnelRecoveryFunc
	failures     int
	lastRecovery time.Time
	now          func() time.Time
}

// DefaultTunnelMonitorConfig returns safe, production-grade default settings.
func DefaultTunnelMonitorConfig() TunnelMonitorConfig {
	return TunnelMonitorConfig{
		Enabled:          false,
		URL:              DefaultTunnelHealthURL,
		Interval:         DefaultTunnelHealthInterval,
		Timeout:          DefaultTunnelHealthTimeout,
		FailureThreshold: DefaultTunnelFailureThreshold,
		Cooldown:         DefaultTunnelCooldown,
	}
}

// TunnelMonitorConfigFromEnv loads configurations with LUMIN_TUNNEL_HEALTH_* overrides.
func TunnelMonitorConfigFromEnv() TunnelMonitorConfig {
	cfg := DefaultTunnelMonitorConfig()

	if val := os.Getenv("LUMIN_TUNNEL_HEALTH_MONITOR"); val != "" {
		cfg.Enabled = parseEnvBool(val)
	}
	if val := strings.TrimSpace(os.Getenv("LUMIN_TUNNEL_HEALTH_URL")); val != "" {
		cfg.URL = val
	}
	if val := strings.TrimSpace(os.Getenv("LUMIN_TUNNEL_HEALTH_PROXY")); val != "" {
		cfg.ProxyURL = val
	}
	cfg.Interval = parseEnvDuration("LUMIN_TUNNEL_HEALTH_INTERVAL", cfg.Interval)
	cfg.Timeout = parseEnvDuration("LUMIN_TUNNEL_HEALTH_TIMEOUT", cfg.Timeout)
	cfg.Cooldown = parseEnvDuration("LUMIN_TUNNEL_HEALTH_COOLDOWN", cfg.Cooldown)
	cfg.FailureThreshold = parseEnvInt("LUMIN_TUNNEL_HEALTH_FAILURES", cfg.FailureThreshold)

	return cfg.Normalize()
}

// Normalize sanitizes configuration fields and enforces safety invariants.
func (c TunnelMonitorConfig) Normalize() TunnelMonitorConfig {
	if strings.TrimSpace(c.URL) == "" {
		c.URL = DefaultTunnelHealthURL
	}
	c.URL = strings.TrimSpace(c.URL)
	c.ProxyURL = strings.TrimSpace(c.ProxyURL)

	if c.Interval < time.Second {
		c.Interval = DefaultTunnelHealthInterval
	}
	if c.Timeout < time.Second {
		c.Timeout = DefaultTunnelHealthTimeout
	}
	if c.FailureThreshold < 1 {
		c.FailureThreshold = DefaultTunnelFailureThreshold
	}
	if c.Cooldown < time.Second {
		c.Cooldown = DefaultTunnelCooldown
	}

	return c
}

// NewTunnelMonitor constructs a new watchdog monitor instance.
func NewTunnelMonitor(cfg TunnelMonitorConfig, recoverFn TunnelRecoveryFunc) (*TunnelMonitor, error) {
	cfg = cfg.Normalize()

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ResponseHeaderTimeout: cfg.Timeout,
	}

	if cfg.ProxyURL != "" {
		pURL, err := url.Parse(cfg.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid tunnel monitor proxy url: %w", err)
		}
		transport.Proxy = http.ProxyURL(pURL)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
	}

	return &TunnelMonitor{
		cfg:       cfg,
		client:    client,
		recoverFn: recoverFn,
		now:       time.Now,
	}, nil
}

// NewTunnelMonitorWithClient creates a monitor with a custom HTTP client and clock for testing.
func NewTunnelMonitorWithClient(cfg TunnelMonitorConfig, client *http.Client, recoverFn TunnelRecoveryFunc, now func() time.Time) *TunnelMonitor {
	cfg = cfg.Normalize()
	if client == nil {
		client = &http.Client{Timeout: cfg.Timeout}
	}
	if now == nil {
		now = time.Now
	}
	return &TunnelMonitor{
		cfg:       cfg,
		client:    client,
		recoverFn: recoverFn,
		now:       now,
	}
}

// Run executes the monitoring loop until the context is canceled.
func (m *TunnelMonitor) Run(ctx context.Context) {
	if m == nil || !m.cfg.Enabled {
		return
	}

	ticker := time.NewTicker(m.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = m.Step(ctx)
		}
	}
}

// Step performs an individual probe and executes recovery if threshold is breached.
// Returns (recovered bool, err error).
func (m *TunnelMonitor) Step(ctx context.Context) (bool, error) {
	if m == nil {
		return false, errors.New("nil tunnel monitor")
	}

	if err := m.probe(ctx); err != nil {
		m.failures++

		if m.failures < m.cfg.FailureThreshold {
			return false, fmt.Errorf("probe failed (%d/%d): %w", m.failures, m.cfg.FailureThreshold, err)
		}

		currentTime := m.now()
		if !m.lastRecovery.IsZero() && currentTime.Sub(m.lastRecovery) < m.cfg.Cooldown {
			m.failures = m.cfg.FailureThreshold
			return false, fmt.Errorf("probe failed (%d/%d); recovery cooldown active: %w", m.failures, m.cfg.FailureThreshold, err)
		}

		if m.recoverFn == nil {
			m.failures = m.cfg.FailureThreshold
			return false, errors.New("recovery function not set")
		}

		if recErr := m.recoverFn(ctx); recErr != nil {
			return false, fmt.Errorf("recovery handler failed after probe failure %w: %w", err, recErr)
		}

		m.lastRecovery = currentTime
		m.failures = 0
		return true, err
	}

	m.failures = 0
	return false, nil
}

func (m *TunnelMonitor) probe(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.cfg.URL, nil)
	if err != nil {
		return err
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("unexpected http status %d", resp.StatusCode)
	}

	return nil
}

func parseEnvBool(val string) bool {
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "1", "true", "yes", "y", "on", "enable", "enabled":
		return true
	default:
		return false
	}
}

func parseEnvDuration(name string, fallback time.Duration) time.Duration {
	val := strings.TrimSpace(os.Getenv(name))
	if val == "" {
		return fallback
	}
	d, err := time.ParseDuration(val)
	if err != nil {
		return fallback
	}
	return d
}

func parseEnvInt(name string, fallback int) int {
	val := strings.TrimSpace(os.Getenv(name))
	if val == "" {
		return fallback
	}
	n, err := strconv.Atoi(val)
	if err != nil {
		return fallback
	}
	return n
}
