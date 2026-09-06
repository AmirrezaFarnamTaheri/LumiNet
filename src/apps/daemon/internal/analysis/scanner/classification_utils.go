// Package scanner implements host and dns probing operations.

package scanner

import (
	"context"
	"errors"
	"math"
	"strings"
	"sync"
)

// ScanResultMetrics holds raw network performance and capability values.
type ScanResultMetrics struct {
	TCP                   bool   `json:"tcp"`
	TLS                   bool   `json:"tls"`
	HTTP                  bool   `json:"http"`
	TLSVersion            string `json:"tls_version"`
	ALPN                  string `json:"alpn"`
	HTTP3Hint             bool   `json:"http3_hint"`
	NetworkClassification string `json:"network_classification"`
	TLSFingerprint        string `json:"tls_fingerprint"`
	LatencyMS             int64  `json:"latency_ms"`
	Error                 string `json:"error"`
}

// Getters & Setters for ScanResultMetrics
func (m *ScanResultMetrics) GetTCP() bool { return m.TCP }
func (m *ScanResultMetrics) SetTCP(v bool) { m.TCP = v }
func (m *ScanResultMetrics) GetTLS() bool { return m.TLS }
func (m *ScanResultMetrics) SetTLS(v bool) { m.TLS = v }
func (m *ScanResultMetrics) GetHTTP() bool { return m.HTTP }
func (m *ScanResultMetrics) SetHTTP(v bool) { m.HTTP = v }
func (m *ScanResultMetrics) GetTLSVersion() string { return m.TLSVersion }
func (m *ScanResultMetrics) SetTLSVersion(v string) { m.TLSVersion = v }
func (m *ScanResultMetrics) GetALPN() string { return m.ALPN }
func (m *ScanResultMetrics) SetALPN(v string) { m.ALPN = v }
func (m *ScanResultMetrics) GetHTTP3Hint() bool { return m.HTTP3Hint }
func (m *ScanResultMetrics) SetHTTP3Hint(v bool) { m.HTTP3Hint = v }
func (m *ScanResultMetrics) GetNetworkClassification() string { return m.NetworkClassification }
func (m *ScanResultMetrics) SetNetworkClassification(v string) { m.NetworkClassification = v }
func (m *ScanResultMetrics) GetTLSFingerprint() string { return m.TLSFingerprint }
func (m *ScanResultMetrics) SetTLSFingerprint(v string) { m.TLSFingerprint = v }
func (m *ScanResultMetrics) GetLatencyMS() int64 { return m.LatencyMS }
func (m *ScanResultMetrics) SetLatencyMS(v int64) { m.LatencyMS = v }
func (m *ScanResultMetrics) GetError() string { return m.Error }
func (m *ScanResultMetrics) SetError(v string) { m.Error = v }

// Builders for ScanResultMetrics
func (m *ScanResultMetrics) WithTCP(v bool) *ScanResultMetrics { m.SetTCP(v); return m }
func (m *ScanResultMetrics) WithTLS(v bool) *ScanResultMetrics { m.SetTLS(v); return m }
func (m *ScanResultMetrics) WithHTTP(v bool) *ScanResultMetrics { m.SetHTTP(v); return m }
func (m *ScanResultMetrics) WithTLSVersion(v string) *ScanResultMetrics { m.SetTLSVersion(v); return m }
func (m *ScanResultMetrics) WithALPN(v string) *ScanResultMetrics { m.SetALPN(v); return m }
func (m *ScanResultMetrics) WithHTTP3Hint(v bool) *ScanResultMetrics { m.SetHTTP3Hint(v); return m }
func (m *ScanResultMetrics) WithNetworkClassification(v string) *ScanResultMetrics { m.SetNetworkClassification(v); return m }
func (m *ScanResultMetrics) WithTLSFingerprint(v string) *ScanResultMetrics { m.SetTLSFingerprint(v); return m }
func (m *ScanResultMetrics) WithLatencyMS(v int64) *ScanResultMetrics { m.SetLatencyMS(v); return m }
func (m *ScanResultMetrics) WithError(v string) *ScanResultMetrics { m.SetError(v); return m }

// NetworkClassifierConfig scores host performance results and identifies routing classification.
type NetworkClassifierConfig struct {
	mu                    sync.RWMutex
	MinScore              int
	DefaultClassification string
	CloudflareHost        string
	FastlyHost            string
	AkamaiHost            string
	CloudfrontHost        string
	TimeoutPenalty        int
	ResetPenalty          int
	RefusedPenalty        int
	IsActive              bool
}

// Getters & Setters for NetworkClassifierConfig
func (c *NetworkClassifierConfig) GetMinScore() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.MinScore }
func (c *NetworkClassifierConfig) SetMinScore(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.MinScore = v }
func (c *NetworkClassifierConfig) GetDefaultClassification() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.DefaultClassification }
func (c *NetworkClassifierConfig) SetDefaultClassification(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.DefaultClassification = v }
func (c *NetworkClassifierConfig) GetCloudflareHost() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.CloudflareHost }
func (c *NetworkClassifierConfig) SetCloudflareHost(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.CloudflareHost = v }
func (c *NetworkClassifierConfig) GetFastlyHost() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.FastlyHost }
func (c *NetworkClassifierConfig) SetFastlyHost(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.FastlyHost = v }
func (c *NetworkClassifierConfig) GetAkamaiHost() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.AkamaiHost }
func (c *NetworkClassifierConfig) SetAkamaiHost(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.AkamaiHost = v }
func (c *NetworkClassifierConfig) GetCloudfrontHost() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.CloudfrontHost }
func (c *NetworkClassifierConfig) SetCloudfrontHost(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.CloudfrontHost = v }
func (c *NetworkClassifierConfig) GetTimeoutPenalty() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.TimeoutPenalty }
func (c *NetworkClassifierConfig) SetTimeoutPenalty(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.TimeoutPenalty = v }
func (c *NetworkClassifierConfig) GetResetPenalty() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.ResetPenalty }
func (c *NetworkClassifierConfig) SetResetPenalty(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.ResetPenalty = v }
func (c *NetworkClassifierConfig) GetRefusedPenalty() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.RefusedPenalty }
func (c *NetworkClassifierConfig) SetRefusedPenalty(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.RefusedPenalty = v }
func (c *NetworkClassifierConfig) GetIsActive() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.IsActive }
func (c *NetworkClassifierConfig) SetIsActive(v bool) { c.mu.Lock(); defer c.mu.Unlock(); c.IsActive = v }

// Builders for NetworkClassifierConfig
func (c *NetworkClassifierConfig) WithMinScore(v int) *NetworkClassifierConfig { c.SetMinScore(v); return c }
func (c *NetworkClassifierConfig) WithDefaultClassification(v string) *NetworkClassifierConfig { c.SetDefaultClassification(v); return c }
func (c *NetworkClassifierConfig) WithIsActive(v bool) *NetworkClassifierConfig { c.SetIsActive(v); return c }

// Operations
func NewNetworkClassifierConfig() *NetworkClassifierConfig {
	return &NetworkClassifierConfig{
		DefaultClassification: "unknown",
		CloudflareHost:        "cloudflare",
		FastlyHost:            "fastly",
		AkamaiHost:            "akamai",
		CloudfrontHost:        "cloudfront",
		TimeoutPenalty:        8,
		ResetPenalty:          8,
		RefusedPenalty:        8,
		IsActive:              true,
	}
}

func (c *NetworkClassifierConfig) Score(m *ScanResultMetrics) int {
	s := 0
	if m.GetTCP() {
		s += 20
	}
	if m.GetTLS() {
		s += 35
	}
	if m.GetHTTP() {
		s += 35
	}
	if strings.EqualFold(m.GetTLSVersion(), "TLS1.3") {
		s += 8
	}
	if strings.EqualFold(m.GetALPN(), "h2") {
		s += 7
	}
	if m.GetHTTP3Hint() {
		s += 6
	}
	if m.GetNetworkClassification() != "" && m.GetNetworkClassification() != "unknown" {
		s += 8
	}
	if m.GetTLSFingerprint() != "" {
		s += 3
	}
	if m.GetLatencyMS() > 0 {
		val := 45 - int(math.Log1p(float64(m.GetLatencyMS()))*8)
		if val > 0 {
			s += val
		}
	}
	if m.GetError() != "" {
		s -= c.GetTimeoutPenalty()
	}
	if s < 0 {
		return 0
	}
	return s
}

func (c *NetworkClassifierConfig) ClassifyNetworkError(err error, phase string) string {
	if err == nil {
		return ""
	}
	lower := strings.ToLower(err.Error())
	prefix := "SCAN"
	switch phase {
	case "dns":
		prefix = "DNS"
	case "tcp":
		prefix = "TCP_CONNECT"
	case "tls":
		prefix = "TLS_HANDSHAKE"
	case "http":
		prefix = "HTTP"
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded), strings.Contains(lower, "timeout"):
		return prefix + "_TIMEOUT"
	case strings.Contains(lower, "reset"):
		return prefix + "_RESET"
	case strings.Contains(lower, "refused"):
		return prefix + "_REFUSED"
	default:
		return prefix + "_FAILED"
	}
}

func (c *NetworkClassifierConfig) DetectNetworkClassification(ip, sni, cert string) string {
	host := strings.ToLower(sni + " " + cert)
	switch {
	case strings.Contains(host, c.GetCloudflareHost()):
		return "cloudflare"
	case strings.Contains(host, c.GetFastlyHost()) || strings.Contains(host, "github"):
		return "fastly"
	case strings.Contains(host, c.GetAkamaiHost()):
		return "akamai"
	case strings.Contains(host, c.GetCloudfrontHost()) || strings.Contains(host, "amazon"):
		return "cloudfront"
	default:
		return c.GetDefaultClassification()
	}
}

func (c *NetworkClassifierConfig) IsCloudflare(class string) bool {
	return class == "cloudflare"
}

func (c *NetworkClassifierConfig) IsFastly(class string) bool {
	return class == "fastly"
}

func (c *NetworkClassifierConfig) IsAkamai(class string) bool {
	return class == "akamai"
}

func (c *NetworkClassifierConfig) IsCloudfront(class string) bool {
	return class == "cloudfront"
}

func (c *NetworkClassifierConfig) GetStatusMessage() string {
	if c.GetIsActive() {
		return "Classifier is active"
	}
	return "Classifier is inactive"
}

func (c *NetworkClassifierConfig) ResetConfig() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.MinScore = 0
	c.DefaultClassification = "unknown"
}
