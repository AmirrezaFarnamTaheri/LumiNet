// Package scanner implements host and dns probing operations.

package scanner

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
)

// TxtTarget represents a target nameserver resolved from TXT configurations.
type TxtTarget struct {
	Host  string `json:"host"`
	Label string `json:"label"`
	Port  int    `json:"port"`
	Proto string `json:"proto"`
}

// Getters & Setters for TxtTarget
func (t *TxtTarget) GetHost() string { return t.Host }
func (t *TxtTarget) SetHost(v string) { t.Host = v }
func (t *TxtTarget) GetLabel() string { return t.Label }
func (t *TxtTarget) SetLabel(v string) { t.Label = v }
func (t *TxtTarget) GetPort() int { return t.Port }
func (t *TxtTarget) SetPort(v int) { t.Port = v }
func (t *TxtTarget) GetProto() string { return t.Proto }
func (t *TxtTarget) SetProto(v string) { t.Proto = v }

// Builders for TxtTarget
func (t *TxtTarget) WithHost(v string) *TxtTarget { t.SetHost(v); return t }
func (t *TxtTarget) WithLabel(v string) *TxtTarget { t.SetLabel(v); return t }
func (t *TxtTarget) WithPort(v int) *TxtTarget { t.SetPort(v); return t }
func (t *TxtTarget) WithProto(v string) *TxtTarget { t.SetProto(v); return t }

// TxtModeConfig handles configuration for DNS TXT caching bypass queries.
type TxtModeConfig struct {
	mu           sync.RWMutex
	QueryDomain  string
	ResolverFile string
	RawResolvers string
	NonceLength  int
	CacheBypass  bool
	MaxTargets   int
	UseTCP       bool
	PortOverride int
	LogFilePath  string
	IsActive     bool
}

// Getters & Setters for TxtModeConfig
func (c *TxtModeConfig) GetQueryDomain() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.QueryDomain }
func (c *TxtModeConfig) SetQueryDomain(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.QueryDomain = v }
func (c *TxtModeConfig) GetResolverFile() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.ResolverFile }
func (c *TxtModeConfig) SetResolverFile(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.ResolverFile = v }
func (c *TxtModeConfig) GetRawResolvers() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.RawResolvers }
func (c *TxtModeConfig) SetRawResolvers(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.RawResolvers = v }
func (c *TxtModeConfig) GetNonceLength() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.NonceLength }
func (c *TxtModeConfig) SetNonceLength(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.NonceLength = v }
func (c *TxtModeConfig) GetCacheBypass() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.CacheBypass }
func (c *TxtModeConfig) SetCacheBypass(v bool) { c.mu.Lock(); defer c.mu.Unlock(); c.CacheBypass = v }
func (c *TxtModeConfig) GetMaxTargets() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.MaxTargets }
func (c *TxtModeConfig) SetMaxTargets(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.MaxTargets = v }
func (c *TxtModeConfig) GetUseTCP() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.UseTCP }
func (c *TxtModeConfig) SetUseTCP(v bool) { c.mu.Lock(); defer c.mu.Unlock(); c.UseTCP = v }
func (c *TxtModeConfig) GetPortOverride() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.PortOverride }
func (c *TxtModeConfig) SetPortOverride(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.PortOverride = v }
func (c *TxtModeConfig) GetLogFilePath() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.LogFilePath }
func (c *TxtModeConfig) SetLogFilePath(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.LogFilePath = v }
func (c *TxtModeConfig) GetIsActive() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.IsActive }
func (c *TxtModeConfig) SetIsActive(v bool) { c.mu.Lock(); defer c.mu.Unlock(); c.IsActive = v }

// Builders for TxtModeConfig
func (c *TxtModeConfig) WithQueryDomain(v string) *TxtModeConfig { c.SetQueryDomain(v); return c }
func (c *TxtModeConfig) WithResolverFile(v string) *TxtModeConfig { c.SetResolverFile(v); return c }
func (c *TxtModeConfig) WithRawResolvers(v string) *TxtModeConfig { c.SetRawResolvers(v); return c }
func (c *TxtModeConfig) WithNonceLength(v int) *TxtModeConfig { c.SetNonceLength(v); return c }
func (c *TxtModeConfig) WithCacheBypass(v bool) *TxtModeConfig { c.SetCacheBypass(v); return c }
func (c *TxtModeConfig) WithMaxTargets(v int) *TxtModeConfig { c.SetMaxTargets(v); return c }
func (c *TxtModeConfig) WithUseTCP(v bool) *TxtModeConfig { c.SetUseTCP(v); return c }
func (c *TxtModeConfig) WithPortOverride(v int) *TxtModeConfig { c.SetPortOverride(v); return c }
func (c *TxtModeConfig) WithLogFilePath(v string) *TxtModeConfig { c.SetLogFilePath(v); return c }
func (c *TxtModeConfig) WithIsActive(v bool) *TxtModeConfig { c.SetIsActive(v); return c }

// Operations
func NewTxtModeConfig() *TxtModeConfig {
	return &TxtModeConfig{
		NonceLength:  6,
		CacheBypass:  true,
		PortOverride: 53,
		IsActive:     true,
	}
}

func (c *TxtModeConfig) BuildTxtQueryName(domain string) string {
	if !c.GetCacheBypass() {
		return domain
	}
	clean := c.GetCleanDomain(domain)
	nonce := c.GenerateRandomNonce()
	if nonce == "" {
		return "random." + clean
	}
	return nonce + "." + clean
}

func (c *TxtModeConfig) GenerateRandomNonce() string {
	length := c.GetNonceLength()
	if length <= 0 {
		length = 6
	}
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	return hex.EncodeToString(buf)
}

func (c *TxtModeConfig) GetCleanDomain(domain string) string {
	clean := strings.TrimSpace(domain)
	return strings.TrimSuffix(clean, ".")
}

func (c *TxtModeConfig) LoadTxtResolverTargets() ([]TxtTarget, error) {
	text := strings.TrimSpace(c.GetRawResolvers())
	if text == "" {
		if c.GetResolverFile() == "" {
			return nil, errors.New("no resolver source configured")
		}
		data, err := os.ReadFile(c.GetResolverFile())
		if err != nil {
			return nil, err
		}
		text = string(data)
	}

	tokens := strings.FieldsFunc(text, func(r rune) bool {
		switch r {
		case ',', '\n', '\r', '\t', ' ', ';':
			return true
		default:
			return false
		}
	})

	seen := make(map[string]struct{})
	targets := make([]TxtTarget, 0, len(tokens))
	for _, token := range tokens {
		target, ok := c.ParseTxtResolverToken(token)
		if !ok {
			continue
		}
		if _, exists := seen[target.Host]; exists {
			continue
		}
		seen[target.Host] = struct{}{}
		targets = append(targets, target)
	}

	return targets, nil
}

func (c *TxtModeConfig) ParseTxtResolverToken(token string) (TxtTarget, bool) {
	line := strings.TrimSpace(token)
	if line == "" || strings.HasPrefix(line, "#") {
		return TxtTarget{}, false
	}

	label := ""
	value := line
	if idx := strings.Index(line, "|"); idx != -1 {
		label = strings.TrimSpace(line[:idx])
		value = strings.TrimSpace(line[idx+1:])
	}

	value = strings.Trim(value, "'\"")
	value = strings.TrimPrefix(strings.TrimPrefix(value, "dns://"), "dns-txt://")
	value = strings.TrimPrefix(strings.TrimPrefix(value, "udp://"), "tcp://")
	value = strings.TrimPrefix(strings.TrimPrefix(value, "https://"), "http://")
	value = strings.Trim(value, "[]")
	value = strings.TrimSuffix(value, ".")

	host := value
	if strings.Count(host, ":") == 1 {
		if splitHost, _, err := net.SplitHostPort(host); err == nil {
			host = splitHost
		} else {
			parts := strings.SplitN(host, ":", 2)
			if net.ParseIP(parts[0]) != nil {
				host = parts[0]
			}
		}
	}

	if net.ParseIP(host) == nil {
		return TxtTarget{}, false
	}
	if label == "" {
		label = host
	}

	return TxtTarget{
		Host:  host,
		Label: label,
		Port:  c.GetPortOverride(),
		Proto: "udp",
	}, true
}

func (c *TxtModeConfig) ExportTargetsJSON() (string, error) {
	targets, err := c.LoadTxtResolverTargets()
	if err != nil {
		return "", err
	}
	res, err := json.Marshal(targets)
	return string(res), err
}

func (c *TxtModeConfig) ValidateConfig() bool {
	return c.GetNonceLength() > 0
}
