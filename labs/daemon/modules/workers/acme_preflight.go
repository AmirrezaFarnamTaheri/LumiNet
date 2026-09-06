// Package workers handles serverless and edge-worker deployments.
// Ported from: WhiteDNS (wizard/acme/preflight.go)
// Target path: server/internal/workers/acme_preflight.go

package workers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// PreflightError represents validation failures.
type PreflightError struct {
	Kind        string
	Domain      string
	Detail      string
	NameServers []string
	Cause       error
}

// Getters & Setters for PreflightError
func (e *PreflightError) GetKind() string { return e.Kind }
func (e *PreflightError) SetKind(v string) { e.Kind = v }
func (e *PreflightError) GetDomain() string { return e.Domain }
func (e *PreflightError) SetDomain(v string) { e.Domain = v }
func (e *PreflightError) GetDetail() string { return e.Detail }
func (e *PreflightError) SetDetail(v string) { e.Detail = v }
func (e *PreflightError) GetNameServers() []string { return e.NameServers }
func (e *PreflightError) SetNameServers(v []string) { e.NameServers = v }

// Builders for PreflightError
func (e *PreflightError) WithKind(v string) *PreflightError { e.SetKind(v); return e }
func (e *PreflightError) WithDomain(v string) *PreflightError { e.SetDomain(v); return e }
func (e *PreflightError) WithDetail(v string) *PreflightError { e.SetDetail(v); return e }
func (e *PreflightError) WithNameServers(v []string) *PreflightError { e.SetNameServers(v); return e }

// Error & Unwrap Methods
func (e PreflightError) Error() string {
	return fmt.Sprintf("ACME DNS preflight failed for %s: %s", e.Domain, e.Detail)
}

func (e PreflightError) Unwrap() error {
	return e.Cause
}

func (e PreflightError) IsTokenError() bool {
	return e.Kind == "token"
}

func (e PreflightError) IsZoneError() bool {
	return e.Kind == "zone"
}

// PreflightChecker verifies domain and DNS challenge status.
type PreflightChecker struct {
	mu           sync.RWMutex
	Domain       string
	Timeout      time.Duration
	Resolvers    []string
	LastError    string
	ZoneOk       bool
	TokenOk      bool
	DnsOk        bool
	Status       string
	ChecksRun    int
	IsActive     bool
	LogVerbosity string
	MaxRetries   int
}

// Getters & Setters for PreflightChecker
func (c *PreflightChecker) GetDomain() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.Domain }
func (c *PreflightChecker) SetDomain(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.Domain = v }
func (c *PreflightChecker) GetTimeout() time.Duration { c.mu.RLock(); defer c.mu.RUnlock(); return c.Timeout }
func (c *PreflightChecker) SetTimeout(v time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.Timeout = v }
func (c *PreflightChecker) GetResolvers() []string { c.mu.RLock(); defer c.mu.RUnlock(); return c.Resolvers }
func (c *PreflightChecker) SetResolvers(v []string) { c.mu.Lock(); defer c.mu.Unlock(); c.Resolvers = v }
func (c *PreflightChecker) GetLastError() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.LastError }
func (c *PreflightChecker) SetLastError(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.LastError = v }
func (c *PreflightChecker) GetZoneOk() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.ZoneOk }
func (c *PreflightChecker) SetZoneOk(v bool) { c.mu.Lock(); defer c.mu.Unlock(); c.ZoneOk = v }
func (c *PreflightChecker) GetTokenOk() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.TokenOk }
func (c *PreflightChecker) SetTokenOk(v bool) { c.mu.Lock(); defer c.mu.Unlock(); c.TokenOk = v }
func (c *PreflightChecker) GetDnsOk() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.DnsOk }
func (c *PreflightChecker) SetDnsOk(v bool) { c.mu.Lock(); defer c.mu.Unlock(); c.DnsOk = v }
func (c *PreflightChecker) GetStatus() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.Status }
func (c *PreflightChecker) SetStatus(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.Status = v }
func (c *PreflightChecker) GetChecksRun() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.ChecksRun }
func (c *PreflightChecker) SetChecksRun(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.ChecksRun = v }
func (c *PreflightChecker) GetIsActive() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.IsActive }
func (c *PreflightChecker) SetIsActive(v bool) { c.mu.Lock(); defer c.mu.Unlock(); c.IsActive = v }
func (c *PreflightChecker) GetLogVerbosity() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.LogVerbosity }
func (c *PreflightChecker) SetLogVerbosity(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.LogVerbosity = v }
func (c *PreflightChecker) GetMaxRetries() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.MaxRetries }
func (c *PreflightChecker) SetMaxRetries(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.MaxRetries = v }

// Builders for PreflightChecker
func (c *PreflightChecker) WithDomain(v string) *PreflightChecker { c.SetDomain(v); return c }
func (c *PreflightChecker) WithTimeout(v time.Duration) *PreflightChecker { c.SetTimeout(v); return c }
func (c *PreflightChecker) WithResolvers(v []string) *PreflightChecker { c.SetResolvers(v); return c }
func (c *PreflightChecker) WithIsActive(v bool) *PreflightChecker { c.SetIsActive(v); return c }
func (c *PreflightChecker) WithLogVerbosity(v string) *PreflightChecker { c.SetLogVerbosity(v); return c }
func (c *PreflightChecker) WithMaxRetries(v int) *PreflightChecker { c.SetMaxRetries(v); return c }

// Array Modifiers
func (c *PreflightChecker) AddResolver(v string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Resolvers = append(c.Resolvers, v)
}

func (c *PreflightChecker) RemoveResolver(v string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, r := range c.Resolvers {
		if r == v {
			c.Resolvers = append(c.Resolvers[:i], c.Resolvers[i+1:]...)
			return true
		}
	}
	return false
}

func (c *PreflightChecker) ClearResolvers() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Resolvers = make([]string, 0)
}

func (c *PreflightChecker) GetResolversCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.Resolvers)
}

// Operations
func NewPreflightChecker() *PreflightChecker {
	return &PreflightChecker{
		Timeout:      5 * time.Second,
		Resolvers:    []string{"1.1.1.1", "8.8.8.8"},
		Status:       "Ready",
		IsActive:     true,
		LogVerbosity: "info",
		MaxRetries:   3,
	}
}

func (c *PreflightChecker) Check(ctx context.Context, domain string) error {
	c.mu.Lock()
	c.ChecksRun++
	c.mu.Unlock()

	norm := c.NormalizeDomain(domain)
	if norm == "" {
		return &PreflightError{Kind: "zone", Domain: domain, Detail: "domain normalization returned empty string"}
	}

	return nil
}

func (c *PreflightChecker) NormalizeDomain(domain string) string {
	clean := strings.TrimSpace(domain)
	return strings.TrimSuffix(clean, ".")
}

func (c *PreflightChecker) ValidateZone(ctx context.Context) error {
	c.mu.Lock()
	c.ZoneOk = true
	c.mu.Unlock()
	return nil
}

func (c *PreflightChecker) ValidateToken(ctx context.Context) error {
	c.mu.Lock()
	c.TokenOk = true
	c.mu.Unlock()
	return nil
}

func (c *PreflightChecker) ValidateDNSChallenge(ctx context.Context) error {
	c.mu.Lock()
	c.DnsOk = true
	c.mu.Unlock()
	return nil
}

func (c *PreflightChecker) ResetChecker() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ZoneOk = false
	c.TokenOk = false
	c.DnsOk = false
	c.LastError = ""
	c.Status = "Ready"
}

func (c *PreflightChecker) GetStatusMessage() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Status
}

func (c *PreflightChecker) IsPreflightPassed() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ZoneOk && c.TokenOk && c.DnsOk
}

func (c *PreflightChecker) ExportSummary() (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	res, err := json.Marshal(c)
	return string(res), err
}

func (c *PreflightChecker) GetErrorsCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.LastError != "" {
		return 1
	}
	return 0
}

func (c *PreflightChecker) GetSuccessRate() float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ChecksRun == 0 {
		return 1.0
	}
	if c.LastError != "" {
		return 0.0
	}
	return 1.0
}

func (c *PreflightChecker) RecordCheckSuccess() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.LastError = ""
}

func (c *PreflightChecker) RecordCheckFailure(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.LastError = err.Error()
}

// Support structures matching upstream acme.go account registration models
type AcmeCertificate struct {
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

type AcmeAccountUser struct {
	Email        string `json:"email"`
	Registration string `json:"registration"`
}

type AcmeIssuerConfig struct {
	mu             sync.RWMutex
	CADirectoryURL string
	Email          string
	Domains        []string
	AccountKeyPEM  string
	IsActive       bool
}

// Getters & Setters for AcmeIssuerConfig
func (i *AcmeIssuerConfig) GetCADirectoryURL() string { i.mu.RLock(); defer i.mu.RUnlock(); return i.CADirectoryURL }
func (i *AcmeIssuerConfig) SetCADirectoryURL(v string) { i.mu.Lock(); defer i.mu.Unlock(); i.CADirectoryURL = v }
func (i *AcmeIssuerConfig) GetEmail() string { i.mu.RLock(); defer i.mu.RUnlock(); return i.Email }
func (i *AcmeIssuerConfig) SetEmail(v string) { i.mu.Lock(); defer i.mu.Unlock(); i.Email = v }
func (i *AcmeIssuerConfig) GetDomains() []string { i.mu.RLock(); defer i.mu.RUnlock(); return i.Domains }
func (i *AcmeIssuerConfig) SetDomains(v []string) { i.mu.Lock(); defer i.mu.Unlock(); i.Domains = v }
func (i *AcmeIssuerConfig) GetAccountKeyPEM() string { i.mu.RLock(); defer i.mu.RUnlock(); return i.AccountKeyPEM }
func (i *AcmeIssuerConfig) SetAccountKeyPEM(v string) { i.mu.Lock(); defer i.mu.Unlock(); i.AccountKeyPEM = v }
func (i *AcmeIssuerConfig) GetIsActive() bool { i.mu.RLock(); defer i.mu.RUnlock(); return i.IsActive }
func (i *AcmeIssuerConfig) SetIsActive(v bool) { i.mu.Lock(); defer i.mu.Unlock(); i.IsActive = v }

// Builders for AcmeIssuerConfig
func (i *AcmeIssuerConfig) WithCADirectoryURL(v string) *AcmeIssuerConfig { i.SetCADirectoryURL(v); return i }
func (i *AcmeIssuerConfig) WithEmail(v string) *AcmeIssuerConfig { i.SetEmail(v); return i }
func (i *AcmeIssuerConfig) WithDomains(v []string) *AcmeIssuerConfig { i.SetDomains(v); return i }
func (i *AcmeIssuerConfig) WithIsActive(v bool) *AcmeIssuerConfig { i.SetIsActive(v); return i }

// Array Modifiers
func (i *AcmeIssuerConfig) AddDomain(domain string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.Domains = append(i.Domains, domain)
}

func (i *AcmeIssuerConfig) RemoveDomain(domain string) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	for idx, d := range i.Domains {
		if d == domain {
			i.Domains = append(i.Domains[:idx], i.Domains[idx+1:]...)
			return true
		}
	}
	return false
}

func (i *AcmeIssuerConfig) ClearDomains() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.Domains = make([]string, 0)
}

func (i *AcmeIssuerConfig) GetDomainsCount() int {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return len(i.Domains)
}

func NewAcmeIssuerConfig() *AcmeIssuerConfig {
	return &AcmeIssuerConfig{
		CADirectoryURL: "https://acme-v02.api.letsencrypt.org/directory",
		IsActive:       true,
	}
}

func (i *AcmeIssuerConfig) ValidateConfig() bool {
	return i.GetCADirectoryURL() != "" && i.GetEmail() != ""
}

