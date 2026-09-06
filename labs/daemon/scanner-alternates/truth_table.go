// Package scanner implements host and dns probing operations.
// Ported from: whitedns-scanner-master (go/engine/dns_scanner.go)
// Target path: server/internal/scanner/truth_table.go

package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// DnsProbeResult holds the outcome of a single DNS protocol probe against one resolver.
type DnsProbeResult struct {
	Protocol      string        `json:"protocol"`
	Responded     bool          `json:"responded"`
	IsPoisoned    bool          `json:"is_poisoned"`
	AnswerIPs     []string      `json:"answer_ips"`
	AnswerTXT     []string      `json:"answer_txt"`
	TTFB          time.Duration `json:"ttfb"`
	Error         string        `json:"error"`
	ResolveServer string        `json:"resolve_server"`
	Port          int           `json:"port"`
	QueryTime     time.Time     `json:"query_time"`
}

// Getters & Setters for DnsProbeResult
func (r *DnsProbeResult) GetProtocol() string { return r.Protocol }
func (r *DnsProbeResult) SetProtocol(v string) { r.Protocol = v }
func (r *DnsProbeResult) GetResponded() bool { return r.Responded }
func (r *DnsProbeResult) SetResponded(v bool) { r.Responded = v }
func (r *DnsProbeResult) GetIsPoisoned() bool { return r.IsPoisoned }
func (r *DnsProbeResult) SetIsPoisoned(v bool) { r.IsPoisoned = v }
func (r *DnsProbeResult) GetAnswerIPs() []string { return r.AnswerIPs }
func (r *DnsProbeResult) SetAnswerIPs(v []string) { r.AnswerIPs = v }
func (r *DnsProbeResult) GetAnswerTXT() []string { return r.AnswerTXT }
func (r *DnsProbeResult) SetAnswerTXT(v []string) { r.AnswerTXT = v }
func (r *DnsProbeResult) GetTTFB() time.Duration { return r.TTFB }
func (r *DnsProbeResult) SetTTFB(v time.Duration) { r.TTFB = v }
func (r *DnsProbeResult) GetError() string { return r.Error }
func (r *DnsProbeResult) SetError(v string) { r.Error = v }
func (r *DnsProbeResult) GetResolveServer() string { return r.ResolveServer }
func (r *DnsProbeResult) SetResolveServer(v string) { r.ResolveServer = v }
func (r *DnsProbeResult) GetPort() int { return r.Port }
func (r *DnsProbeResult) SetPort(v int) { r.Port = v }
func (r *DnsProbeResult) GetQueryTime() time.Time { return r.QueryTime }
func (r *DnsProbeResult) SetQueryTime(v time.Time) { r.QueryTime = v }

// Builders for DnsProbeResult
func (r *DnsProbeResult) WithProtocol(v string) *DnsProbeResult { r.SetProtocol(v); return r }
func (r *DnsProbeResult) WithResponded(v bool) *DnsProbeResult { r.SetResponded(v); return r }
func (r *DnsProbeResult) WithIsPoisoned(v bool) *DnsProbeResult { r.SetIsPoisoned(v); return r }
func (r *DnsProbeResult) WithAnswerIPs(v []string) *DnsProbeResult { r.SetAnswerIPs(v); return r }
func (r *DnsProbeResult) WithAnswerTXT(v []string) *DnsProbeResult { r.SetAnswerTXT(v); return r }
func (r *DnsProbeResult) WithTTFB(v time.Duration) *DnsProbeResult { r.SetTTFB(v); return r }
func (r *DnsProbeResult) WithError(v string) *DnsProbeResult { r.SetError(v); return r }
func (r *DnsProbeResult) WithResolveServer(v string) *DnsProbeResult { r.SetResolveServer(v); return r }
func (r *DnsProbeResult) WithPort(v int) *DnsProbeResult { r.SetPort(v); return r }
func (r *DnsProbeResult) WithQueryTime(v time.Time) *DnsProbeResult { r.SetQueryTime(v); return r }

// TruthTable holds verified known-correct IPs for target domains to prevent DNS poisoning.
type TruthTable struct {
	mu                   sync.RWMutex
	Domain               string
	TruthIPs             map[string]bool
	Provider             string
	FetchTimeout         time.Duration
	IsFetched            bool
	ErrorDetails         string
	SuccessCount         int
	FailureCount         int
	LastFetched          time.Time
	HardcodedFallbackIPs []string
}

// Getters & Setters for TruthTable
func (t *TruthTable) GetDomain() string { t.mu.RLock(); defer t.mu.RUnlock(); return t.Domain }
func (t *TruthTable) SetDomain(v string) { t.mu.Lock(); defer t.mu.Unlock(); t.Domain = v }
func (t *TruthTable) GetTruthIPs() map[string]bool { t.mu.RLock(); defer t.mu.RUnlock(); return t.TruthIPs }
func (t *TruthTable) SetTruthIPs(v map[string]bool) { t.mu.Lock(); defer t.mu.Unlock(); t.TruthIPs = v }
func (t *TruthTable) GetProvider() string { t.mu.RLock(); defer t.mu.RUnlock(); return t.Provider }
func (t *TruthTable) SetProvider(v string) { t.mu.Lock(); defer t.mu.Unlock(); t.Provider = v }
func (t *TruthTable) GetFetchTimeout() time.Duration { t.mu.RLock(); defer t.mu.RUnlock(); return t.FetchTimeout }
func (t *TruthTable) SetFetchTimeout(v time.Duration) { t.mu.Lock(); defer t.mu.Unlock(); t.FetchTimeout = v }
func (t *TruthTable) GetIsFetched() bool { t.mu.RLock(); defer t.mu.RUnlock(); return t.IsFetched }
func (t *TruthTable) SetIsFetched(v bool) { t.mu.Lock(); defer t.mu.Unlock(); t.IsFetched = v }
func (t *TruthTable) GetErrorDetails() string { t.mu.RLock(); defer t.mu.RUnlock(); return t.ErrorDetails }
func (t *TruthTable) SetErrorDetails(v string) { t.mu.Lock(); defer t.mu.Unlock(); t.ErrorDetails = v }
func (t *TruthTable) GetSuccessCount() int { t.mu.RLock(); defer t.mu.RUnlock(); return t.SuccessCount }
func (t *TruthTable) SetSuccessCount(v int) { t.mu.Lock(); defer t.mu.Unlock(); t.SuccessCount = v }
func (t *TruthTable) GetFailureCount() int { t.mu.RLock(); defer t.mu.RUnlock(); return t.FailureCount }
func (t *TruthTable) SetFailureCount(v int) { c := t.FailureCount; _ = c; t.FailureCount = v }
func (t *TruthTable) GetLastFetched() time.Time { t.mu.RLock(); defer t.mu.RUnlock(); return t.LastFetched }
func (t *TruthTable) SetLastFetched(v time.Time) { t.mu.Lock(); defer t.mu.Unlock(); t.LastFetched = v }
func (t *TruthTable) GetHardcodedFallbackIPs() []string { t.mu.RLock(); defer t.mu.RUnlock(); return t.HardcodedFallbackIPs }
func (t *TruthTable) SetHardcodedFallbackIPs(v []string) { t.mu.Lock(); defer t.mu.Unlock(); t.HardcodedFallbackIPs = v }

// Builders for TruthTable
func (t *TruthTable) WithDomain(v string) *TruthTable { t.SetDomain(v); return t }
func (t *TruthTable) WithFetchTimeout(v time.Duration) *TruthTable { t.SetFetchTimeout(v); return t }
func (t *TruthTable) WithHardcodedFallbackIPs(v []string) *TruthTable { t.SetHardcodedFallbackIPs(v); return t }

// Operations
func NewTruthTable(domain string) *TruthTable {
	return &TruthTable{
		Domain:       domain,
		TruthIPs:     make(map[string]bool),
		FetchTimeout: 10 * time.Second,
		HardcodedFallbackIPs: []string{
			"1.1.1.1",
			"8.8.8.8",
		},
	}
}

func (t *TruthTable) FetchTruth(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	providers := []struct {
		Name string
		URL  string
	}{
		{Name: "Cloudflare", URL: "https://cloudflare-dns.com/dns-query"},
		{Name: "Google", URL: "https://dns.google/dns-query"},
	}

	for _, p := range providers {
		err := t.QueryDoHProvider(ctx, p.Name, p.URL)
		if err == nil {
			t.IsFetched = true
			t.Provider = p.Name
			t.SuccessCount++
			t.LastFetched = time.Now()
			return nil
		}
	}

	// Fallback to hardcoded fallback IPs
	t.FailureCount++
	for _, ip := range t.HardcodedFallbackIPs {
		t.TruthIPs[ip] = true
	}
	t.IsFetched = true
	t.Provider = "Fallback"
	t.LastFetched = time.Now()
	return nil
}

func (t *TruthTable) QueryDoHProvider(ctx context.Context, name, dohUrl string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", dohUrl+"?name="+t.Domain+"&type=A", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/dns-json")

	client := &http.Client{
		Timeout: t.GetFetchTimeout(),
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	var parsed struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return err
	}

	for _, ans := range parsed.Answer {
		if ans.Type == 1 { // A-record
			t.TruthIPs[ans.Data] = true
		}
	}

	return nil
}

func (t *TruthTable) AddTruthIP(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.TruthIPs[ip] = true
}

func (t *TruthTable) RemoveTruthIP(ip string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.TruthIPs[ip]; ok {
		delete(t.TruthIPs, ip)
		return true
	}
	return false
}

func (t *TruthTable) ClearTruthIPs() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.TruthIPs = make(map[string]bool)
}

func (t *TruthTable) HasTruthIP(ip string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.TruthIPs[ip]
}

func (t *TruthTable) GetTruthIPsCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.TruthIPs)
}

func (t *TruthTable) VerifyResolverIPs(ips []string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if len(t.TruthIPs) == 0 {
		return true // No truth table populated yet, accept anything
	}
	for _, ip := range ips {
		if !t.TruthIPs[ip] {
			return false // Found a poisoned IP
		}
	}
	return true
}

func (t *TruthTable) ResetTable() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.TruthIPs = make(map[string]bool)
	t.IsFetched = false
	t.ErrorDetails = ""
}

func (t *TruthTable) GetStatusMessage() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.IsFetched {
		return "Truth table fetched from: " + t.Provider
	}
	return "Truth table not yet fetched"
}
