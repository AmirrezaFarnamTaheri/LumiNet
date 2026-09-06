// Package scanner implements host and dns probing operations.

package scanner

import (
	"encoding/json"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// SiteProbeResult holds the outcome of an individual site probe.
type SiteProbeResult struct {
	Url        string        `json:"url"`
	StatusCode int           `json:"status_code"`
	Latency    time.Duration `json:"latency"`
	Success    bool          `json:"success"`
	Ip         string        `json:"ip"`
	ErrorMsg   string        `json:"error_msg"`
}

// Getters & Setters for SiteProbeResult
func (s *SiteProbeResult) GetUrl() string { return s.Url }
func (s *SiteProbeResult) SetUrl(val string) { s.Url = val }
func (s *SiteProbeResult) GetStatusCode() int { return s.StatusCode }
func (s *SiteProbeResult) SetStatusCode(val int) { s.StatusCode = val }
func (s *SiteProbeResult) GetLatency() time.Duration { return s.Latency }
func (s *SiteProbeResult) SetLatency(val time.Duration) { s.Latency = val }
func (s *SiteProbeResult) GetSuccess() bool { return s.Success }
func (s *SiteProbeResult) SetSuccess(val bool) { s.Success = val }
func (s *SiteProbeResult) GetIp() string { return s.Ip }
func (s *SiteProbeResult) SetIp(val string) { s.Ip = val }
func (s *SiteProbeResult) GetErrorMsg() string { return s.ErrorMsg }
func (s *SiteProbeResult) SetErrorMsg(val string) { s.ErrorMsg = val }

// Builders for SiteProbeResult
func (s *SiteProbeResult) WithUrl(val string) *SiteProbeResult { s.SetUrl(val); return s }
func (s *SiteProbeResult) WithStatusCode(val int) *SiteProbeResult { s.SetStatusCode(val); return s }
func (s *SiteProbeResult) WithLatency(val time.Duration) *SiteProbeResult { s.SetLatency(val); return s }
func (s *SiteProbeResult) WithSuccess(val bool) *SiteProbeResult { s.SetSuccess(val); return s }
func (s *SiteProbeResult) WithIp(val string) *SiteProbeResult { s.SetIp(val); return s }
func (s *SiteProbeResult) WithErrorMsg(val string) *SiteProbeResult { s.SetErrorMsg(val); return s }

// NetworkHealthOptions configures options for the transport health gate.
type NetworkHealthOptions struct {
	mu                   sync.RWMutex
	DisableHealthGate    bool          `json:"disable_health_gate"`
	ProbeTimeout         time.Duration `json:"probe_timeout"`
	HealthSites          []string      `json:"health_sites"`
	TransferDomains      []string      `json:"transfer_domains"`
	BrrrMode             bool          `json:"brrr_mode"`
	MaxParallelChecks    int           `json:"max_parallel_checks"`
	RetryInterval        time.Duration `json:"retry_interval"`
	ReportOnSuccess      bool          `json:"report_on_success"`
	CheckDnsReachability bool          `json:"check_dns_reachability"`
	DnsResolverIp        string        `json:"dns_resolver_ip"`
}

// Getters & Setters for NetworkHealthOptions
func (o *NetworkHealthOptions) GetDisableHealthGate() bool { o.mu.RLock(); defer o.mu.RUnlock(); return o.DisableHealthGate }
func (o *NetworkHealthOptions) SetDisableHealthGate(val bool) { o.mu.Lock(); defer o.mu.Unlock(); o.DisableHealthGate = val }
func (o *NetworkHealthOptions) GetProbeTimeout() time.Duration { o.mu.RLock(); defer o.mu.RUnlock(); return o.ProbeTimeout }
func (o *NetworkHealthOptions) SetProbeTimeout(val time.Duration) { o.mu.Lock(); defer o.mu.Unlock(); o.ProbeTimeout = val }
func (o *NetworkHealthOptions) GetHealthSites() []string { o.mu.RLock(); defer o.mu.RUnlock(); return o.HealthSites }
func (o *NetworkHealthOptions) SetHealthSites(val []string) { o.mu.Lock(); defer o.mu.Unlock(); o.HealthSites = val }
func (o *NetworkHealthOptions) GetTransferDomains() []string { o.mu.RLock(); defer o.mu.RUnlock(); return o.TransferDomains }
func (o *NetworkHealthOptions) SetTransferDomains(val []string) { o.mu.Lock(); defer o.mu.Unlock(); o.TransferDomains = val }
func (o *NetworkHealthOptions) GetBrrrMode() bool { o.mu.RLock(); defer o.mu.RUnlock(); return o.BrrrMode }
func (o *NetworkHealthOptions) SetBrrrMode(val bool) { o.mu.Lock(); defer o.mu.Unlock(); o.BrrrMode = val }
func (o *NetworkHealthOptions) GetMaxParallelChecks() int { o.mu.RLock(); defer o.mu.RUnlock(); return o.MaxParallelChecks }
func (o *NetworkHealthOptions) SetMaxParallelChecks(val int) { o.mu.Lock(); defer o.mu.Unlock(); o.MaxParallelChecks = val }
func (o *NetworkHealthOptions) GetRetryInterval() time.Duration { o.mu.RLock(); defer o.mu.RUnlock(); return o.RetryInterval }
func (o *NetworkHealthOptions) SetRetryInterval(val time.Duration) { o.mu.Lock(); defer o.mu.Unlock(); o.RetryInterval = val }
func (o *NetworkHealthOptions) GetReportOnSuccess() bool { o.mu.RLock(); defer o.mu.RUnlock(); return o.ReportOnSuccess }
func (o *NetworkHealthOptions) SetReportOnSuccess(val bool) { o.mu.Lock(); defer o.mu.Unlock(); o.ReportOnSuccess = val }
func (o *NetworkHealthOptions) GetCheckDnsReachability() bool { o.mu.RLock(); defer o.mu.RUnlock(); return o.CheckDnsReachability }
func (o *NetworkHealthOptions) SetCheckDnsReachability(val bool) { o.mu.Lock(); defer o.mu.Unlock(); o.CheckDnsReachability = val }
func (o *NetworkHealthOptions) GetDnsResolverIp() string { o.mu.RLock(); defer o.mu.RUnlock(); return o.DnsResolverIp }
func (o *NetworkHealthOptions) SetDnsResolverIp(val string) { o.mu.Lock(); defer o.mu.Unlock(); o.DnsResolverIp = val }

// Builders for NetworkHealthOptions
func (o *NetworkHealthOptions) WithDisableHealthGate(val bool) *NetworkHealthOptions { o.SetDisableHealthGate(val); return o }
func (o *NetworkHealthOptions) WithProbeTimeout(val time.Duration) *NetworkHealthOptions { o.SetProbeTimeout(val); return o }
func (o *NetworkHealthOptions) WithHealthSites(val []string) *NetworkHealthOptions { o.SetHealthSites(val); return o }
func (o *NetworkHealthOptions) WithTransferDomains(val []string) *NetworkHealthOptions { o.SetTransferDomains(val); return o }
func (o *NetworkHealthOptions) WithBrrrMode(val bool) *NetworkHealthOptions { o.SetBrrrMode(val); return o }
func (o *NetworkHealthOptions) WithMaxParallelChecks(val int) *NetworkHealthOptions { o.SetMaxParallelChecks(val); return o }
func (o *NetworkHealthOptions) WithRetryInterval(val time.Duration) *NetworkHealthOptions { o.SetRetryInterval(val); return o }
func (o *NetworkHealthOptions) WithReportOnSuccess(val bool) *NetworkHealthOptions { o.SetReportOnSuccess(val); return o }
func (o *NetworkHealthOptions) WithCheckDnsReachability(val bool) *NetworkHealthOptions { o.SetCheckDnsReachability(val); return o }
func (o *NetworkHealthOptions) WithDnsResolverIp(val string) *NetworkHealthOptions { o.SetDnsResolverIp(val); return o }

// Array Modifiers for NetworkHealthOptions
func (o *NetworkHealthOptions) AddHealthSite(val string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.HealthSites = append(o.HealthSites, val)
}
func (o *NetworkHealthOptions) RemoveHealthSite(val string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	for i, v := range o.HealthSites {
		if v == val {
			o.HealthSites = append(o.HealthSites[:i], o.HealthSites[i+1:]...)
			return true
		}
	}
	return false
}
func (o *NetworkHealthOptions) ClearHealthSites() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.HealthSites = make([]string, 0)
}
func (o *NetworkHealthOptions) GetHealthSitesCount() int {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return len(o.HealthSites)
}
func (o *NetworkHealthOptions) AddTransferDomain(val string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.TransferDomains = append(o.TransferDomains, val)
}
func (o *NetworkHealthOptions) RemoveTransferDomain(val string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	for i, v := range o.TransferDomains {
		if v == val {
			o.TransferDomains = append(o.TransferDomains[:i], o.TransferDomains[i+1:]...)
			return true
		}
	}
	return false
}
func (o *NetworkHealthOptions) ClearTransferDomains() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.TransferDomains = make([]string, 0)
}
func (o *NetworkHealthOptions) GetTransferDomainsCount() int {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return len(o.TransferDomains)
}

// NetworkHealthTracker supervises network connectivity state.
type NetworkHealthTracker struct {
	mu                 sync.RWMutex
	Active             bool          `json:"active"`
	ChecksRun          int64         `json:"checks_run"`
	SuccessCount       int64         `json:"success_count"`
	FailureCount       int64         `json:"failure_count"`
	LastChecked        time.Time     `json:"last_checked"`
	Status             string        `json:"status"`
	IsDeviceOnline     bool          `json:"is_device_online"`
	GatePaused         bool          `json:"gate_paused"`
	CurrentNetworkType string        `json:"current_network_type"`
	LatencyAverage     time.Duration `json:"latency_average"`
	TotalChecksRun     int64         `json:"total_checks_run"`
	TotalChecksSuccess int64         `json:"total_checks_success"`
}

// Getters & Setters for NetworkHealthTracker
func (t *NetworkHealthTracker) GetActive() bool { t.mu.RLock(); defer t.mu.RUnlock(); return t.Active }
func (t *NetworkHealthTracker) SetActive(val bool) { t.mu.Lock(); defer t.mu.Unlock(); t.Active = val }
func (t *NetworkHealthTracker) GetChecksRun() int64 { return atomic.LoadInt64(&t.ChecksRun) }
func (t *NetworkHealthTracker) SetChecksRun(val int64) { atomic.StoreInt64(&t.ChecksRun, val) }
func (t *NetworkHealthTracker) GetSuccessCount() int64 { return atomic.LoadInt64(&t.SuccessCount) }
func (t *NetworkHealthTracker) SetSuccessCount(val int64) { atomic.StoreInt64(&t.SuccessCount, val) }
func (t *NetworkHealthTracker) GetFailureCount() int64 { return atomic.LoadInt64(&t.FailureCount) }
func (t *NetworkHealthTracker) SetFailureCount(val int64) { atomic.StoreInt64(&t.FailureCount, val) }
func (t *NetworkHealthTracker) GetLastChecked() time.Time { t.mu.RLock(); defer t.mu.RUnlock(); return t.LastChecked }
func (t *NetworkHealthTracker) SetLastChecked(val time.Time) { t.mu.Lock(); defer t.mu.Unlock(); t.LastChecked = val }
func (t *NetworkHealthTracker) GetStatus() string { t.mu.RLock(); defer t.mu.RUnlock(); return t.Status }
func (t *NetworkHealthTracker) SetStatus(val string) { t.mu.Lock(); defer t.mu.Unlock(); t.Status = val }
func (t *NetworkHealthTracker) GetIsDeviceOnline() bool { t.mu.RLock(); defer t.mu.RUnlock(); return t.IsDeviceOnline }
func (t *NetworkHealthTracker) SetIsDeviceOnline(val bool) { t.mu.Lock(); defer t.mu.Unlock(); t.IsDeviceOnline = val }
func (t *NetworkHealthTracker) GetGatePaused() bool { t.mu.RLock(); defer t.mu.RUnlock(); return t.GatePaused }
func (t *NetworkHealthTracker) SetGatePaused(val bool) { t.mu.Lock(); defer t.mu.Unlock(); t.GatePaused = val }
func (t *NetworkHealthTracker) GetCurrentNetworkType() string { t.mu.RLock(); defer t.mu.RUnlock(); return t.CurrentNetworkType }
func (t *NetworkHealthTracker) SetCurrentNetworkType(val string) { t.mu.Lock(); defer t.mu.Unlock(); t.CurrentNetworkType = val }
func (t *NetworkHealthTracker) GetLatencyAverage() time.Duration { t.mu.RLock(); defer t.mu.RUnlock(); return t.LatencyAverage }
func (t *NetworkHealthTracker) SetLatencyAverage(val time.Duration) { t.mu.Lock(); defer t.mu.Unlock(); t.LatencyAverage = val }
func (t *NetworkHealthTracker) GetTotalChecksRun() int64 { return atomic.LoadInt64(&t.TotalChecksRun) }
func (t *NetworkHealthTracker) SetTotalChecksRun(val int64) { atomic.StoreInt64(&t.TotalChecksRun, val) }
func (t *NetworkHealthTracker) GetTotalChecksSuccess() int64 { return atomic.LoadInt64(&t.TotalChecksSuccess) }
func (t *NetworkHealthTracker) SetTotalChecksSuccess(val int64) { atomic.StoreInt64(&t.TotalChecksSuccess, val) }

// Builders for NetworkHealthTracker
func (t *NetworkHealthTracker) WithActive(val bool) *NetworkHealthTracker { t.SetActive(val); return t }
func (t *NetworkHealthTracker) WithChecksRun(val int64) *NetworkHealthTracker { t.SetChecksRun(val); return t }
func (t *NetworkHealthTracker) WithSuccessCount(val int64) *NetworkHealthTracker { t.SetSuccessCount(val); return t }
func (t *NetworkHealthTracker) WithFailureCount(val int64) *NetworkHealthTracker { t.SetFailureCount(val); return t }
func (t *NetworkHealthTracker) WithLastChecked(val time.Time) *NetworkHealthTracker { t.SetLastChecked(val); return t }
func (t *NetworkHealthTracker) WithStatus(val string) *NetworkHealthTracker { t.SetStatus(val); return t }
func (t *NetworkHealthTracker) WithIsDeviceOnline(val bool) *NetworkHealthTracker { t.SetIsDeviceOnline(val); return t }
func (t *NetworkHealthTracker) WithGatePaused(val bool) *NetworkHealthTracker { t.SetGatePaused(val); return t }
func (t *NetworkHealthTracker) WithCurrentNetworkType(val string) *NetworkHealthTracker { t.SetCurrentNetworkType(val); return t }
func (t *NetworkHealthTracker) WithLatencyAverage(val time.Duration) *NetworkHealthTracker { t.SetLatencyAverage(val); return t }
func (t *NetworkHealthTracker) WithTotalChecksRun(val int64) *NetworkHealthTracker { t.SetTotalChecksRun(val); return t }
func (t *NetworkHealthTracker) WithTotalChecksSuccess(val int64) *NetworkHealthTracker { t.SetTotalChecksSuccess(val); return t }

// Logic / Operations
func (t *NetworkHealthTracker) RecordSuccess(latency time.Duration) {
	atomic.AddInt64(&t.ChecksRun, 1)
	atomic.AddInt64(&t.SuccessCount, 1)
	atomic.AddInt64(&t.TotalChecksRun, 1)
	atomic.AddInt64(&t.TotalChecksSuccess, 1)
	t.mu.Lock()
	t.LastChecked = time.Now()
	t.IsDeviceOnline = true
	t.LatencyAverage = (t.LatencyAverage + latency) / 2
	t.mu.Unlock()
}

func (t *NetworkHealthTracker) RecordFailure() {
	atomic.AddInt64(&t.ChecksRun, 1)
	atomic.AddInt64(&t.FailureCount, 1)
	atomic.AddInt64(&t.TotalChecksRun, 1)
	t.mu.Lock()
	t.LastChecked = time.Now()
	t.IsDeviceOnline = false
	t.mu.Unlock()
}

func (t *NetworkHealthTracker) ResetStats() {
	atomic.StoreInt64(&t.ChecksRun, 0)
	atomic.StoreInt64(&t.SuccessCount, 0)
	atomic.StoreInt64(&t.FailureCount, 0)
}

func (t *NetworkHealthTracker) GetSuccessRate() float64 {
	run := atomic.LoadInt64(&t.ChecksRun)
	if run == 0 {
		return 1.0
	}
	return float64(atomic.LoadInt64(&t.SuccessCount)) / float64(run)
}

func (t *NetworkHealthTracker) ShouldPauseScan() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.GatePaused
}

func (t *NetworkHealthTracker) ExecuteHealthCheck(opts *NetworkHealthOptions) bool {
	if opts.GetDisableHealthGate() {
		return true
	}
	online := t.QuickConnectivityCheck(opts.GetProbeTimeout())
	if online {
		t.RecordSuccess(100 * time.Millisecond)
	} else {
		t.RecordFailure()
	}
	return online
}

func (t *NetworkHealthTracker) IsConnectivityValid() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.IsDeviceOnline
}

func (t *NetworkHealthTracker) QuickConnectivityCheck(timeout time.Duration) bool {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	for _, host := range []string{"1.1.1.1:443", "8.8.8.8:53", "9.9.9.9:443"} {
		c, err := net.DialTimeout("tcp", host, timeout)
		if err == nil {
			_ = c.Close()
			return true
		}
	}
	return false
}

func (t *NetworkHealthTracker) ExportJSON() (string, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	res, err := json.Marshal(t)
	return string(res), err
}

func (t *NetworkHealthTracker) ValidateOptions(opts *NetworkHealthOptions) bool {
	return opts.GetProbeTimeout() > 0
}

func (t *NetworkHealthTracker) LoadDefaults() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Active = true
	t.Status = "Operational"
	t.IsDeviceOnline = true
	t.CurrentNetworkType = "WiFi"
}

func (t *NetworkHealthTracker) GetStatusMessage() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.Status
}
