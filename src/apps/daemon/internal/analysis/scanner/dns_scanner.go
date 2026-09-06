// Package scanner implements host and dns probing operations.

package scanner

import (
	"context"
	"net"
	"sync"
	"time"
)

// DnsScanRequest defines the target hostname, resolver pool, and scanning flags.
type DnsScanRequest struct {
	mu             sync.RWMutex
	Hostname       string        `json:"hostname"`
	ResolverPool   []string      `json:"resolver_pool"`
	Flags          uint32        `json:"flags"`
	QTypes         []string      `json:"qtypes"`
	Timeout        time.Duration `json:"timeout"`
	Workers        int           `json:"workers"`
	Samples        int           `json:"samples"`
	RatePerSecond  int           `json:"rate_per_second"`
	Jitter         time.Duration `json:"jitter"`
	Port           int           `json:"port"`
	Protocol       string        `json:"protocol"`
	EnableDNSSEC   bool          `json:"enable_dnssec"`
	EnableEDNS     bool          `json:"enable_edns"`
	AllowedLatency time.Duration `json:"allowed_latency"`
	CacheDNS       bool          `json:"cache_dns"`
}

// Getters & Setters for DnsScanRequest
func (r *DnsScanRequest) GetHostname() string { r.mu.RLock(); defer r.mu.RUnlock(); return r.Hostname }
func (r *DnsScanRequest) SetHostname(val string) { r.mu.Lock(); defer r.mu.Unlock(); r.Hostname = val }
func (r *DnsScanRequest) GetResolverPool() []string { r.mu.RLock(); defer r.mu.RUnlock(); return r.ResolverPool }
func (r *DnsScanRequest) SetResolverPool(val []string) { r.mu.Lock(); defer r.mu.Unlock(); r.ResolverPool = val }
func (r *DnsScanRequest) GetFlags() uint32 { r.mu.RLock(); defer r.mu.RUnlock(); return r.Flags }
func (r *DnsScanRequest) SetFlags(val uint32) { r.mu.Lock(); defer r.mu.Unlock(); r.Flags = val }
func (r *DnsScanRequest) GetQTypes() []string { r.mu.RLock(); defer r.mu.RUnlock(); return r.QTypes }
func (r *DnsScanRequest) SetQTypes(val []string) { r.mu.Lock(); defer r.mu.Unlock(); r.QTypes = val }
func (r *DnsScanRequest) GetTimeout() time.Duration { r.mu.RLock(); defer r.mu.RUnlock(); return r.Timeout }
func (r *DnsScanRequest) SetTimeout(val time.Duration) { r.mu.Lock(); defer r.mu.Unlock(); r.Timeout = val }
func (r *DnsScanRequest) GetWorkers() int { r.mu.RLock(); defer r.mu.RUnlock(); return r.Workers }
func (r *DnsScanRequest) SetWorkers(val int) { r.mu.Lock(); defer r.mu.Unlock(); r.Workers = val }
func (r *DnsScanRequest) GetSamples() int { r.mu.RLock(); defer r.mu.RUnlock(); return r.Samples }
func (r *DnsScanRequest) SetSamples(val int) { r.mu.Lock(); defer r.mu.Unlock(); r.Samples = val }
func (r *DnsScanRequest) GetRatePerSecond() int { r.mu.RLock(); defer r.mu.RUnlock(); return r.RatePerSecond }
func (r *DnsScanRequest) SetRatePerSecond(val int) { r.mu.Lock(); defer r.mu.Unlock(); r.RatePerSecond = val }
func (r *DnsScanRequest) GetJitter() time.Duration { r.mu.RLock(); defer r.mu.RUnlock(); return r.Jitter }
func (r *DnsScanRequest) SetJitter(val time.Duration) { r.mu.Lock(); defer r.mu.Unlock(); r.Jitter = val }
func (r *DnsScanRequest) GetPort() int { r.mu.RLock(); defer r.mu.RUnlock(); return r.Port }
func (r *DnsScanRequest) SetPort(val int) { r.mu.Lock(); defer r.mu.Unlock(); r.Port = val }
func (r *DnsScanRequest) GetProtocol() string { r.mu.RLock(); defer r.mu.RUnlock(); return r.Protocol }
func (r *DnsScanRequest) SetProtocol(val string) { r.mu.Lock(); defer r.mu.Unlock(); r.Protocol = val }
func (r *DnsScanRequest) GetEnableDNSSEC() bool { r.mu.RLock(); defer r.mu.RUnlock(); return r.EnableDNSSEC }
func (r *DnsScanRequest) SetEnableDNSSEC(val bool) { r.mu.Lock(); defer r.mu.Unlock(); r.EnableDNSSEC = val }
func (r *DnsScanRequest) GetEnableEDNS() bool { r.mu.RLock(); defer r.mu.RUnlock(); return r.EnableEDNS }
func (r *DnsScanRequest) SetEnableEDNS(val bool) { r.mu.Lock(); defer r.mu.Unlock(); r.EnableEDNS = val }
func (r *DnsScanRequest) GetAllowedLatency() time.Duration { r.mu.RLock(); defer r.mu.RUnlock(); return r.AllowedLatency }
func (r *DnsScanRequest) SetAllowedLatency(val time.Duration) { r.mu.Lock(); defer r.mu.Unlock(); r.AllowedLatency = val }
func (r *DnsScanRequest) GetCacheDNS() bool { r.mu.RLock(); defer r.mu.RUnlock(); return r.CacheDNS }
func (r *DnsScanRequest) SetCacheDNS(val bool) { r.mu.Lock(); defer r.mu.Unlock(); r.CacheDNS = val }

// Builders for DnsScanRequest
func (r *DnsScanRequest) WithHostname(val string) *DnsScanRequest { r.SetHostname(val); return r }
func (r *DnsScanRequest) WithResolverPool(val []string) *DnsScanRequest { r.SetResolverPool(val); return r }
func (r *DnsScanRequest) WithFlags(val uint32) *DnsScanRequest { r.SetFlags(val); return r }
func (r *DnsScanRequest) WithQTypes(val []string) *DnsScanRequest { r.SetQTypes(val); return r }
func (r *DnsScanRequest) WithTimeout(val time.Duration) *DnsScanRequest { r.SetTimeout(val); return r }
func (r *DnsScanRequest) WithWorkers(val int) *DnsScanRequest { r.SetWorkers(val); return r }
func (r *DnsScanRequest) WithSamples(val int) *DnsScanRequest { r.SetSamples(val); return r }
func (r *DnsScanRequest) WithRatePerSecond(val int) *DnsScanRequest { r.SetRatePerSecond(val); return r }
func (r *DnsScanRequest) WithJitter(val time.Duration) *DnsScanRequest { r.SetJitter(val); return r }
func (r *DnsScanRequest) WithPort(val int) *DnsScanRequest { r.SetPort(val); return r }
func (r *DnsScanRequest) WithProtocol(val string) *DnsScanRequest { r.SetProtocol(val); return r }
func (r *DnsScanRequest) WithEnableDNSSEC(val bool) *DnsScanRequest { r.SetEnableDNSSEC(val); return r }
func (r *DnsScanRequest) WithEnableEDNS(val bool) *DnsScanRequest { r.SetEnableEDNS(val); return r }
func (r *DnsScanRequest) WithAllowedLatency(val time.Duration) *DnsScanRequest { r.SetAllowedLatency(val); return r }
func (r *DnsScanRequest) WithCacheDNS(val bool) *DnsScanRequest { r.SetCacheDNS(val); return r }

// Array Modifiers for DnsScanRequest
func (r *DnsScanRequest) AddResolver(val string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ResolverPool = append(r.ResolverPool, val)
}
func (r *DnsScanRequest) RemoveResolver(val string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, v := range r.ResolverPool {
		if v == val {
			r.ResolverPool = append(r.ResolverPool[:i], r.ResolverPool[i+1:]...)
			return true
		}
	}
	return false
}
func (r *DnsScanRequest) AddQType(val string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.QTypes = append(r.QTypes, val)
}
func (r *DnsScanRequest) RemoveQType(val string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, v := range r.QTypes {
		if v == val {
			r.QTypes = append(r.QTypes[:i], r.QTypes[i+1:]...)
			return true
		}
	}
	return false
}
func (r *DnsScanRequest) ClearResolvers() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ResolverPool = make([]string, 0)
}
func (r *DnsScanRequest) ClearQTypes() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.QTypes = make([]string, 0)
}

// DnsAttempt records individual DNS query execution details, including remote endpoint IP, latency, and error types.
type DnsAttempt struct {
	Resolver  string        `json:"resolver"`
	IP        string        `json:"ip,omitempty"`
	Latency   time.Duration `json:"latency"`
	Err       string        `json:"err,omitempty"`
	Transport string        `json:"transport"`
	Outcome   string        `json:"outcome"`
	Truncated bool          `json:"truncated"`
	RCode     int           `json:"rcode"`
	RawSize   int           `json:"raw_size"`
	QueryTime time.Time     `json:"query_time"`
}

// Getters & Setters for DnsAttempt
func (a *DnsAttempt) GetResolver() string { return a.Resolver }
func (a *DnsAttempt) SetResolver(val string) { a.Resolver = val }
func (a *DnsAttempt) GetIP() string { return a.IP }
func (a *DnsAttempt) SetIP(val string) { a.IP = val }
func (a *DnsAttempt) GetLatency() time.Duration { return a.Latency }
func (a *DnsAttempt) SetLatency(val time.Duration) { a.Latency = val }
func (a *DnsAttempt) GetErr() string { return a.Err }
func (a *DnsAttempt) SetErr(val string) { a.Err = val }
func (a *DnsAttempt) GetTransport() string { return a.Transport }
func (a *DnsAttempt) SetTransport(val string) { a.Transport = val }
func (a *DnsAttempt) GetOutcome() string { return a.Outcome }
func (a *DnsAttempt) SetOutcome(val string) { a.Outcome = val }
func (a *DnsAttempt) GetTruncated() bool { return a.Truncated }
func (a *DnsAttempt) SetTruncated(val bool) { a.Truncated = val }
func (a *DnsAttempt) GetRCode() int { return a.RCode }
func (a *DnsAttempt) SetRCode(val int) { a.RCode = val }
func (a *DnsAttempt) GetRawSize() int { return a.RawSize }
func (a *DnsAttempt) SetRawSize(val int) { a.RawSize = val }
func (a *DnsAttempt) GetQueryTime() time.Time { return a.QueryTime }
func (a *DnsAttempt) SetQueryTime(val time.Time) { a.QueryTime = val }

// Builders for DnsAttempt
func (a *DnsAttempt) WithResolver(val string) *DnsAttempt { a.SetResolver(val); return a }
func (a *DnsAttempt) WithIP(val string) *DnsAttempt { a.SetIP(val); return a }
func (a *DnsAttempt) WithLatency(val time.Duration) *DnsAttempt { a.SetLatency(val); return a }
func (a *DnsAttempt) WithErr(val string) *DnsAttempt { a.SetErr(val); return a }
func (a *DnsAttempt) WithTransport(val string) *DnsAttempt { a.SetTransport(val); return a }
func (a *DnsAttempt) WithOutcome(val string) *DnsAttempt { a.SetOutcome(val); return a }
func (a *DnsAttempt) WithTruncated(val bool) *DnsAttempt { a.SetTruncated(val); return a }
func (a *DnsAttempt) WithRCode(val int) *DnsAttempt { a.SetRCode(val); return a }
func (a *DnsAttempt) WithRawSize(val int) *DnsAttempt { a.SetRawSize(val); return a }
func (a *DnsAttempt) WithQueryTime(val time.Time) *DnsAttempt { a.SetQueryTime(val); return a }

// DnsResult summarizes the scanning results, listing resolved IPs, lookup success status, and best response latency.
type DnsResult struct {
	mu            sync.RWMutex
	ResolvedIPs   []string      `json:"resolved_ips"`
	Success       bool          `json:"success"`
	BestLatency   time.Duration `json:"best_latency"`
	Attempts      []DnsAttempt  `json:"attempts"`
	Domain        string        `json:"domain"`
	CNAMEChain    []string      `json:"cname_chain"`
	CNAMELoop     bool          `json:"cname_loop"`
	TTLMin        uint32        `json:"ttl_min"`
	Authoritative bool          `json:"authoritative"`
	Recursive     bool          `json:"recursive"`
	DNSSEC        bool          `json:"dnssec"`
	EDNS          bool          `json:"edns"`
	Truncated     bool          `json:"truncated"`
	Vendor        string        `json:"vendor"`
	Health        int           `json:"health"`
}

// Getters & Setters for DnsResult
func (r *DnsResult) GetResolvedIPs() []string { r.mu.RLock(); defer r.mu.RUnlock(); return r.ResolvedIPs }
func (r *DnsResult) SetResolvedIPs(val []string) { r.mu.Lock(); defer r.mu.Unlock(); r.ResolvedIPs = val }
func (r *DnsResult) GetSuccess() bool { r.mu.RLock(); defer r.mu.RUnlock(); return r.Success }
func (r *DnsResult) SetSuccess(val bool) { r.mu.Lock(); defer r.mu.Unlock(); r.Success = val }
func (r *DnsResult) GetBestLatency() time.Duration { r.mu.RLock(); defer r.mu.RUnlock(); return r.BestLatency }
func (r *DnsResult) SetBestLatency(val time.Duration) { r.mu.Lock(); defer r.mu.Unlock(); r.BestLatency = val }
func (r *DnsResult) GetAttempts() []DnsAttempt { r.mu.RLock(); defer r.mu.RUnlock(); return r.Attempts }
func (r *DnsResult) SetAttempts(val []DnsAttempt) { r.mu.Lock(); defer r.mu.Unlock(); r.Attempts = val }
func (r *DnsResult) GetDomain() string { r.mu.RLock(); defer r.mu.RUnlock(); return r.Domain }
func (r *DnsResult) SetDomain(val string) { r.mu.Lock(); defer r.mu.Unlock(); r.Domain = val }
func (r *DnsResult) GetCNAMEChain() []string { r.mu.RLock(); defer r.mu.RUnlock(); return r.CNAMEChain }
func (r *DnsResult) SetCNAMEChain(val []string) { r.mu.Lock(); defer r.mu.Unlock(); r.CNAMEChain = val }
func (r *DnsResult) GetCNAMELoop() bool { r.mu.RLock(); defer r.mu.RUnlock(); return r.CNAMELoop }
func (r *DnsResult) SetCNAMELoop(val bool) { r.mu.Lock(); defer r.mu.Unlock(); r.CNAMELoop = val }
func (r *DnsResult) GetTTLMin() uint32 { r.mu.RLock(); defer r.mu.RUnlock(); return r.TTLMin }
func (r *DnsResult) SetTTLMin(val uint32) { r.mu.Lock(); defer r.mu.Unlock(); r.TTLMin = val }
func (r *DnsResult) GetAuthoritative() bool { r.mu.RLock(); defer r.mu.RUnlock(); return r.Authoritative }
func (r *DnsResult) SetAuthoritative(val bool) { r.mu.Lock(); defer r.mu.Unlock(); r.Authoritative = val }
func (r *DnsResult) GetRecursive() bool { r.mu.RLock(); defer r.mu.RUnlock(); return r.Recursive }
func (r *DnsResult) SetRecursive(val bool) { r.mu.Lock(); defer r.mu.Unlock(); r.Recursive = val }
func (r *DnsResult) GetDNSSEC() bool { r.mu.RLock(); defer r.mu.RUnlock(); return r.DNSSEC }
func (r *DnsResult) SetDNSSEC(val bool) { r.mu.Lock(); defer r.mu.Unlock(); r.DNSSEC = val }
func (r *DnsResult) GetEDNS() bool { r.mu.RLock(); defer r.mu.RUnlock(); return r.EDNS }
func (r *DnsResult) SetEDNS(val bool) { r.mu.Lock(); defer r.mu.Unlock(); r.EDNS = val }
func (r *DnsResult) GetTruncated() bool { r.mu.RLock(); defer r.mu.RUnlock(); return r.Truncated }
func (r *DnsResult) SetTruncated(val bool) { r.mu.Lock(); defer r.mu.Unlock(); r.Truncated = val }
func (r *DnsResult) GetVendor() string { r.mu.RLock(); defer r.mu.RUnlock(); return r.Vendor }
func (r *DnsResult) SetVendor(val string) { r.mu.Lock(); defer r.mu.Unlock(); r.Vendor = val }
func (r *DnsResult) GetHealth() int { r.mu.RLock(); defer r.mu.RUnlock(); return r.Health }
func (r *DnsResult) SetHealth(val int) { r.mu.Lock(); defer r.mu.Unlock(); r.Health = val }

// Builders for DnsResult
func (r *DnsResult) WithResolvedIPs(val []string) *DnsResult { r.SetResolvedIPs(val); return r }
func (r *DnsResult) WithSuccess(val bool) *DnsResult { r.SetSuccess(val); return r }
func (r *DnsResult) WithBestLatency(val time.Duration) *DnsResult { r.SetBestLatency(val); return r }
func (r *DnsResult) WithAttempts(val []DnsAttempt) *DnsResult { r.SetAttempts(val); return r }
func (r *DnsResult) WithDomain(val string) *DnsResult { r.SetDomain(val); return r }
func (r *DnsResult) WithCNAMEChain(val []string) *DnsResult { r.SetCNAMEChain(val); return r }
func (r *DnsResult) WithCNAMELoop(val bool) *DnsResult { r.SetCNAMELoop(val); return r }
func (r *DnsResult) WithTTLMin(val uint32) *DnsResult { r.SetTTLMin(val); return r }
func (r *DnsResult) WithAuthoritative(val bool) *DnsResult { r.SetAuthoritative(val); return r }
func (r *DnsResult) WithRecursive(val bool) *DnsResult { r.SetRecursive(val); return r }
func (r *DnsResult) WithDNSSEC(val bool) *DnsResult { r.SetDNSSEC(val); return r }
func (r *DnsResult) WithEDNS(val bool) *DnsResult { r.SetEDNS(val); return r }
func (r *DnsResult) WithTruncated(val bool) *DnsResult { r.SetTruncated(val); return r }
func (r *DnsResult) WithVendor(val string) *DnsResult { r.SetVendor(val); return r }
func (r *DnsResult) WithHealth(val int) *DnsResult { r.SetHealth(val); return r }

// Array Modifiers for DnsResult
func (r *DnsResult) AddResolvedIP(val string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ResolvedIPs = append(r.ResolvedIPs, val)
}
func (r *DnsResult) RemoveResolvedIP(val string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, v := range r.ResolvedIPs {
		if v == val {
			r.ResolvedIPs = append(r.ResolvedIPs[:i], r.ResolvedIPs[i+1:]...)
			return true
		}
	}
	return false
}
func (r *DnsResult) AddAttempt(val DnsAttempt) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Attempts = append(r.Attempts, val)
}
func (r *DnsResult) RemoveAttempt(resolver string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, v := range r.Attempts {
		if v.Resolver == resolver {
			r.Attempts = append(r.Attempts[:i], r.Attempts[i+1:]...)
			return true
		}
	}
	return false
}
func (r *DnsResult) ClearResolvedIPs() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ResolvedIPs = make([]string, 0)
}
func (r *DnsResult) ClearAttempts() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Attempts = make([]DnsAttempt, 0)
}

// DnsTTLRecord tracks the Time-to-Live (TTL) variance of resolved domains.
type DnsTTLRecord struct {
	TTL       uint32    `json:"ttl"`
	Observed  time.Time `json:"observed"`
	IP        string    `json:"ip"`
	Name      string    `json:"name"`
	RType     string    `json:"rtype"`
	Domain    string    `json:"domain"`
	Timestamp time.Time `json:"timestamp"`
	Active    bool      `json:"active"`
	TTLMin    uint32    `json:"ttl_min"`
	TTLMax    uint32    `json:"ttl_max"`
}

// Getters & Setters for DnsTTLRecord
func (t *DnsTTLRecord) GetTTL() uint32 { return t.TTL }
func (t *DnsTTLRecord) SetTTL(val uint32) { t.TTL = val }
func (t *DnsTTLRecord) GetObserved() time.Time { return t.Observed }
func (t *DnsTTLRecord) SetObserved(val time.Time) { t.Observed = val }
func (t *DnsTTLRecord) GetIP() string { return t.IP }
func (t *DnsTTLRecord) SetIP(val string) { t.IP = val }
func (t *DnsTTLRecord) GetName() string { return t.Name }
func (t *DnsTTLRecord) SetName(val string) { t.Name = val }
func (t *DnsTTLRecord) GetRType() string { return t.RType }
func (t *DnsTTLRecord) SetRType(val string) { t.RType = val }
func (t *DnsTTLRecord) GetDomain() string { return t.Domain }
func (t *DnsTTLRecord) SetDomain(val string) { t.Domain = val }
func (t *DnsTTLRecord) GetTimestamp() time.Time { return t.Timestamp }
func (t *DnsTTLRecord) SetTimestamp(val time.Time) { t.Timestamp = val }
func (t *DnsTTLRecord) GetActive() bool { return t.Active }
func (t *DnsTTLRecord) SetActive(val bool) { t.Active = val }
func (t *DnsTTLRecord) GetTTLMin() uint32 { return t.TTLMin }
func (t *DnsTTLRecord) SetTTLMin(val uint32) { t.TTLMin = val }
func (t *DnsTTLRecord) GetTTLMax() uint32 { return t.TTLMax }
func (t *DnsTTLRecord) SetTTLMax(val uint32) { t.TTLMax = val }

// Builders for DnsTTLRecord
func (t *DnsTTLRecord) WithTTL(val uint32) *DnsTTLRecord { t.SetTTL(val); return t }
func (t *DnsTTLRecord) WithObserved(val time.Time) *DnsTTLRecord { t.SetObserved(val); return t }
func (t *DnsTTLRecord) WithIP(val string) *DnsTTLRecord { t.SetIP(val); return t }
func (t *DnsTTLRecord) WithName(val string) *DnsTTLRecord { t.SetName(val); return t }
func (t *DnsTTLRecord) WithRType(val string) *DnsTTLRecord { t.SetRType(val); return t }
func (t *DnsTTLRecord) WithDomain(val string) *DnsTTLRecord { t.SetDomain(val); return t }
func (t *DnsTTLRecord) WithTimestamp(val time.Time) *DnsTTLRecord { t.SetTimestamp(val); return t }
func (t *DnsTTLRecord) WithActive(val bool) *DnsTTLRecord { t.SetActive(val); return t }
func (t *DnsTTLRecord) WithTTLMin(val uint32) *DnsTTLRecord { t.SetTTLMin(val); return t }
func (t *DnsTTLRecord) WithTTLMax(val uint32) *DnsTTLRecord { t.SetTTLMax(val); return t }

// ParsedDNS structures extracted records for evaluation against known censorship signatures.
type ParsedDNS struct {
	Domain           string         `json:"domain"`
	Records          []DnsTTLRecord `json:"records"`
	CensorshipOk     bool           `json:"censorship_ok"`
	CensorshipType   string         `json:"censorship_type"`
	LastChecked      time.Time      `json:"last_checked"`
	IsWhitelisted    bool           `json:"is_whitelisted"`
	IsBlacklisted    bool           `json:"is_blacklisted"`
	MatchesSignature bool           `json:"matches_signature"`
	ResponseCode     int            `json:"response_code"`
	LatencyMin       time.Duration  `json:"latency_min"`
}

// Getters & Setters for ParsedDNS
func (p *ParsedDNS) GetDomain() string { return p.Domain }
func (p *ParsedDNS) SetDomain(val string) { p.Domain = val }
func (p *ParsedDNS) GetRecords() []DnsTTLRecord { return p.Records }
func (p *ParsedDNS) SetRecords(val []DnsTTLRecord) { p.Records = val }
func (p *ParsedDNS) GetCensorshipOk() bool { return p.CensorshipOk }
func (p *ParsedDNS) SetCensorshipOk(val bool) { p.CensorshipOk = val }
func (p *ParsedDNS) GetCensorshipType() string { return p.CensorshipType }
func (p *ParsedDNS) SetCensorshipType(val string) { p.CensorshipType = val }
func (p *ParsedDNS) GetLastChecked() time.Time { return p.LastChecked }
func (p *ParsedDNS) SetLastChecked(val time.Time) { p.LastChecked = val }
func (p *ParsedDNS) GetIsWhitelisted() bool { return p.IsWhitelisted }
func (p *ParsedDNS) SetIsWhitelisted(val bool) { p.IsWhitelisted = val }
func (p *ParsedDNS) GetIsBlacklisted() bool { return p.IsBlacklisted }
func (p *ParsedDNS) SetIsBlacklisted(val bool) { p.IsBlacklisted = val }
func (p *ParsedDNS) GetMatchesSignature() bool { return p.MatchesSignature }
func (p *ParsedDNS) SetMatchesSignature(val bool) { p.MatchesSignature = val }
func (p *ParsedDNS) GetResponseCode() int { return p.ResponseCode }
func (p *ParsedDNS) SetResponseCode(val int) { p.ResponseCode = val }
func (p *ParsedDNS) GetLatencyMin() time.Duration { return p.LatencyMin }
func (p *ParsedDNS) SetLatencyMin(val time.Duration) { p.LatencyMin = val }

// Builders for ParsedDNS
func (p *ParsedDNS) WithDomain(val string) *ParsedDNS { p.SetDomain(val); return p }
func (p *ParsedDNS) WithRecords(val []DnsTTLRecord) *ParsedDNS { p.SetRecords(val); return p }
func (p *ParsedDNS) WithCensorshipOk(val bool) *ParsedDNS { p.SetCensorshipOk(val); return p }
func (p *ParsedDNS) WithCensorshipType(val string) *ParsedDNS { p.SetCensorshipType(val); return p }
func (p *ParsedDNS) WithLastChecked(val time.Time) *ParsedDNS { p.SetLastChecked(val); return p }
func (p *ParsedDNS) WithIsWhitelisted(val bool) *ParsedDNS { p.SetIsWhitelisted(val); return p }
func (p *ParsedDNS) WithIsBlacklisted(val bool) *ParsedDNS { p.SetIsBlacklisted(val); return p }
func (p *ParsedDNS) WithMatchesSignature(val bool) *ParsedDNS { p.SetMatchesSignature(val); return p }
func (p *ParsedDNS) WithResponseCode(val int) *ParsedDNS { p.SetResponseCode(val); return p }
func (p *ParsedDNS) WithLatencyMin(val time.Duration) *ParsedDNS { p.SetLatencyMin(val); return p }

// DnsJob manages the concurrent execution of DNS query probes.
type DnsJob struct {
	Request DnsScanRequest
	Results chan DnsAttempt
	mu      sync.Mutex
	done    bool
}

// Run executes the DNS scans concurrently.
func (j *DnsJob) Run(ctx context.Context) *DnsResult {
	j.mu.Lock()
	if j.done {
		j.mu.Unlock()
		return &DnsResult{}
	}
	j.done = true
	j.mu.Unlock()

	var wg sync.WaitGroup
	attemptsChan := make(chan DnsAttempt, len(j.Request.ResolverPool))

	for _, resolver := range j.Request.ResolverPool {
		wg.Add(1)
		go func(res string) {
			defer wg.Done()
			start := time.Now()

			r := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{
						Timeout: 2 * time.Second,
					}
					return d.DialContext(ctx, "udp", res+":53")
				},
			}

			ips, err := r.LookupHost(ctx, j.Request.Hostname)
			latency := time.Since(start)

			var attempt DnsAttempt
			attempt.Resolver = res
			attempt.Latency = latency
			attempt.QueryTime = start
			if err != nil {
				attempt.Err = err.Error()
				attempt.Outcome = "failed"
			} else if len(ips) > 0 {
				attempt.IP = ips[0]
				attempt.Outcome = "success"
			}
			attemptsChan <- attempt
		}(resolver)
	}

	wg.Wait()
	close(attemptsChan)

	result := &DnsResult{}
	result.BestLatency = 999 * time.Second
	for att := range attemptsChan {
		result.Attempts = append(result.Attempts, att)
		if att.Err == "" {
			result.Success = true
			if att.IP != "" {
				result.ResolvedIPs = append(result.ResolvedIPs, att.IP)
			}
			if att.Latency < result.BestLatency {
				result.BestLatency = att.Latency
			}
		}
	}

	if len(result.ResolvedIPs) == 0 {
		result.BestLatency = 0
	}

	return result
}
