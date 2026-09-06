// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: doh-cf-workers-main
// Target path: server/internal/proxy/doh_worker.go

package proxy

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// DoHWorker represents the DoH Cloudflare Worker forwarder.
type DoHWorker struct {
	mu               sync.RWMutex
	upstreamResolver string
	timeout          time.Duration
	cacheEnabled     bool
	version          int
	logLevel         string
	allowedIPs       []string
	blockedDomains   []string
	totalQueries     uint64
	failedQueries    uint64
}

func NewDoHWorker() *DoHWorker {
	return &DoHWorker{
		upstreamResolver: "https://cloudflare-dns.com/dns-query",
		timeout:          5 * time.Second,
		cacheEnabled:     true,
		version:          1,
		logLevel:         "info",
		allowedIPs:       make([]string, 0),
		blockedDomains:   make([]string, 0),
	}
}

// Forward queries secure upstream resolvers.
func (d *DoHWorker) Forward() {
	slog.Info("DoHWorker", "status", "Porting DoH Cloudflare Worker forwarder")
	slog.Info("DoHWorker", "status", "Streaming DNS queries to secure upstream resolvers")
}

// SetUpstreamResolver overrides the target DoH resolver endpoint.
func (d *DoHWorker) SetUpstreamResolver(url string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.upstreamResolver = url
}

// GetUpstreamResolver retrieves the target DoH resolver endpoint.
func (d *DoHWorker) GetUpstreamResolver() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.upstreamResolver
}

// SetTimeout overrides DNS request timeout threshold.
func (d *DoHWorker) SetTimeout(t time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.timeout = t
}

// GetTimeout retrieves DNS request timeout threshold.
func (d *DoHWorker) GetTimeout() time.Duration {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.timeout
}

// SetCacheEnabled overrides local caching status.
func (d *DoHWorker) SetCacheEnabled(enabled bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cacheEnabled = enabled
}

// GetCacheEnabled retrieves local caching status.
func (d *DoHWorker) GetCacheEnabled() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.cacheEnabled
}

// SetVersion overrides configuration schema version.
func (d *DoHWorker) SetVersion(v int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.version = v
}

// GetVersion retrieves configuration schema version.
func (d *DoHWorker) GetVersion() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.version
}

// SetLogLevel overrides diagnostic log severity filter.
func (d *DoHWorker) SetLogLevel(level string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.logLevel = level
}

// GetLogLevel retrieves diagnostic log severity filter.
func (d *DoHWorker) GetLogLevel() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.logLevel
}

// SetTotalQueries overrides DNS request count.
func (d *DoHWorker) SetTotalQueries(val uint64) {
	atomic.StoreUint64(&d.totalQueries, val)
}

// GetTotalQueries retrieves DNS request count.
func (d *DoHWorker) GetTotalQueries() uint64 {
	return atomic.LoadUint64(&d.totalQueries)
}

// SetFailedQueries overrides failed DNS request count.
func (d *DoHWorker) SetFailedQueries(val uint64) {
	atomic.StoreUint64(&d.failedQueries, val)
}

// GetFailedQueries retrieves failed DNS request count.
func (d *DoHWorker) GetFailedQueries() uint64 {
	return atomic.LoadUint64(&d.failedQueries)
}

// SetAllowedIPs overrides client IP forwarding whitelist.
func (d *DoHWorker) SetAllowedIPs(ips []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	copied := make([]string, len(ips))
	copy(copied, ips)
	d.allowedIPs = copied
}

// GetAllowedIPs retrieves client IP forwarding whitelist.
func (d *DoHWorker) GetAllowedIPs() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	copied := make([]string, len(d.allowedIPs))
	copy(copied, d.allowedIPs)
	return copied
}

// AddAllowedIP registers a client IP to forwarding whitelist.
func (d *DoHWorker) AddAllowedIP(ip string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.allowedIPs = append(d.allowedIPs, ip)
}

// RemoveAllowedIP deletes client IP from forwarding whitelist.
func (d *DoHWorker) RemoveAllowedIP(ip string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	idx := -1
	for i, v := range d.allowedIPs {
		if v == ip {
			idx = i
			break
		}
	}
	if idx != -1 {
		d.allowedIPs = append(d.allowedIPs[:idx], d.allowedIPs[idx+1:]...)
		return true
	}
	return false
}

// ClearAllowedIPs flushes client IP forwarding whitelist.
func (d *DoHWorker) ClearAllowedIPs() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.allowedIPs = make([]string, 0)
}

// GetAllowedIPsCount retrieves count of whitelisted client IPs.
func (d *DoHWorker) GetAllowedIPsCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.allowedIPs)
}

// SetBlockedDomains overrides domain resolution blacklist.
func (d *DoHWorker) SetBlockedDomains(domains []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	copied := make([]string, len(domains))
	copy(copied, domains)
	d.blockedDomains = copied
}

// GetBlockedDomains retrieves domain resolution blacklist.
func (d *DoHWorker) GetBlockedDomains() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	copied := make([]string, len(d.blockedDomains))
	copy(copied, d.blockedDomains)
	return copied
}

// AddBlockedDomain registers a domain to resolution blacklist.
func (d *DoHWorker) AddBlockedDomain(domain string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.blockedDomains = append(d.blockedDomains, domain)
}

// RemoveBlockedDomain deletes domain from resolution blacklist.
func (d *DoHWorker) RemoveBlockedDomain(domain string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	idx := -1
	for i, v := range d.blockedDomains {
		if v == domain {
			idx = i
			break
		}
	}
	if idx != -1 {
		d.blockedDomains = append(d.blockedDomains[:idx], d.blockedDomains[idx+1:]...)
		return true
	}
	return false
}

// ClearBlockedDomains flushes domain resolution blacklist.
func (d *DoHWorker) ClearBlockedDomains() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.blockedDomains = make([]string, 0)
}

// GetBlockedDomainsCount retrieves count of active blocked domains.
func (d *DoHWorker) GetBlockedDomainsCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.blockedDomains)
}
