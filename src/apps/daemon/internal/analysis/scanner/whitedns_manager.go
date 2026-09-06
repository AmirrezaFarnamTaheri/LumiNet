// Package scanner implements host and dns probing operations.

package scanner

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// WhiteDnsManager resolves and caches specific SDK hosts using fallback DNS addresses.
type WhiteDnsManager struct {
	mu                sync.RWMutex
	DomainMap         map[string][]string
	DnsServers        []string
	SdkHosts          []string
	DefaultTencentDns string
	QueryTimeout      time.Duration
	CacheTTL          time.Duration
	QueriesRun        int64
	SuccessCount      int64
	FailureCount      int64
	LastQueryTime     time.Time
}

// Getters & Setters for WhiteDnsManager
func (m *WhiteDnsManager) GetDomainMap() map[string][]string { m.mu.RLock(); defer m.mu.RUnlock(); return m.DomainMap }
func (m *WhiteDnsManager) SetDomainMap(v map[string][]string) { m.mu.Lock(); defer m.mu.Unlock(); m.DomainMap = v }
func (m *WhiteDnsManager) GetDnsServers() []string { m.mu.RLock(); defer m.mu.RUnlock(); return m.DnsServers }
func (m *WhiteDnsManager) SetDnsServers(v []string) { m.mu.Lock(); defer m.mu.Unlock(); m.DnsServers = v }
func (m *WhiteDnsManager) GetSdkHosts() []string { m.mu.RLock(); defer m.mu.RUnlock(); return m.SdkHosts }
func (m *WhiteDnsManager) SetSdkHosts(v []string) { m.mu.Lock(); defer m.mu.Unlock(); m.SdkHosts = v }
func (m *WhiteDnsManager) GetDefaultTencentDns() string { m.mu.RLock(); defer m.mu.RUnlock(); return m.DefaultTencentDns }
func (m *WhiteDnsManager) SetDefaultTencentDns(v string) { m.mu.Lock(); defer m.mu.Unlock(); m.DefaultTencentDns = v }
func (m *WhiteDnsManager) GetQueryTimeout() time.Duration { m.mu.RLock(); defer m.mu.RUnlock(); return m.QueryTimeout }
func (m *WhiteDnsManager) SetQueryTimeout(v time.Duration) { m.mu.Lock(); defer m.mu.Unlock(); m.QueryTimeout = v }
func (m *WhiteDnsManager) GetCacheTTL() time.Duration { m.mu.RLock(); defer m.mu.RUnlock(); return m.CacheTTL }
func (m *WhiteDnsManager) SetCacheTTL(v time.Duration) { m.mu.Lock(); defer m.mu.Unlock(); m.CacheTTL = v }
func (m *WhiteDnsManager) GetQueriesRun() int64 { return atomic.LoadInt64(&m.QueriesRun) }
func (m *WhiteDnsManager) SetQueriesRun(v int64) { atomic.StoreInt64(&m.QueriesRun, v) }
func (m *WhiteDnsManager) GetSuccessCount() int64 { return atomic.LoadInt64(&m.SuccessCount) }
func (m *WhiteDnsManager) SetSuccessCount(v int64) { atomic.StoreInt64(&m.SuccessCount, v) }
func (m *WhiteDnsManager) GetFailureCount() int64 { return atomic.LoadInt64(&m.FailureCount) }
func (m *WhiteDnsManager) SetFailureCount(v int64) { atomic.StoreInt64(&m.FailureCount, v) }
func (m *WhiteDnsManager) GetLastQueryTime() time.Time { m.mu.RLock(); defer m.mu.RUnlock(); return m.LastQueryTime }
func (m *WhiteDnsManager) SetLastQueryTime(v time.Time) { m.mu.Lock(); defer m.mu.Unlock(); m.LastQueryTime = v }

// Builders for WhiteDnsManager
func (m *WhiteDnsManager) WithDnsServers(v []string) *WhiteDnsManager { m.SetDnsServers(v); return m }
func (m *WhiteDnsManager) WithSdkHosts(v []string) *WhiteDnsManager { m.SetSdkHosts(v); return m }
func (m *WhiteDnsManager) WithDefaultTencentDns(v string) *WhiteDnsManager { m.SetDefaultTencentDns(v); return m }
func (m *WhiteDnsManager) WithQueryTimeout(v time.Duration) *WhiteDnsManager { m.SetQueryTimeout(v); return m }
func (m *WhiteDnsManager) WithCacheTTL(v time.Duration) *WhiteDnsManager { m.SetCacheTTL(v); return m }

// Operations
func NewWhiteDnsManager() *WhiteDnsManager {
	return &WhiteDnsManager{
		DomainMap:         make(map[string][]string),
		DefaultTencentDns: "119.29.29.29",
		QueryTimeout:      2 * time.Second,
		CacheTTL:          10 * time.Minute,
		DnsServers:        []string{"1.1.1.1", "8.8.8.8"},
		SdkHosts: []string{
			"cloudcapiv4.herewhite.com",
			"expresscloudharestoragev2.herewhite.com",
			"cloudharestoragev2.herewhite.com",
			"scdncloudharestoragev3.herewhite.com",
		},
	}
}

func (m *WhiteDnsManager) QuerySdkDomains(ctx context.Context) {
	hosts := m.GetSdkHosts()
	for _, host := range hosts {
		m.QueryHost(ctx, host)
	}
}

func (m *WhiteDnsManager) QueryHost(ctx context.Context, host string) {
	atomic.AddInt64(&m.QueriesRun, 1)
	m.mu.Lock()
	m.LastQueryTime = time.Now()
	m.mu.Unlock()

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: m.GetQueryTimeout(),
			}
			return d.DialContext(ctx, network, m.GetDefaultTencentDns()+":53")
		},
	}

	ips, err := resolver.LookupHost(ctx, host)
	if err != nil || len(ips) == 0 {
		atomic.AddInt64(&m.FailureCount, 1)
		return
	}

	atomic.AddInt64(&m.SuccessCount, 1)
	m.mu.Lock()
	m.DomainMap[host] = ips
	m.mu.Unlock()
}

func (m *WhiteDnsManager) IpForDomain(host string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ips, ok := m.DomainMap[host]
	if !ok || len(ips) == 0 {
		return ""
	}
	return ips[0]
}

func (m *WhiteDnsManager) CanonicalRequestForRequest(originalUrl string, host string) (string, string) {
	ip := m.IpForDomain(host)
	if ip == "" {
		return originalUrl, ""
	}

	// Substitute host with IP in originalUrl
	newUrl := strings.Replace(originalUrl, host, ip, 1)

	// In China/domestic networks, if global acceleration isn't needed, fallback to normal storage storage
	if strings.Contains(host, "scdncloudharestoragev3.herewhite.com") {
		normalIp := m.IpForDomain("expresscloudharestoragev2.herewhite.com")
		if normalIp != "" {
			newUrl = strings.Replace(originalUrl, "scdncloudharestoragev3.herewhite.com", normalIp, 1)
			return newUrl, "expresscloudharestoragev2.herewhite.com"
		}
		newUrl = strings.Replace(originalUrl, "scdncloudharestoragev3.herewhite.com", "expresscloudharestoragev2.herewhite.com", 1)
		return newUrl, ""
	}

	return newUrl, host
}

func (m *WhiteDnsManager) AddSdkHost(host string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.SdkHosts = append(m.SdkHosts, host)
}

func (m *WhiteDnsManager) RemoveSdkHost(host string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, h := range m.SdkHosts {
		if h == host {
			m.SdkHosts = append(m.SdkHosts[:i], m.SdkHosts[i+1:]...)
			return true
		}
	}
	return false
}

func (m *WhiteDnsManager) ClearSdkHosts() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.SdkHosts = make([]string, 0)
}

func (m *WhiteDnsManager) AddDnsServer(server string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.DnsServers = append(m.DnsServers, server)
}

func (m *WhiteDnsManager) RemoveDnsServer(server string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, s := range m.DnsServers {
		if s == server {
			m.DnsServers = append(m.DnsServers[:i], m.DnsServers[i+1:]...)
			return true
		}
	}
	return false
}

func (m *WhiteDnsManager) ClearDnsServers() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.DnsServers = make([]string, 0)
}

func (m *WhiteDnsManager) ResetStats() {
	atomic.StoreInt64(&m.QueriesRun, 0)
	atomic.StoreInt64(&m.SuccessCount, 0)
	atomic.StoreInt64(&m.FailureCount, 0)
}

func (m *WhiteDnsManager) GetSuccessRate() float64 {
	run := atomic.LoadInt64(&m.QueriesRun)
	if run == 0 {
		return 1.0
	}
	return float64(atomic.LoadInt64(&m.SuccessCount)) / float64(run)
}
