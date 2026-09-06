package dns

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// DnsProtocol represents the DNS transport protocol.
type DnsProtocol int

const (
	UDP DnsProtocol = iota
	TCP
	DoH
	DoT
	DoQ
	DNSCrypt
)

// DnsContext maintains request/response transaction lifecycle state.
type DnsContext struct {
	Request      []byte
	Response     []byte
	Proto        DnsProtocol
	ClientAddr   net.Addr
	UpstreamAddr string
	QueryName    string
	QueryType    uint16
	StartTime    time.Time
}

// CacheEntry represents a cached DNS response with TTL validation.
type CacheEntry struct {
	Response  []byte
	ExpiresAt time.Time
	Upstream  string
	QueryName string
	QueryType uint16
}

// IsExpired checks if the cache entry TTL has passed.
func (e *CacheEntry) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// NewCacheEntry creates a new CacheEntry with clamped TTL limits.
func NewCacheEntry(response []byte, ttl time.Duration, upstream, queryName string, queryType uint16, minTTL, maxTTL time.Duration) *CacheEntry {
	clamped := ttl
	if clamped < minTTL {
		clamped = minTTL
	}
	if clamped > maxTTL {
		clamped = maxTTL
	}
	return &CacheEntry{
		Response:  response,
		ExpiresAt: time.Now().Add(clamped),
		Upstream:  upstream,
		QueryName: queryName,
		QueryType: queryType,
	}
}

// CacheKey builds a cache key without ECS details.
func CacheKey(queryName string, queryType uint16, dnssecOK bool) string {
	flag := "0"
	if dnssecOK {
		flag = "1"
	}
	return fmt.Sprintf("%s:%d:%s", flag, queryType, strings.ToLower(queryName))
}

// CacheKeyWithECS builds a cache key incorporating client subnet options.
func CacheKeyWithECS(queryName string, queryType uint16, dnssecOK bool, ecsIP net.IP, ecsMask byte) string {
	flag := "0"
	if dnssecOK {
		flag = "1"
	}
	ecsStr := "none"
	if ecsIP != nil {
		ecsStr = fmt.Sprintf("%s/%d", ecsIP.String(), ecsMask)
	}
	return fmt.Sprintf("%s:%d:%s:%s", flag, queryType, strings.ToLower(queryName), ecsStr)
}

// DnsCache represents a thread-safe DNS cache with LRU eviction.
type DnsCache struct {
	mu      sync.RWMutex
	entries map[string]*CacheEntry
	maxSize int
	minTTL  time.Duration
	maxTTL  time.Duration
}

// NewDnsCache initializes a DNS response cache.
func NewDnsCache(maxSize int, minTTL, maxTTL time.Duration) *DnsCache {
	return &DnsCache{
		entries: make(map[string]*CacheEntry),
		maxSize: maxSize,
		minTTL:  minTTL,
		maxTTL:  maxTTL,
	}
}

// Get retrieves a valid unexpired cache entry.
func (c *DnsCache) Get(key string) (*CacheEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[key]
	if !ok || entry.IsExpired() {
		return nil, false
	}
	return entry, true
}

// Insert inserts a cache entry, evicting expired or oldest items if at capacity.
func (c *DnsCache) Insert(key string, entry *CacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) >= c.maxSize {
		for k, e := range c.entries {
			if e.IsExpired() {
				delete(c.entries, k)
			}
		}
	}

	if len(c.entries) >= c.maxSize {
		var oldestKey string
		var oldestTime time.Time
		first := true
		for k, e := range c.entries {
			if first || e.ExpiresAt.Before(oldestTime) {
				oldestKey = k
				oldestTime = e.ExpiresAt
				first = false
			}
		}
		if oldestKey != "" {
			delete(c.entries, oldestKey)
		}
	}

	c.entries[key] = entry
}

// EvictExpired removes all expired items from the cache.
func (c *DnsCache) EvictExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.entries {
		if e.IsExpired() {
			delete(c.entries, k)
		}
	}
}

// Len returns the current cache size.
func (c *DnsCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// UpstreamConfig handles domain-specific DNS upstream routing rules.
type UpstreamConfig struct {
	DefaultUpstreams []string
	DomainUpstreams  map[string][]string
	DomainExclusions []string
	mu               sync.RWMutex
}

// NewUpstreamConfig creates an UpstreamConfig instance.
func NewUpstreamConfig(defaults []string, domains map[string][]string, exclusions []string) *UpstreamConfig {
	return &UpstreamConfig{
		DefaultUpstreams: defaults,
		DomainUpstreams:  domains,
		DomainExclusions: exclusions,
	}
}

// GetUpstreamsForDomain fetches the matching upstreams for a domain hierarchy.
func (u *UpstreamConfig) GetUpstreamsForDomain(domain string) []string {
	u.mu.RLock()
	defer u.mu.RUnlock()

	domain = strings.TrimSuffix(strings.ToLower(domain), ".")

	for _, excl := range u.DomainExclusions {
		if strings.TrimSuffix(strings.ToLower(excl), ".") == domain {
			return u.DefaultUpstreams
		}
	}

	if ups, ok := u.DomainUpstreams[domain]; ok {
		return ups
	}

	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		parent := strings.Join(parts[i:], ".")
		if ups, ok := u.DomainUpstreams[parent]; ok {
			return ups
		}
	}

	return u.DefaultUpstreams
}

// PendingRequests deduplicates concurrent upstream DNS queries for identical keys.
type PendingRequests struct {
	mu      sync.Mutex
	pending map[string]chan struct{}
}

// NewPendingRequests creates a PendingRequests cache.
func NewPendingRequests() *PendingRequests {
	return &PendingRequests{
		pending: make(map[string]chan struct{}),
	}
}

// Register registers a request key as pending. Returns a completion channel and true if registered first.
func (p *PendingRequests) Register(key string) (chan struct{}, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if ch, ok := p.pending[key]; ok {
		return ch, false
	}

	ch := make(chan struct{})
	p.pending[key] = ch
	return ch, true
}

// Complete completes a pending query and notifies listeners.
func (p *PendingRequests) Complete(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if ch, ok := p.pending[key]; ok {
		close(ch)
		delete(p.pending, key)
	}
}

// BogusNxDomain filters responses containing malicious or hijack IPs into NXDOMAIN.
type BogusNxDomain struct {
	BogusIPs     []net.IP
	BogusSubnets []*net.IPNet
	mu           sync.RWMutex
}

// NewBogusNxDomain creates a BogusNxDomain registry.
func NewBogusNxDomain() *BogusNxDomain {
	return &BogusNxDomain{
		BogusIPs:     make([]net.IP, 0),
		BogusSubnets: make([]*net.IPNet, 0),
	}
}

// IsBogus checks if any IP is configured as bogus.
func (b *BogusNxDomain) IsBogus(ips []net.IP) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for _, ip := range ips {
		for _, bogusIP := range b.BogusIPs {
			if ip.Equal(bogusIP) {
				return true
			}
		}
		for _, subnet := range b.BogusSubnets {
			if subnet.Contains(ip) {
				return true
			}
		}
	}
	return false
}

type rateCounter struct {
	count       uint32
	windowStart time.Time
}

// RateLimiter limits the DNS query rate per client IP subnet.
type RateLimiter struct {
	mu          sync.Mutex
	rate        uint32
	subnetLenV4 byte
	subnetLenV6 byte
	counters    map[string]*rateCounter
}

// NewRateLimiter creates a RateLimiter instance.
func NewRateLimiter(rate uint32, subnetLenV4, subnetLenV6 byte) *RateLimiter {
	return &RateLimiter{
		rate:        rate,
		subnetLenV4: subnetLenV4,
		subnetLenV6: subnetLenV6,
		counters:    make(map[string]*rateCounter),
	}
}

// IsLimited checks if the client IP exceeds the rate limits.
func (r *RateLimiter) IsLimited(ip net.IP) bool {
	if r.rate == 0 {
		return false
	}
	key := r.subnetKey(ip)

	r.mu.Lock()
	defer r.mu.Unlock()

	counter, ok := r.counters[key]
	if !ok {
		counter = &rateCounter{count: 0, windowStart: time.Now()}
		r.counters[key] = counter
	}

	if time.Since(counter.windowStart) >= time.Second {
		counter.count = 0
		counter.windowStart = time.Now()
	}

	counter.count++
	return counter.count > r.rate
}

func (r *RateLimiter) subnetKey(ip net.IP) string {
	if ip.To4() != nil {
		mask := net.CIDRMask(int(r.subnetLenV4), 32)
		masked := ip.Mask(mask)
		return "v4:" + masked.String()
	}
	mask := net.CIDRMask(int(r.subnetLenV6), 128)
	masked := ip.Mask(mask)
	return "v6:" + masked.String()
}

// DnsHandler processes a DnsContext payload.
type DnsHandler interface {
	Handle(ctx *DnsContext) error
}

// DnsMiddleware encapsulates a DnsHandler in pre/post execution hooks.
type DnsMiddleware interface {
	Wrap(next DnsHandler) DnsHandler
}

// DnsProxyConfig defines DNS proxy operational variables.
type DnsProxyConfig struct {
	Listen        []string
	Upstreams     *UpstreamConfig
	CacheSize     int
	CacheMinTTL   time.Duration
	CacheMaxTTL   time.Duration
	RateLimit     uint32
	Dns64         bool
	Nat64Prefix   []byte
	BogusNxDomain *BogusNxDomain
	EnableECS     bool
	BlockAAAA     bool
}
