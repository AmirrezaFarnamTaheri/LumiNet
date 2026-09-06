package security

import (
	"bufio"
	"net"
	"strings"
	"sync"
)

type BlockCategory int

const (
	CategoryMalware BlockCategory = iota
	CategoryAdvertising
	CategoryTracking
	CategoryCryptomining
	CategoryAdultContent
	CategoryTelemetry
)

type DnsBlocklistEngine struct {
	exactDomains       map[string]BlockCategory
	wildcardSuffixes   map[string]BlockCategory
	whitelistedDomains map[string]bool
	blockedIPs         map[string]bool
	mu                 sync.RWMutex
}

func NewDnsBlocklistEngine() *DnsBlocklistEngine {
	return &DnsBlocklistEngine{
		exactDomains:       make(map[string]BlockCategory),
		wildcardSuffixes:   make(map[string]BlockCategory),
		whitelistedDomains: make(map[string]bool),
		blockedIPs:         make(map[string]bool),
	}
}

func (e *DnsBlocklistEngine) AddExactRule(domain string, cat BlockCategory) {
	e.mu.Lock()
	defer e.mu.Unlock()
	clean := strings.Trim(strings.ToLower(domain), ". ")
	if clean != "" {
		e.exactDomains[clean] = cat
	}
}

func (e *DnsBlocklistEngine) AddWildcardRule(suffix string, cat BlockCategory) {
	e.mu.Lock()
	defer e.mu.Unlock()
	clean := strings.Trim(strings.ToLower(suffix), ". ")
	clean = strings.TrimPrefix(clean, "*.")
	clean = strings.TrimPrefix(clean, ".")
	if clean != "" {
		e.wildcardSuffixes[clean] = cat
	}
}

func (e *DnsBlocklistEngine) AddWhitelist(domain string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	clean := strings.Trim(strings.ToLower(domain), ". ")
	if clean != "" {
		e.whitelistedDomains[clean] = true
	}
}

func (e *DnsBlocklistEngine) AddBlockedIP(ip net.IP) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if ip != nil {
		e.blockedIPs[ip.String()] = true
	}
}

func (e *DnsBlocklistEngine) ParseHostsContent(content string, cat BlockCategory) {
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 && (parts[0] == "0.0.0.0" || parts[0] == "127.0.0.1") {
			e.AddExactRule(parts[1], cat)
		} else if len(parts) == 1 {
			if strings.HasPrefix(parts[0], "*.") || strings.HasPrefix(parts[0], ".") {
				e.AddWildcardRule(parts[0], cat)
			} else {
				e.AddExactRule(parts[0], cat)
			}
		}
	}
}

func (e *DnsBlocklistEngine) IsDomainBlocked(domain string) (BlockCategory, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	clean := strings.Trim(strings.ToLower(domain), ". ")

	// 1. Whitelist check
	if e.whitelistedDomains[clean] {
		return 0, false
	}
	parts := strings.Split(clean, ".")
	for i := 1; i < len(parts); i++ {
		parent := strings.Join(parts[i:], ".")
		if e.whitelistedDomains[parent] {
			return 0, false
		}
	}

	// 2. Exact match check
	if cat, ok := e.exactDomains[clean]; ok {
		return cat, true
	}

	// 3. Wildcard suffix check
	for suffix, cat := range e.wildcardSuffixes {
		if clean == suffix || strings.HasSuffix(clean, "."+suffix) {
			return cat, true
		}
	}

	return 0, false
}

func (e *DnsBlocklistEngine) IsIPBlocked(ip net.IP) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if ip == nil {
		return false
	}
	return e.blockedIPs[ip.String()]
}
