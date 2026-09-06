package routing

import (
	"strings"
	"sync"
)

// DynamicMatcher owns process-local domain routing overrides. It preserves the
// historical GeoSiteMatcher behavior without coupling mutable overrides to the
// proxy runtime package.
type DynamicMatcher struct {
	mu             sync.RWMutex
	blockedDomains map[string]bool
	directDomains  map[string]bool
}

// NewDynamicMatcher creates an empty dynamic routing override matcher.
func NewDynamicMatcher() *DynamicMatcher {
	return &DynamicMatcher{
		blockedDomains: make(map[string]bool),
		directDomains:  make(map[string]bool),
	}
}

// AddBlockedDomain registers a domain for proxy tunneling enforcement.
func (m *DynamicMatcher) AddBlockedDomain(domain string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.blockedDomains[strings.ToLower(domain)] = true
}

// AddDirectDomain registers a domain for bypass / direct connection.
func (m *DynamicMatcher) AddDirectDomain(domain string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.directDomains[strings.ToLower(domain)] = true
}

// MatchDomain evaluates domain routing disposition: "proxy", "direct", or
// "default". Exact blocked rules take precedence over exact direct rules,
// followed by blocked and then direct suffix matches.
func (m *DynamicMatcher) MatchDomain(domain string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	domain = strings.ToLower(domain)
	if m.blockedDomains[domain] {
		return "proxy"
	}
	if m.directDomains[domain] {
		return "direct"
	}

	for rule := range m.blockedDomains {
		if strings.HasSuffix(domain, "."+rule) {
			return "proxy"
		}
	}
	for rule := range m.directDomains {
		if strings.HasSuffix(domain, "."+rule) {
			return "direct"
		}
	}
	return "default"
}
