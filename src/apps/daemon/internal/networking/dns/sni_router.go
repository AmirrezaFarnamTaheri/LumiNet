package dns

import (
	"strings"
	"sync"
)

// SNIRoutingTable maps domain patterns to dedicated target IP addresses.
type SNIRoutingTable struct {
	mu        sync.RWMutex
	exact     map[string]string
	wildcards map[string]string
	contains  map[string]string
}

// NewSNIRoutingTable instantiates an empty routing table.
func NewSNIRoutingTable() *SNIRoutingTable {
	return &SNIRoutingTable{
		exact:     make(map[string]string),
		wildcards: make(map[string]string),
		contains:  make(map[string]string),
	}
}

// AddExactRoute registers a strict 1-to-1 hostname match.
func (t *SNIRoutingTable) AddExactRoute(domain, targetIP string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.exact[strings.ToLower(strings.TrimSuffix(domain, "."))] = targetIP
}

// AddWildcardRoute registers a suffix domain match (e.g., "*.youtube.com" or ".youtube.com").
func (t *SNIRoutingTable) AddWildcardRoute(suffix, targetIP string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	clean := strings.ToLower(suffix)
	clean = strings.TrimPrefix(clean, "*")
	clean = strings.TrimPrefix(clean, ".")
	clean = strings.TrimSuffix(clean, ".")
	t.wildcards[clean] = targetIP
}

// AddSubstringRoute registers a substring match rule.
func (t *SNIRoutingTable) AddSubstringRoute(substr, targetIP string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.contains[strings.ToLower(substr)] = targetIP
}

// ResolveRoute evaluates the domain against exact, wildcard, and substring rules in order.
// Returns the matched IP and true if a rule applies.
func (t *SNIRoutingTable) ResolveRoute(domain string) (string, bool) {
	clean := strings.ToLower(strings.TrimSuffix(domain, "."))

	t.mu.RLock()
	defer t.mu.RUnlock()

	// 1. Exact match
	if ip, ok := t.exact[clean]; ok {
		return ip, true
	}

	// 2. Wildcard / Suffix match
	for suffix, ip := range t.wildcards {
		if clean == suffix || strings.HasSuffix(clean, "."+suffix) {
			return ip, true
		}
	}

	// 3. Substring match
	for substr, ip := range t.contains {
		if strings.Contains(clean, substr) {
			return ip, true
		}
	}

	return "", false
}

// Count returns the total rules registered across all match modes.
func (t *SNIRoutingTable) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.exact) + len(t.wildcards) + len(t.contains)
}
