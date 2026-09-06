// Package domainrouting provides domain-based routing rules for LumiNet.
//
// Categories are organized for split tunneling:
//   - cn: Direct connection (China-accessible domains)
//   - anticensorship: Proxy through LumiNet
//   - vpnservices: Proxy through LumiNet
//   - doh: DNS-over-HTTPS servers
//   - ads: Block/ad-filter
//   - media: Proxy for uncensored media
package routing

import (
	"bufio"
	"embed"
	"errors"
	"io/fs"
	"regexp"
	"strings"
)

//go:embed domain_data/*.txt
var domainData embed.FS

// RouteAction determines how to route traffic for a domain.
type RouteAction int

const (
	RouteDirect RouteAction = iota // Direct connection
	RouteProxy                     // Proxy through LumiNet
	RouteBlock                     // Block/ad-filter
	RouteDNS                       // DNS-over-HTTPS routing
)

// DomainList represents a named list of domain rules.
type DomainList struct {
	Name    string
	Domains []DomainRule
}

// DomainRule represents a single domain routing rule.
type DomainRule struct {
	Pattern string // Domain pattern (e.g., "google.com", "full:www.google.com", "keyword:ads")
	Type    RuleType
	Action  RouteAction
}

// RuleType determines how the pattern matches.
type RuleType int

const (
	RuleDomain  RuleType = iota // Match domain and subdomains
	RuleFull                    // Exact match
	RuleKeyword                 // Contains keyword
	RuleRegexp                  // Regex match
)

// Router provides domain-based routing decisions.
type Router struct {
	rules map[string][]DomainRule
}

// NewRouter creates a new domain router from embedded data.
func NewRouter() (*Router, error) {
	r := &Router{
		rules: make(map[string][]DomainRule),
	}

	// Load key categories
	categories := map[string]RouteAction{
		"geolocation-cn":          RouteDirect,
		"geolocation-!cn":         RouteProxy,
		"category-anticensorship": RouteProxy,
		"category-vpnservices":    RouteProxy,
		"category-service-access": RouteProxy,
		"category-ads":            RouteBlock,
		"category-ads-all":        RouteBlock,
		"category-doh":            RouteDNS,
		"category-media":          RouteProxy,
		"private":                 RouteDirect,
	}

	for cat, action := range categories {
		rules, err := loadCategory(cat, action)
		if err != nil {
			continue // Skip missing categories
		}
		r.rules[cat] = rules
	}

	return r, nil
}

// Lookup determines the routing action for a domain.
func (r *Router) Lookup(domain string) (RouteAction, string) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	// Check proxy categories first (anticensorship, vpnservices)
	for _, cat := range []string{"category-service-access", "category-anticensorship", "category-vpnservices", "category-media"} {
		if rules, ok := r.rules[cat]; ok {
			for _, rule := range rules {
				if matchDomain(domain, rule) {
					return RouteProxy, cat
				}
			}
		}
	}

	// Check ad-blocking
	for _, cat := range []string{"category-ads", "category-ads-all"} {
		if rules, ok := r.rules[cat]; ok {
			for _, rule := range rules {
				if matchDomain(domain, rule) {
					return RouteBlock, cat
				}
			}
		}
	}

	// Check DoH servers
	if rules, ok := r.rules["category-doh"]; ok {
		for _, rule := range rules {
			if matchDomain(domain, rule) {
				return RouteDNS, "category-doh"
			}
		}
	}

	// Check CN domains (direct)
	if rules, ok := r.rules["geolocation-cn"]; ok {
		for _, rule := range rules {
			if matchDomain(domain, rule) {
				return RouteDirect, "geolocation-cn"
			}
		}
	}

	// Check non-CN domains (proxy)
	if rules, ok := r.rules["geolocation-!cn"]; ok {
		for _, rule := range rules {
			if matchDomain(domain, rule) {
				return RouteProxy, "geolocation-!cn"
			}
		}
	}

	// Check private domains (direct)
	if rules, ok := r.rules["private"]; ok {
		for _, rule := range rules {
			if matchDomain(domain, rule) {
				return RouteDirect, "private"
			}
		}
	}

	// Default: proxy (unknown domains go through LumiNet)
	return RouteProxy, "default"
}

// ListCategories returns all loaded category names.
func (r *Router) ListCategories() []string {
	cats := make([]string, 0, len(r.rules))
	for cat := range r.rules {
		cats = append(cats, cat)
	}
	return cats
}

// CategoryCount returns the number of rules in a category.
func (r *Router) CategoryCount(cat string) int {
	return len(r.rules[cat])
}

func matchDomain(domain string, rule DomainRule) bool {
	switch rule.Type {
	case RuleFull:
		return domain == rule.Pattern
	case RuleDomain:
		return domain == rule.Pattern || strings.HasSuffix(domain, "."+rule.Pattern)
	case RuleKeyword:
		return strings.Contains(domain, rule.Pattern)
	case RuleRegexp:
		matcher, err := regexp.Compile(rule.Pattern)
		return err == nil && matcher.MatchString(domain)
	default:
		return false
	}
}

func loadCategory(category string, action RouteAction) ([]DomainRule, error) {
	return loadCategoryFromFS(domainData, category, action)
}

func loadCategoryFromFS(fsys fs.FS, category string, action RouteAction) ([]DomainRule, error) {
	var rules []DomainRule
	active := make(map[string]bool)
	seen := make(map[string]struct{})

	var visit func(string, bool) error
	visit = func(name string, required bool) error {
		name = normalizeCategoryName(name)
		if name == "" || active[name] {
			return nil
		}
		data, err := readCategoryFile(fsys, name)
		if err != nil {
			if !required && errors.Is(err, fs.ErrNotExist) {
				// The embedded corpus is intentionally a curated subset of the
				// upstream domain-list repository. Missing external include
				// targets are therefore non-fatal.
				return nil
			}
			return err
		}

		active[name] = true
		defer delete(active, name)

		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			line = stripDomainListAttributes(line)
			if strings.HasPrefix(line, "include:") {
				if err := visit(strings.TrimPrefix(line, "include:"), false); err != nil {
					return err
				}
				continue
			}

			rule := parseRule(line, action)
			if rule == nil {
				continue
			}
			key := string(rune(rule.Type)) + "\x00" + rule.Pattern
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			rules = append(rules, *rule)
		}
		return scanner.Err()
	}

	if err := visit(category, true); err != nil {
		return nil, err
	}
	return rules, nil
}

func readCategoryFile(fsys fs.FS, name string) ([]byte, error) {
	paths := []string{name + ".txt", "domain_data/" + name + ".txt"}
	var lastErr error
	for _, path := range paths {
		data, err := fs.ReadFile(fsys, path)
		if err == nil {
			return data, nil
		}
		lastErr = err
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}
	return nil, lastErr
}

func normalizeCategoryName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, ".txt")
	return name
}

func stripDomainListAttributes(line string) string {
	line = strings.TrimSpace(line)
	if idx := strings.Index(line, " @"); idx >= 0 {
		line = strings.TrimSpace(line[:idx])
	}
	return line
}

func parseRule(line string, action RouteAction) *DomainRule {
	line = stripDomainListAttributes(line)
	// Handle include: directives
	if strings.HasPrefix(line, "include:") {
		// For now, skip includes (would need recursive loading)
		return nil
	}

	// Handle full: prefix (exact match)
	if strings.HasPrefix(line, "full:") {
		return &DomainRule{
			Pattern: strings.TrimPrefix(line, "full:"),
			Type:    RuleFull,
			Action:  action,
		}
	}

	// Handle keyword: prefix
	if strings.HasPrefix(line, "keyword:") {
		return &DomainRule{
			Pattern: strings.TrimPrefix(line, "keyword:"),
			Type:    RuleKeyword,
			Action:  action,
		}
	}

	// Handle regexp: prefix
	if strings.HasPrefix(line, "regexp:") {
		return &DomainRule{
			Pattern: strings.TrimPrefix(line, "regexp:"),
			Type:    RuleRegexp,
			Action:  action,
		}
	}

	// Default: domain match (includes subdomains)
	return &DomainRule{
		Pattern: line,
		Type:    RuleDomain,
		Action:  action,
	}
}
