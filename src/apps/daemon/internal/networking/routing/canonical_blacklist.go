package routing

import (
	"encoding/base64"
	"strings"
	"sync"
)

type MatchType int

const (
	MatchDirect MatchType = iota
	MatchBlocked
	MatchWhitelisted
)

type CanonicalBlacklistEngine struct {
	exactBlocked      map[string]bool
	domainSuffixes    map[string]bool
	whitelistExact    map[string]bool
	whitelistSuffixes map[string]bool
	keywords          []string
	totalRules        int
	mu                sync.RWMutex
}

func NewCanonicalBlacklistEngine() *CanonicalBlacklistEngine {
	return &CanonicalBlacklistEngine{
		exactBlocked:      make(map[string]bool),
		domainSuffixes:    make(map[string]bool),
		whitelistExact:    make(map[string]bool),
		whitelistSuffixes: make(map[string]bool),
	}
}

func (e *CanonicalBlacklistEngine) ParseRawRule(line string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "!") || strings.HasPrefix(trimmed, "[") {
		return
	}
	e.totalRules++

	if strings.HasPrefix(trimmed, "@@") {
		rule := strings.TrimPrefix(trimmed, "@@")
		if strings.HasPrefix(rule, "||") {
			dom := strings.TrimPrefix(rule, "||")
			dom = strings.TrimPrefix(strings.ToLower(dom), ".")
			e.whitelistSuffixes[dom] = true
		} else {
			dom := strings.TrimPrefix(rule, "|")
			dom = strings.TrimPrefix(strings.ToLower(dom), ".")
			e.whitelistExact[dom] = true
		}
		return
	}

	if strings.HasPrefix(trimmed, "||") {
		dom := strings.TrimPrefix(trimmed, "||")
		dom = strings.TrimPrefix(strings.ToLower(dom), ".")
		e.domainSuffixes[dom] = true
		return
	}

	if strings.HasPrefix(trimmed, "|") {
		dom := strings.TrimPrefix(trimmed, "|")
		dom = strings.TrimPrefix(dom, "http://")
		dom = strings.TrimPrefix(dom, "https://")
		dom = strings.TrimPrefix(strings.ToLower(dom), ".")
		e.exactBlocked[dom] = true
		return
	}

	if !strings.HasPrefix(trimmed, "/") {
		e.keywords = append(e.keywords, strings.ToLower(trimmed))
	}
}

func (e *CanonicalBlacklistEngine) LoadBase64Ruleset(b64Content string) error {
	clean := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, b64Content)

	decoded, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return err
	}

	lines := strings.Split(string(decoded), "\n")
	for _, l := range lines {
		e.ParseRawRule(l)
	}
	return nil
}

func (e *CanonicalBlacklistEngine) EvaluateTarget(host string) (MatchType, string) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	hostLower := strings.Trim(strings.ToLower(host), ". ")

	// 1. Whitelist
	if e.whitelistExact[hostLower] {
		return MatchWhitelisted, hostLower
	}
	for suf := range e.whitelistSuffixes {
		if hostLower == suf || strings.HasSuffix(hostLower, "."+suf) {
			return MatchWhitelisted, suf
		}
	}

	// 2. Exact blocked
	if e.exactBlocked[hostLower] {
		return MatchBlocked, hostLower
	}

	// 3. Domain suffix blocked
	for suf := range e.domainSuffixes {
		if hostLower == suf || strings.HasSuffix(hostLower, "."+suf) {
			return MatchBlocked, suf
		}
	}

	// 4. Keyword
	for _, kw := range e.keywords {
		if strings.Contains(hostLower, kw) {
			return MatchBlocked, kw
		}
	}

	return MatchDirect, ""
}
