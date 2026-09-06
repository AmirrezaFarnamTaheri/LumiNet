// Package proxy — SOCKS5/HTTP proxy rule AST and engine adapter.
//
// Addresses SC-02: Proxy AST + Engine Adapter.
//
// Rules are expressed as a small DSL parsed into an AST. The evaluator
// matches each outbound connection against the ordered rule list and
// returns the first matching Action. This allows proxy-chain decisions
// (direct, block, specific proxy) to be expressed independently of the
// underlying transport.
//
// Grammar (informal):
//
//	rule      = matcher+ action
//	matcher   = domain-glob | ip-cidr | port-range | tag-expr
//	action    = "direct" | "block" | "proxy" proxy-tag
package proxy

import (
	"fmt"
	"net"
	"path"
	"strconv"
	"strings"
)

// --- Action ----------------------------------------------------------------

// Action is what the proxy engine should do when a rule matches.
type Action int

const (
	ActionDirect Action = iota // connect without proxy
	ActionBlock                // drop the connection
	ActionProxy                // route through the named proxy tag
)

func (a Action) String() string {
	switch a {
	case ActionDirect:
		return "DIRECT"
	case ActionBlock:
		return "BLOCK"
	case ActionProxy:
		return "PROXY"
	}
	return "UNKNOWN"
}

// --- Matchers (AST nodes) --------------------------------------------------

// Matcher tests whether a given Endpoint matches a condition.
type Matcher interface {
	Match(ep Endpoint) bool
	String() string
}

// Endpoint is a resolved outbound connection target.
type Endpoint struct {
	Host string // hostname or IP
	IP   net.IP // may be nil if not yet resolved
	Port uint16
	Tags []string // application / subscription tags
}

// DomainGlobMatcher matches hostnames using shell-style glob patterns.
// Example: "*.example.com", "ads.?oogle.com"
type DomainGlobMatcher struct {
	Pattern string
}

func (m DomainGlobMatcher) Match(ep Endpoint) bool {
	ok, _ := path.Match(strings.ToLower(m.Pattern), strings.ToLower(ep.Host))
	return ok
}
func (m DomainGlobMatcher) String() string { return "domain:" + m.Pattern }

// CIDRMatcher matches when the endpoint IP falls within a CIDR block.
type CIDRMatcher struct {
	Net *net.IPNet
}

func (m CIDRMatcher) Match(ep Endpoint) bool {
	if ep.IP == nil {
		return false
	}
	return m.Net.Contains(ep.IP)
}
func (m CIDRMatcher) String() string { return "cidr:" + m.Net.String() }

// PortRangeMatcher matches a closed port range [Lo, Hi].
type PortRangeMatcher struct {
	Lo, Hi uint16
}

func (m PortRangeMatcher) Match(ep Endpoint) bool {
	return ep.Port >= m.Lo && ep.Port <= m.Hi
}
func (m PortRangeMatcher) String() string {
	if m.Lo == m.Hi {
		return "port:" + strconv.Itoa(int(m.Lo))
	}
	return fmt.Sprintf("port:%d-%d", m.Lo, m.Hi)
}

// TagMatcher matches when the endpoint carries the given application tag.
type TagMatcher struct {
	Tag string
}

func (m TagMatcher) Match(ep Endpoint) bool {
	for _, t := range ep.Tags {
		if strings.EqualFold(t, m.Tag) {
			return true
		}
	}
	return false
}
func (m TagMatcher) String() string { return "tag:" + m.Tag }

// --- Rule (AST node) -------------------------------------------------------

// Rule is an ordered list of matchers with an associated action.
// All matchers must match for the rule to fire (AND semantics).
type Rule struct {
	Matchers []Matcher
	Action   Action
	ProxyTag string // non-empty only when Action == ActionProxy
	Comment  string
}

// Evaluate returns true if all matchers in r match ep.
func (r Rule) Evaluate(ep Endpoint) bool {
	if len(r.Matchers) == 0 {
		return false
	}
	for _, m := range r.Matchers {
		if !m.Match(ep) {
			return false
		}
	}
	return true
}

// --- RuleSet ---------------------------------------------------------------

// RuleSet is an ordered collection of Rules.  The first matching rule wins.
type RuleSet struct {
	Rules []Rule
}

// Decide returns the action for the given endpoint (and the matching rule index).
// Returns ActionDirect and -1 if no rule matches (default-allow).
func (rs *RuleSet) Decide(ep Endpoint) (Action, string, int) {
	for i, r := range rs.Rules {
		if r.Evaluate(ep) {
			return r.Action, r.ProxyTag, i
		}
	}
	return ActionDirect, "", -1
}

// --- Parser ----------------------------------------------------------------

// ParseRuleSet parses a text representation of a rule set.
//
// Format (one rule per line):
//
//	[matchers...] ACTION [proxy-tag]
//
// Matchers:
//
//	domain:<glob>          matches hostname
//	cidr:<CIDR>            matches resolved IP
//	port:<N> or port:<N-M> matches port or range
//	tag:<name>             matches application tag
//
// Actions: DIRECT | BLOCK | PROXY <tag>
//
// Lines starting with # are comments.
func ParseRuleSet(text string) (*RuleSet, error) {
	rs := &RuleSet{}
	for lineNo, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		tokens := strings.Fields(line)
		if len(tokens) == 0 {
			continue
		}

		var rule Rule
		var i int
		for i = 0; i < len(tokens); i++ {
			t := tokens[i]
			upper := strings.ToUpper(t)
			if upper == "DIRECT" || upper == "BLOCK" || upper == "PROXY" {
				break
			}
			m, err := parseMatcher(t)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", lineNo+1, err)
			}
			rule.Matchers = append(rule.Matchers, m)
		}

		if i >= len(tokens) {
			return nil, fmt.Errorf("line %d: no action found", lineNo+1)
		}

		switch strings.ToUpper(tokens[i]) {
		case "DIRECT":
			rule.Action = ActionDirect
		case "BLOCK":
			rule.Action = ActionBlock
		case "PROXY":
			rule.Action = ActionProxy
			if i+1 >= len(tokens) {
				return nil, fmt.Errorf("line %d: PROXY requires a proxy-tag argument", lineNo+1)
			}
			rule.ProxyTag = tokens[i+1]
		default:
			return nil, fmt.Errorf("line %d: unknown action %q", lineNo+1, tokens[i])
		}

		rs.Rules = append(rs.Rules, rule)
	}
	return rs, nil
}

func parseMatcher(token string) (Matcher, error) {
	parts := strings.SplitN(token, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid matcher %q: expected type:value", token)
	}
	kind, value := strings.ToLower(parts[0]), parts[1]
	switch kind {
	case "domain":
		return DomainGlobMatcher{Pattern: value}, nil
	case "cidr":
		_, ipnet, err := net.ParseCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", value, err)
		}
		return CIDRMatcher{Net: ipnet}, nil
	case "port":
		if idx := strings.Index(value, "-"); idx >= 0 {
			lo, err1 := strconv.ParseUint(value[:idx], 10, 16)
			hi, err2 := strconv.ParseUint(value[idx+1:], 10, 16)
			if err1 != nil || err2 != nil || lo > hi {
				return nil, fmt.Errorf("invalid port range %q", value)
			}
			return PortRangeMatcher{Lo: uint16(lo), Hi: uint16(hi)}, nil
		}
		p, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", value, err)
		}
		return PortRangeMatcher{Lo: uint16(p), Hi: uint16(p)}, nil
	case "tag":
		return TagMatcher{Tag: value}, nil
	default:
		return nil, fmt.Errorf("unknown matcher type %q", kind)
	}
}
