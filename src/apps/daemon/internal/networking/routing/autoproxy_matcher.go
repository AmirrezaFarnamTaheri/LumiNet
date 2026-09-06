package routing

import (
	"strings"
)

type AutoProxyVerdict string

const (
	VerdictDirect AutoProxyVerdict = "DIRECT"
	VerdictProxy  AutoProxyVerdict = "PROXY"
)

type AutoProxyRuleItem struct {
	Pattern string
	IsExact bool
	IsSuffix bool
	Verdict AutoProxyVerdict
}

type AutoProxyMatcher struct {
	rules []AutoProxyRuleItem
}

func NewAutoProxyMatcher() *AutoProxyMatcher {
	return &AutoProxyMatcher{rules: make([]AutoProxyRuleItem, 0)}
}

func (m *AutoProxyMatcher) ParseLine(line string) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "!") || strings.HasPrefix(trimmed, "[") {
		return
	}

	verdict := VerdictProxy
	target := trimmed
	if strings.HasPrefix(trimmed, "@@") {
		verdict = VerdictDirect
		target = strings.TrimPrefix(trimmed, "@@")
	}

	if strings.HasPrefix(target, "||") {
		domain := strings.TrimPrefix(target, "||")
		m.rules = append(m.rules, AutoProxyRuleItem{
			Pattern:  strings.ToLower(domain),
			IsSuffix: true,
			Verdict:  verdict,
		})
	} else if strings.HasPrefix(target, "|") {
		prefix := strings.TrimPrefix(target, "|")
		m.rules = append(m.rules, AutoProxyRuleItem{
			Pattern: strings.ToLower(prefix),
			IsExact: false,
			Verdict: verdict,
		})
	} else {
		m.rules = append(m.rules, AutoProxyRuleItem{
			Pattern: strings.ToLower(target),
			Verdict: verdict,
		})
	}
}

func (m *AutoProxyMatcher) Match(urlStr string) (AutoProxyVerdict, bool) {
	lower := strings.ToLower(urlStr)
	for _, r := range m.rules {
		if r.IsSuffix {
			if strings.Contains(lower, r.Pattern) {
				return r.Verdict, true
			}
		} else {
			if strings.Contains(lower, r.Pattern) {
				return r.Verdict, true
			}
		}
	}
	return "", false
}
