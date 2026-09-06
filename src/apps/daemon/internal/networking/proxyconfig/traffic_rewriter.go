package proxyconfig

import (
	"strings"
	"sync"
)

type RewriteActionType int

const (
	ActionRedirectUrl RewriteActionType = iota
	ActionSetHeader
	ActionRemoveHeader
	ActionReplaceBody
)

type RewriteRule struct {
	RuleID        string
	DomainPattern string
	PathPrefix    string
	IsActive      bool
	ActionType    RewriteActionType
	NewURL        string
	HeaderName    string
	HeaderValue   string
	BodyPattern   string
	BodyReplace   string
}

type MitmTrafficRewriter struct {
	rules          []*RewriteRule
	totalMutations uint64
	mu             sync.RWMutex
}

func NewMitmTrafficRewriter() *MitmTrafficRewriter {
	return &MitmTrafficRewriter{}
}

func (r *MitmTrafficRewriter) AddRule(rule *RewriteRule) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rules = append(r.rules, rule)
}

func (r *MitmTrafficRewriter) MatchRule(domain, path string) *RewriteRule {
	r.mu.RLock()
	defer r.mu.RUnlock()

	domainLower := strings.ToLower(domain)
	for _, rule := range r.rules {
		if !rule.IsActive {
			continue
		}

		domainMatch := false
		if rule.DomainPattern == "*" {
			domainMatch = true
		} else if strings.HasPrefix(rule.DomainPattern, "*.") {
			suffix := strings.TrimPrefix(rule.DomainPattern, "*.")
			domainMatch = strings.HasSuffix(domainLower, suffix)
		} else {
			domainMatch = domainLower == strings.ToLower(rule.DomainPattern)
		}

		if domainMatch && strings.HasPrefix(path, rule.PathPrefix) {
			return rule
		}
	}
	return nil
}

func (r *MitmTrafficRewriter) RewriteRequest(domain string, path *string, headers map[string]string) *RewriteRule {
	rule := r.MatchRule(domain, *path)
	if rule == nil {
		return nil
	}

	r.mu.Lock()
	r.totalMutations++
	r.mu.Unlock()

	switch rule.ActionType {
	case ActionRedirectUrl:
		*path = rule.NewURL
	case ActionSetHeader:
		headers[rule.HeaderName] = rule.HeaderValue
	case ActionRemoveHeader:
		delete(headers, rule.HeaderName)
	}
	return rule
}

func (r *MitmTrafficRewriter) RewriteResponseBody(domain, path string, body []byte) []byte {
	rule := r.MatchRule(domain, path)
	if rule == nil || rule.ActionType != ActionReplaceBody {
		return body
	}

	bodyStr := string(body)
	if strings.Contains(bodyStr, rule.BodyPattern) {
		r.mu.Lock()
		r.totalMutations++
		r.mu.Unlock()
		return []byte(strings.ReplaceAll(bodyStr, rule.BodyPattern, rule.BodyReplace))
	}
	return body
}
