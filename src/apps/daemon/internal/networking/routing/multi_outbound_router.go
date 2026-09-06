package routing

import (
	"strings"
	"sync"
)

type OutboundPolicyType string

const (
	PolicyDirect OutboundPolicyType = "DIRECT"
	PolicyProxy  OutboundPolicyType = "PROXY"
	PolicyReject OutboundPolicyType = "REJECT"
)

type OutboundPolicy struct {
	Type OutboundPolicyType
	Tag  string
}

type OutboundRouteRule struct {
	Pattern  string
	IsSuffix bool
	Policy   OutboundPolicy
}

type MultiOutboundRouter struct {
	mu             sync.RWMutex
	rules          []OutboundRouteRule
	defaultPolicy  OutboundPolicy
	outboundWeights map[string]uint32
	rrCounter      int
}

func NewMultiOutboundRouter(defaultPolicy OutboundPolicy) *MultiOutboundRouter {
	return &MultiOutboundRouter{
		rules:          make([]OutboundRouteRule, 0),
		defaultPolicy:  defaultPolicy,
		outboundWeights: make(map[string]uint32),
		rrCounter:      0,
	}
}

func (r *MultiOutboundRouter) AddRule(pattern string, isSuffix bool, policy OutboundPolicy) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rules = append(r.rules, OutboundRouteRule{
		Pattern:  strings.ToLower(strings.TrimSpace(pattern)),
		IsSuffix: isSuffix,
		Policy:   policy,
	})
}

func (r *MultiOutboundRouter) RegisterOutbound(tag string, weight uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if weight < 1 {
		weight = 1
	}
	r.outboundWeights[tag] = weight
}

func (r *MultiOutboundRouter) MatchTarget(host string) OutboundPolicy {
	r.mu.RLock()
	defer r.mu.RUnlock()
	clean := strings.ToLower(strings.TrimSpace(host))
	for _, rule := range r.rules {
		if rule.IsSuffix {
			if clean == rule.Pattern || strings.HasSuffix(clean, "."+rule.Pattern) {
				return rule.Policy
			}
		} else if clean == rule.Pattern {
			return rule.Policy
		}
	}
	return r.defaultPolicy
}

func (r *MultiOutboundRouter) SelectBalancedOutbound(outbounds []string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(outbounds) == 0 {
		return "", false
	}
	chosen := outbounds[r.rrCounter%len(outbounds)]
	r.rrCounter++
	return chosen, true
}
