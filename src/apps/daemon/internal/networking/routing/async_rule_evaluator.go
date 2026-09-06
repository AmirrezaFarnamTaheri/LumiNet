package routing

import (
	"net"
	"sort"
	"strings"
	"sync"
)

// MatchRuleType defines classification criteria
type MatchRuleType int

const (
	AsyncRuleDomain MatchRuleType = iota
	AsyncRuleDomainSuffix
	AsyncRuleDomainKeyword
	AsyncRuleIPCIDR
	AsyncRulePortRange
	AsyncRuleProcessName
	AsyncRuleMatch
)

// RoutingRuleRecord holds single rule specification
type RoutingRuleRecord struct {
	Type           MatchRuleType
	Value          string
	IPNet          *net.IPNet
	PortStart      uint16
	PortEnd        uint16
	TargetOutbound string
	Priority       uint32
}

// RouteTrafficContext provides evaluation parameters
type RouteTrafficContext struct {
	Domain      string
	DestIP      net.IP
	DestPort    uint16
	ProcessName string
}

// AsyncRuleEvaluator evaluates multi-condition traffic routing rules
type AsyncRuleEvaluator struct {
	mu              sync.RWMutex
	Rules           []*RoutingRuleRecord
	DefaultOutbound string
}

// NewAsyncRuleEvaluator creates an evaluator instance
func NewAsyncRuleEvaluator(defaultOutbound string) *AsyncRuleEvaluator {
	return &AsyncRuleEvaluator{
		DefaultOutbound: defaultOutbound,
	}
}

// AddRule adds an evaluation rule
func (e *AsyncRuleEvaluator) AddRule(rule *RoutingRuleRecord) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.Rules = append(e.Rules, rule)
	sort.Slice(e.Rules, func(i, j int) bool {
		return e.Rules[i].Priority > e.Rules[j].Priority
	})
}

// Evaluate finds first matching rule or returns default
func (e *AsyncRuleEvaluator) Evaluate(ctx *RouteTrafficContext) string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, r := range e.Rules {
		if e.matches(r, ctx) {
			return r.TargetOutbound
		}
	}
	return e.DefaultOutbound
}

func (e *AsyncRuleEvaluator) matches(r *RoutingRuleRecord, ctx *RouteTrafficContext) bool {
	switch r.Type {
	case AsyncRuleDomain:
		return strings.EqualFold(ctx.Domain, r.Value)

	case AsyncRuleDomainSuffix:
		if ctx.Domain == "" {
			return false
		}
		target := strings.ToLower(r.Value)
		d := strings.ToLower(ctx.Domain)
		return d == target || strings.HasSuffix(d, "."+target)

	case AsyncRuleDomainKeyword:
		if ctx.Domain == "" {
			return false
		}
		return strings.Contains(strings.ToLower(ctx.Domain), strings.ToLower(r.Value))

	case AsyncRuleIPCIDR:
		if ctx.DestIP == nil || r.IPNet == nil {
			return false
		}
		return r.IPNet.Contains(ctx.DestIP)

	case AsyncRulePortRange:
		return ctx.DestPort >= r.PortStart && ctx.DestPort <= r.PortEnd

	case AsyncRuleProcessName:
		return strings.EqualFold(ctx.ProcessName, r.Value)

	case AsyncRuleMatch:
		return true

	default:
		return false
	}
}
