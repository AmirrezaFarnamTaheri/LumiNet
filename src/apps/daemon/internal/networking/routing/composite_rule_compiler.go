package routing

import (
	"net"
	"strings"
	"sync"
)

type RuleAction string

const (
	RuleActionDirect RuleAction = "DIRECT"
	RuleActionProxy  RuleAction = "PROXY"
	RuleActionReject RuleAction = "REJECT"
)

type RuleCriterionType string

const (
	CriterionDomain        RuleCriterionType = "DOMAIN"
	CriterionDomainSuffix  RuleCriterionType = "DOMAIN-SUFFIX"
	CriterionDomainKeyword RuleCriterionType = "DOMAIN-KEYWORD"
	CriterionIpCidr        RuleCriterionType = "IP-CIDR"
	CriterionUserAgent     RuleCriterionType = "USER-AGENT"
)

type RuleCriterion struct {
	Type      RuleCriterionType
	Pattern   string
	IpNet     *net.IPNet
}

type CompiledRule struct {
	Criterion RuleCriterion
	Action    RuleAction
}

type CompositeRuleCompiler struct {
	mu    sync.RWMutex
	rules []CompiledRule
}

func NewCompositeRuleCompiler() *CompositeRuleCompiler {
	return &CompositeRuleCompiler{
		rules: make([]CompiledRule, 0),
	}
}

func (c *CompositeRuleCompiler) ParseLine(line string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
		return false
	}

	parts := strings.Split(trimmed, ",")
	if len(parts) < 3 {
		return false
	}

	rType := strings.ToUpper(strings.TrimSpace(parts[0]))
	pattern := strings.TrimSpace(parts[1])
	actionStr := strings.ToUpper(strings.TrimSpace(parts[2]))

	var action RuleAction
	switch actionStr {
	case "DIRECT":
		action = RuleActionDirect
	case "PROXY":
		action = RuleActionProxy
	case "REJECT":
		action = RuleActionReject
	default:
		return false
	}

	var crit RuleCriterion
	switch rType {
	case "DOMAIN":
		crit = RuleCriterion{Type: CriterionDomain, Pattern: strings.ToLower(pattern)}
	case "DOMAIN-SUFFIX":
		crit = RuleCriterion{Type: CriterionDomainSuffix, Pattern: strings.ToLower(pattern)}
	case "DOMAIN-KEYWORD":
		crit = RuleCriterion{Type: CriterionDomainKeyword, Pattern: strings.ToLower(pattern)}
	case "IP-CIDR":
		cidrStr := pattern
		if !strings.Contains(cidrStr, "/") {
			cidrStr += "/32"
		}
		_, ipNet, err := net.ParseCIDR(cidrStr)
		if err != nil {
			return false
		}
		crit = RuleCriterion{Type: CriterionIpCidr, Pattern: pattern, IpNet: ipNet}
	case "USER-AGENT":
		crit = RuleCriterion{Type: CriterionUserAgent, Pattern: pattern}
	default:
		return false
	}

	c.rules = append(c.rules, CompiledRule{Criterion: crit, Action: action})
	return true
}

func (c *CompositeRuleCompiler) EvaluateDomain(domain string) (RuleAction, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	clean := strings.ToLower(strings.TrimSpace(domain))
	for _, r := range c.rules {
		switch r.Criterion.Type {
		case CriterionDomain:
			if clean == r.Criterion.Pattern {
				return r.Action, true
			}
		case CriterionDomainSuffix:
			if clean == r.Criterion.Pattern || strings.HasSuffix(clean, "."+r.Criterion.Pattern) {
				return r.Action, true
			}
		case CriterionDomainKeyword:
			if strings.Contains(clean, r.Criterion.Pattern) {
				return r.Action, true
			}
		}
	}
	return "", false
}

func (c *CompositeRuleCompiler) EvaluateIP(ip net.IP) (RuleAction, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, r := range c.rules {
		if r.Criterion.Type == CriterionIpCidr && r.Criterion.IpNet != nil {
			if r.Criterion.IpNet.Contains(ip) {
				return r.Action, true
			}
		}
	}
	return "", false
}

func (c *CompositeRuleCompiler) RuleCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.rules)
}
