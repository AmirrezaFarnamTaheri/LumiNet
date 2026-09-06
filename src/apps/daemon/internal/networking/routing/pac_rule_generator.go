package routing

import (
	"fmt"
	"strings"
)

type PacRuleAction string

const (
	PacRuleActionDirect PacRuleAction = "DIRECT"
	PacRuleActionProxy  PacRuleAction = "PROXY"
)

type PacRuleEntry struct {
	Pattern       string
	IsExact       bool
	IsSuffix      bool
	Action        PacRuleAction
	ProxyEndpoint string
}

type PacRuleGenerator struct {
	rules         []PacRuleEntry
	defaultAction PacRuleAction
	defaultProxy  string
}

func NewPacRuleGenerator(defaultAction PacRuleAction, defaultProxy string) *PacRuleGenerator {
	return &PacRuleGenerator{
		rules:         make([]PacRuleEntry, 0),
		defaultAction: defaultAction,
		defaultProxy:  defaultProxy,
	}
}

func (p *PacRuleGenerator) AddRule(pattern string, action PacRuleAction, proxyEndpoint string) {
	trimmed := strings.ToLower(strings.TrimSpace(pattern))
	isExact := false
	isSuffix := false
	pat := trimmed

	if strings.HasPrefix(trimmed, "||") {
		isSuffix = true
		pat = strings.TrimPrefix(trimmed, "||")
	} else if strings.HasPrefix(trimmed, "|") {
		isExact = true
		pat = strings.TrimPrefix(trimmed, "|")
	}

	p.rules = append(p.rules, PacRuleEntry{
		Pattern:       pat,
		IsExact:       isExact,
		IsSuffix:      isSuffix,
		Action:        action,
		ProxyEndpoint: proxyEndpoint,
	})
}

func (p *PacRuleGenerator) EvaluateHost(host string) (PacRuleAction, string) {
	hostLower := strings.ToLower(host)
	for _, rule := range p.rules {
		if rule.IsExact {
			if hostLower == rule.Pattern {
				return rule.Action, rule.ProxyEndpoint
			}
		} else if rule.IsSuffix {
			if hostLower == rule.Pattern || strings.HasSuffix(hostLower, "."+rule.Pattern) {
				return rule.Action, rule.ProxyEndpoint
			}
		} else if strings.Contains(hostLower, rule.Pattern) {
			return rule.Action, rule.ProxyEndpoint
		}
	}
	return p.defaultAction, p.defaultProxy
}

func (p *PacRuleGenerator) GeneratePacScript() string {
	var rulesJs []string
	for _, r := range p.rules {
		if r.Action == PacRuleActionProxy {
			rulesJs = append(rulesJs, fmt.Sprintf("  \"%s\": \"PROXY %s\",", r.Pattern, r.ProxyEndpoint))
		}
	}

	defRet := "\"DIRECT\""
	if p.defaultAction == PacRuleActionProxy {
		defRet = fmt.Sprintf("\"PROXY %s\"", p.defaultProxy)
	}

	return fmt.Sprintf(`// LumiNet Generated PAC
var rules = {
%s
};

function FindProxyForURL(url, host) {
    for (var d in rules) {
        if (dnsDomainIs(host, d) || host === d) {
            return rules[d];
        }
    }
    return %s;
}
`, strings.Join(rulesJs, "\n"), defRet)
}

func (p *PacRuleGenerator) GenerateDnsmasqConfig(dnsServer string) string {
	var lines []string
	for _, r := range p.rules {
		lines = append(lines, fmt.Sprintf("server=/%s/%s", r.Pattern, dnsServer))
	}
	return strings.Join(lines, "\n")
}
