package proxyconfig

import (
	"fmt"
	"strings"
)

type SingboxRule struct {
	Type     string
	Value    string
	Outbound string
}

type SingboxCompiler struct {
	rules []SingboxRule
}

func NewSingboxCompiler() *SingboxCompiler {
	return &SingboxCompiler{rules: make([]SingboxRule, 0)}
}

func (s *SingboxCompiler) AddRule(ruleType, value, outbound string) {
	s.rules = append(s.rules, SingboxRule{
		Type:     ruleType,
		Value:    value,
		Outbound: outbound,
	})
}

func (s *SingboxCompiler) MatchDomain(domain string) (string, bool) {
	lower := strings.ToLower(strings.TrimSpace(domain))
	for _, r := range s.rules {
		if r.Type == "domain_suffix" {
			if lower == r.Value || strings.HasSuffix(lower, "."+r.Value) {
				return r.Outbound, true
			}
		} else if r.Type == "domain" {
			if lower == r.Value {
				return r.Outbound, true
			}
		} else if r.Type == "geosite" {
			if r.Value == "cn" && (strings.HasSuffix(lower, ".cn") || strings.Contains(lower, "baidu")) {
				return r.Outbound, true
			}
		}
	}
	return "", false
}

func (s *SingboxCompiler) ExportJSON() string {
	var sb strings.Builder
	sb.WriteString("{\n  \"version\": 1,\n  \"rules\": [\n")
	for i, r := range s.rules {
		comma := ""
		if i+1 < len(s.rules) {
			comma = ","
		}
		sb.WriteString(fmt.Sprintf("    {\"%s\": [\"%s\"], \"outbound\": \"%s\"}%s\n", r.Type, r.Value, r.Outbound, comma))
	}
	sb.WriteString("  ]\n}\n")
	return sb.String()
}
