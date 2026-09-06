// Package sub manages subscription parsing and fetching.
package sub

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// SingBoxRulesList compiles Clash/Mihomo-format routing rules into Sing-Box rule-set format.
type SingBoxRulesList struct {
	// rules holds parsed rule entries keyed by outbound tag
	rules map[string][]SingBoxRule
}

// SingBoxRuleType is the type of a Sing-Box rule entry.
type SingBoxRuleType string

const (
	SingBoxRuleDomain        SingBoxRuleType = "domain"
	SingBoxRuleDomainSuffix  SingBoxRuleType = "domain_suffix"
	SingBoxRuleDomainKeyword SingBoxRuleType = "domain_keyword"
	SingBoxRuleIPCIDR        SingBoxRuleType = "ip_cidr"
	SingBoxRuleGeoIP         SingBoxRuleType = "geoip"
	SingBoxRuleGeoSite       SingBoxRuleType = "geosite"
	SingBoxRuleProcessName   SingBoxRuleType = "process_name"
)

// SingBoxRule represents a single compiled routing rule.
type SingBoxRule struct {
	Type     SingBoxRuleType
	Value    string
	Outbound string
}

func NewSingBoxRulesList() *SingBoxRulesList {
	return &SingBoxRulesList{
		rules: make(map[string][]SingBoxRule),
	}
}

// ParseClash reads Clash/Mihomo YAML-style rule lines and translates them to Sing-Box rules.
// Input format per line: RULE-TYPE,value,outbound[,no-resolve]
//
//	e.g. DOMAIN-SUFFIX,google.com,proxy
//	     IP-CIDR,192.168.0.0/16,direct
//	     GEOIP,CN,direct
//	     GEOSITE,category-ads,reject
func (s *SingBoxRulesList) ParseClash(r io.Reader) error {
	s.rules = make(map[string][]SingBoxRule)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) < 3 {
			continue
		}
		ruleType := strings.ToUpper(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])
		outbound := strings.ToLower(strings.TrimSpace(parts[2]))

		var t SingBoxRuleType
		switch ruleType {
		case "DOMAIN":
			t = SingBoxRuleDomain
		case "DOMAIN-SUFFIX":
			t = SingBoxRuleDomainSuffix
		case "DOMAIN-KEYWORD":
			t = SingBoxRuleDomainKeyword
		case "IP-CIDR", "IP-CIDR6":
			t = SingBoxRuleIPCIDR
		case "GEOIP":
			t = SingBoxRuleGeoIP
		case "GEOSITE":
			t = SingBoxRuleGeoSite
		case "PROCESS-NAME":
			t = SingBoxRuleProcessName
		default:
			continue // skip MATCH, FINAL, unknown
		}
		s.rules[outbound] = append(s.rules[outbound], SingBoxRule{
			Type:     t,
			Value:    value,
			Outbound: outbound,
		})
	}
	return scanner.Err()
}

// Rules returns all parsed rules for a given outbound tag.
func (s *SingBoxRulesList) Rules(outbound string) []SingBoxRule {
	return s.rules[strings.ToLower(outbound)]
}

// AllOutbounds returns all outbound tags present in the rule list.
func (s *SingBoxRulesList) AllOutbounds() []string {
	tags := make([]string, 0, len(s.rules))
	for k := range s.rules {
		tags = append(tags, k)
	}
	return tags
}

// ToSingBoxJSON emits a Sing-Box rule-set JSON fragment for the given outbound.
func (s *SingBoxRulesList) ToSingBoxJSON(outbound string) (string, error) {
	rules := s.rules[strings.ToLower(outbound)]
	if len(rules) == 0 {
		return "", fmt.Errorf("SingBoxRulesList.ToSingBoxJSON: no rules for outbound %q", outbound)
	}

	byType := make(map[SingBoxRuleType][]string)
	for _, r := range rules {
		byType[r.Type] = append(byType[r.Type], r.Value)
	}

	var sb strings.Builder
	sb.WriteString("{\n  \"type\": \"logical\",\n  \"mode\": \"or\",\n  \"rules\": [\n")
	first := true
	for t, vals := range byType {
		if !first {
			sb.WriteString(",\n")
		}
		first = false
		quoted := make([]string, len(vals))
		for i, v := range vals {
			quoted[i] = fmt.Sprintf("%q", v)
		}
		sb.WriteString(fmt.Sprintf("    {%q: [%s]}", string(t), strings.Join(quoted, ", ")))
	}
	sb.WriteString("\n  ],\n  \"outbound\": ")
	sb.WriteString(fmt.Sprintf("%q\n}", outbound))
	return sb.String(), nil
}
