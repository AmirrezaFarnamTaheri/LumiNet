package diagnostics

import (
	"bufio"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

const (
	maxLocalRuleSetBytes = 512 << 10
	maxLocalRuleSetLines = 4096
)

type LocalRuleSetPlanRequest struct {
	Format  string `json:"format,omitempty"`
	Content string `json:"content"`
}

type LocalRuleEvidence struct {
	Action     string   `json:"action"`
	Kind       string   `json:"kind"`
	Value      string   `json:"value"`
	SourceLine int      `json:"source_line"`
	Options    []string `json:"options,omitempty"`
}

type LocalRuleSetPlan struct {
	Format         string              `json:"format"`
	Rules          []LocalRuleEvidence `json:"rules"`
	DuplicateCount int                 `json:"duplicate_count"`
	IgnoredCount   int                 `json:"ignored_count"`
	Fetches        bool                `json:"fetches"`
	Installs       bool                `json:"installs"`
	Invariants     []string            `json:"invariants"`
}

func BuildLocalRuleSetPlan(req LocalRuleSetPlanRequest) (LocalRuleSetPlan, error) {
	if len(req.Content) == 0 || len(req.Content) > maxLocalRuleSetBytes {
		return LocalRuleSetPlan{}, fmt.Errorf("rule-set content must be between 1 and %d bytes", maxLocalRuleSetBytes)
	}
	format := strings.ToLower(strings.TrimSpace(req.Format))
	if format == "" {
		format = "auto"
	}
	supported := map[string]bool{"auto": true, "adguard": true, "hosts": true, "clash": true, "surge": true, "luminet": true}
	if !supported[format] {
		return LocalRuleSetPlan{}, fmt.Errorf("unsupported local rule-set format %q", format)
	}
	plan := LocalRuleSetPlan{Format: format}
	seen := map[string]struct{}{}
	scanner := bufio.NewScanner(strings.NewReader(req.Content))
	scanner.Buffer(make([]byte, 4096), 64<<10)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		if lineNo > maxLocalRuleSetLines {
			return LocalRuleSetPlan{}, fmt.Errorf("rule-set exceeds %d lines", maxLocalRuleSetLines)
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") || strings.HasPrefix(line, ";") {
			plan.IgnoredCount++
			continue
		}
		rule, detected, err := parseLocalRuleLine(format, line, lineNo)
		if err != nil {
			return LocalRuleSetPlan{}, err
		}
		if plan.Format == "auto" && detected != "" {
			// Keep auto as the declared format; per-line detection may legitimately
			// mix common local corpora.
		}
		key := rule.Action + "\x00" + rule.Kind + "\x00" + rule.Value
		if _, ok := seen[key]; ok {
			plan.DuplicateCount++
			continue
		}
		seen[key] = struct{}{}
		plan.Rules = append(plan.Rules, rule)
	}
	if err := scanner.Err(); err != nil {
		return LocalRuleSetPlan{}, fmt.Errorf("read rule-set: %w", err)
	}
	if len(plan.Rules) == 0 {
		return LocalRuleSetPlan{}, fmt.Errorf("rule-set contains no admissible local rules")
	}
	plan.Invariants = []string{
		"normalization is local and deterministic; URLs are never fetched",
		"CIDRs are masked to canonical network prefixes before deduplication",
		"extended Clash/Surge rules preserve only bounded non-executable match evidence and known no-resolve metadata",
		"GEOIP and RULE-SET entries remain symbolic local references; the planner resolves or fetches neither",
		"ambiguous or unsupported executable syntax is rejected rather than guessed",
		"the plan does not install, activate, or execute any converted rule",
	}
	return plan, nil
}

func parseLocalRuleLine(format, line string, lineNo int) (LocalRuleEvidence, string, error) {
	if format == "auto" || format == "adguard" {
		if strings.HasPrefix(line, "@@||") && strings.HasSuffix(line, "^") {
			return canonicalDomainRule("allow", strings.TrimSuffix(strings.TrimPrefix(line, "@@||"), "^"), lineNo, "adguard")
		}
		if strings.HasPrefix(line, "||") && strings.HasSuffix(line, "^") {
			return canonicalDomainRule("block", strings.TrimSuffix(strings.TrimPrefix(line, "||"), "^"), lineNo, "adguard")
		}
		if format == "adguard" {
			return LocalRuleEvidence{}, "", fmt.Errorf("line %d is not supported AdGuard host syntax", lineNo)
		}
	}
	if format == "auto" || format == "hosts" {
		fields := strings.Fields(line)
		if len(fields) == 2 {
			if ip, err := netip.ParseAddr(fields[0]); err == nil {
				host, err := normalizeRuleDomain(fields[1])
				if err != nil {
					return LocalRuleEvidence{}, "", fmt.Errorf("line %d: %w", lineNo, err)
				}
				action := "map"
				if ip.IsLoopback() || ip.IsUnspecified() {
					action = "block"
				}
				return LocalRuleEvidence{Action: action, Kind: "host", Value: ip.String() + " " + host, SourceLine: lineNo}, "hosts", nil
			}
		}
		if format == "hosts" {
			return LocalRuleEvidence{}, "", fmt.Errorf("line %d is not a valid hosts entry", lineNo)
		}
	}
	if format == "auto" || format == "clash" || format == "surge" {
		parts := strings.Split(line, ",")
		if len(parts) >= 2 {
			kind := strings.ToUpper(strings.TrimSpace(parts[0]))
			if kind == "MATCH" || kind == "FINAL" {
				action := normalizeRuleAction(parts[1])
				if action == "" {
					return LocalRuleEvidence{}, "", fmt.Errorf("line %d has unsupported rule action %q", lineNo, strings.TrimSpace(parts[1]))
				}
				options, err := normalizeRuleOptions(parts[2:])
				if err != nil {
					return LocalRuleEvidence{}, "", fmt.Errorf("line %d: %w", lineNo, err)
				}
				return LocalRuleEvidence{Action: action, Kind: "match", Value: "*", SourceLine: lineNo, Options: options}, "clash", nil
			}
			if len(parts) >= 3 {
				value := strings.TrimSpace(parts[1])
				action := normalizeRuleAction(parts[2])
				if action == "" {
					return LocalRuleEvidence{}, "", fmt.Errorf("line %d has unsupported rule action %q", lineNo, strings.TrimSpace(parts[2]))
				}
				options, err := normalizeRuleOptions(parts[3:])
				if err != nil {
					return LocalRuleEvidence{}, "", fmt.Errorf("line %d: %w", lineNo, err)
				}
				switch kind {
				case "DOMAIN", "DOMAIN-SUFFIX":
					host, err := normalizeRuleDomain(value)
					if err != nil {
						return LocalRuleEvidence{}, "", fmt.Errorf("line %d: %w", lineNo, err)
					}
					return LocalRuleEvidence{Action: action, Kind: strings.ToLower(strings.ReplaceAll(kind, "DOMAIN-", "domain-")), Value: host, SourceLine: lineNo, Options: options}, "clash", nil
				case "DOMAIN-KEYWORD":
					keyword, err := normalizeRuleToken(value, 253, "domain keyword")
					if err != nil {
						return LocalRuleEvidence{}, "", fmt.Errorf("line %d: %w", lineNo, err)
					}
					return LocalRuleEvidence{Action: action, Kind: "domain-keyword", Value: strings.ToLower(keyword), SourceLine: lineNo, Options: options}, "clash", nil
				case "IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR":
					prefix, err := netip.ParsePrefix(value)
					if err != nil {
						return LocalRuleEvidence{}, "", fmt.Errorf("line %d invalid CIDR %q", lineNo, value)
					}
					outKind := "cidr"
					if kind == "SRC-IP-CIDR" {
						outKind = "source-cidr"
					}
					return LocalRuleEvidence{Action: action, Kind: outKind, Value: prefix.Masked().String(), SourceLine: lineNo, Options: options}, "clash", nil
				case "SRC-PORT", "DST-PORT":
					port, err := normalizeRulePort(value)
					if err != nil {
						return LocalRuleEvidence{}, "", fmt.Errorf("line %d: %w", lineNo, err)
					}
					outKind := "source-port"
					if kind == "DST-PORT" {
						outKind = "destination-port"
					}
					return LocalRuleEvidence{Action: action, Kind: outKind, Value: port, SourceLine: lineNo, Options: options}, "clash", nil
				case "PROCESS-NAME":
					name, err := normalizeRuleToken(value, 255, "process name")
					if err != nil {
						return LocalRuleEvidence{}, "", fmt.Errorf("line %d: %w", lineNo, err)
					}
					return LocalRuleEvidence{Action: action, Kind: "process-name", Value: name, SourceLine: lineNo, Options: options}, "clash", nil
				case "GEOIP", "SRC-GEOIP":
					code, err := normalizeGeoCode(value)
					if err != nil {
						return LocalRuleEvidence{}, "", fmt.Errorf("line %d: %w", lineNo, err)
					}
					outKind := "geoip"
					if kind == "SRC-GEOIP" {
						outKind = "source-geoip"
					}
					return LocalRuleEvidence{Action: action, Kind: outKind, Value: code, SourceLine: lineNo, Options: options}, "clash", nil
				case "RULE-SET":
					ref, err := normalizeRuleReference(value)
					if err != nil {
						return LocalRuleEvidence{}, "", fmt.Errorf("line %d: %w", lineNo, err)
					}
					return LocalRuleEvidence{Action: action, Kind: "rule-set-ref", Value: ref, SourceLine: lineNo, Options: options}, "clash", nil
				}
			}
		}
		if format == "clash" || format == "surge" {
			return LocalRuleEvidence{}, "", fmt.Errorf("line %d is not a supported Clash/Surge rule", lineNo)
		}
	}
	if format == "auto" || format == "luminet" {
		fields := strings.Fields(line)
		if len(fields) == 2 {
			action := normalizeRuleAction(fields[0])
			kv := strings.SplitN(fields[1], ":", 2)
			if action != "" && len(kv) == 2 {
				kind, value := strings.ToLower(kv[0]), strings.TrimSpace(kv[1])
				switch kind {
				case "domain", "domain-suffix":
					host, err := normalizeRuleDomain(value)
					if err != nil {
						return LocalRuleEvidence{}, "", fmt.Errorf("line %d: %w", lineNo, err)
					}
					return LocalRuleEvidence{Action: action, Kind: kind, Value: host, SourceLine: lineNo}, "luminet", nil
				case "cidr":
					prefix, err := netip.ParsePrefix(value)
					if err != nil {
						return LocalRuleEvidence{}, "", fmt.Errorf("line %d invalid CIDR %q", lineNo, value)
					}
					return LocalRuleEvidence{Action: action, Kind: "cidr", Value: prefix.Masked().String(), SourceLine: lineNo}, "luminet", nil
				case "domain-keyword", "process-name":
					token, err := normalizeRuleToken(value, 255, kind)
					if err != nil {
						return LocalRuleEvidence{}, "", fmt.Errorf("line %d: %w", lineNo, err)
					}
					if kind == "domain-keyword" {
						token = strings.ToLower(token)
					}
					return LocalRuleEvidence{Action: action, Kind: kind, Value: token, SourceLine: lineNo}, "luminet", nil
				case "source-cidr":
					prefix, err := netip.ParsePrefix(value)
					if err != nil {
						return LocalRuleEvidence{}, "", fmt.Errorf("line %d invalid CIDR %q", lineNo, value)
					}
					return LocalRuleEvidence{Action: action, Kind: kind, Value: prefix.Masked().String(), SourceLine: lineNo}, "luminet", nil
				case "source-port", "destination-port":
					port, err := normalizeRulePort(value)
					if err != nil {
						return LocalRuleEvidence{}, "", fmt.Errorf("line %d: %w", lineNo, err)
					}
					return LocalRuleEvidence{Action: action, Kind: kind, Value: port, SourceLine: lineNo}, "luminet", nil
				case "geoip", "source-geoip":
					code, err := normalizeGeoCode(value)
					if err != nil {
						return LocalRuleEvidence{}, "", fmt.Errorf("line %d: %w", lineNo, err)
					}
					return LocalRuleEvidence{Action: action, Kind: kind, Value: code, SourceLine: lineNo}, "luminet", nil
				case "rule-set-ref":
					ref, err := normalizeRuleReference(value)
					if err != nil {
						return LocalRuleEvidence{}, "", fmt.Errorf("line %d: %w", lineNo, err)
					}
					return LocalRuleEvidence{Action: action, Kind: kind, Value: ref, SourceLine: lineNo}, "luminet", nil
				}
			}
		}
	}
	return LocalRuleEvidence{}, "", fmt.Errorf("line %d has ambiguous or unsupported local rule syntax: %q", lineNo, line)
}

func normalizeRuleOptions(parts []string) ([]string, error) {
	if len(parts) == 0 {
		return nil, nil
	}
	seen := map[string]bool{}
	options := make([]string, 0, len(parts))
	for _, raw := range parts {
		option := strings.ToLower(strings.TrimSpace(raw))
		if option == "" {
			continue
		}
		if option != "no-resolve" {
			return nil, fmt.Errorf("unsupported non-executable rule option %q", raw)
		}
		if !seen[option] {
			seen[option] = true
			options = append(options, option)
		}
	}
	return options, nil
}

func normalizeRuleToken(value string, max int, label string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > max || strings.ContainsAny(value, "\x00\r\n,") {
		return "", fmt.Errorf("invalid %s %q", label, value)
	}
	return value, nil
}

func normalizeRulePort(value string) (string, error) {
	value = strings.TrimSpace(value)
	parts := strings.Split(value, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return "", fmt.Errorf("invalid port or port range %q", value)
	}
	parsed := make([]int, len(parts))
	for i, part := range parts {
		port, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || port < 1 || port > 65535 {
			return "", fmt.Errorf("invalid port or port range %q", value)
		}
		parsed[i] = port
	}
	if len(parsed) == 2 {
		if parsed[0] > parsed[1] {
			return "", fmt.Errorf("descending port range %q", value)
		}
		return fmt.Sprintf("%d-%d", parsed[0], parsed[1]), nil
	}
	return strconv.Itoa(parsed[0]), nil
}

func normalizeGeoCode(value string) (string, error) {
	value = strings.ToUpper(strings.TrimSpace(value))
	if len(value) < 2 || len(value) > 16 {
		return "", fmt.Errorf("invalid GEOIP code %q", value)
	}
	for _, r := range value {
		if !((r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-') {
			return "", fmt.Errorf("invalid GEOIP code %q", value)
		}
	}
	return value, nil
}

func normalizeRuleReference(value string) (string, error) {
	value, err := normalizeRuleToken(value, 128, "rule-set reference")
	if err != nil {
		return "", err
	}
	lower := strings.ToLower(value)
	if strings.Contains(lower, "://") || strings.HasPrefix(lower, "file:") || strings.ContainsAny(value, "/\\") {
		return "", fmt.Errorf("rule-set reference %q must be a local symbolic identifier, not a path or URL", value)
	}
	return value, nil
}

func canonicalDomainRule(action, value string, line int, detected string) (LocalRuleEvidence, string, error) {
	host, err := normalizeRuleDomain(value)
	if err != nil {
		return LocalRuleEvidence{}, "", fmt.Errorf("line %d: %w", line, err)
	}
	return LocalRuleEvidence{Action: action, Kind: "domain-suffix", Value: host, SourceLine: line}, detected, nil
}

func normalizeRuleDomain(value string) (string, error) {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if value == "" || len(value) > 253 || strings.ContainsAny(value, " /\\\t\x00") {
		return "", fmt.Errorf("invalid domain %q", value)
	}
	return value, nil
}

func normalizeRuleAction(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "reject", "block", "deny":
		return "block"
	case "direct", "allow", "permit":
		return "allow"
	case "proxy":
		return "proxy"
	default:
		return ""
	}
}
