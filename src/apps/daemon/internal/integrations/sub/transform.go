package sub

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/maybeknott/luminet/internal/networking/proxyconfig"
)

const (
	maxTransformPatterns    = 32
	maxTransformPatternLen  = 256
	maxTransformReplaceLen  = 512
	maxTransformProtocols   = 64
	maxTransformedNameBytes = 256
)

type RenameRule struct {
	Pattern     string `json:"pattern"`
	Replacement string `json:"replacement"`
}

// TransformSpec is a bounded local node-shaping pipeline
// subscription converters. It intentionally supports deterministic declarative
// operations only: no scripts, remote includes, filesystem reads, or fetches.
type TransformSpec struct {
	Include     []string     `json:"include,omitempty"`
	Exclude     []string     `json:"exclude,omitempty"`
	Rename      []RenameRule `json:"rename,omitempty"`
	Protocols   []string     `json:"protocols,omitempty"`
	Deduplicate bool         `json:"deduplicate,omitempty"`
	SortBy      string       `json:"sort_by,omitempty"` // original|name|protocol|address
	Limit       int          `json:"limit,omitempty"`
}

type TransformReport struct {
	InputNodes   int `json:"input_nodes"`
	OutputNodes  int `json:"output_nodes"`
	Filtered     int `json:"filtered"`
	Renamed      int `json:"renamed"`
	Deduplicated int `json:"deduplicated"`
	Truncated    int `json:"truncated"`
}

type compiledRename struct {
	re          *regexp.Regexp
	replacement string
}

// TransformConfigs applies bounded node shaping while preserving graph
// semantics. If filtering or limiting would orphan a top-level detour target,
// the operation fails instead of silently flattening the chain.
func TransformConfigs(configs []*proxyconfig.ProxyConfig, spec TransformSpec) ([]*proxyconfig.ProxyConfig, TransformReport, error) {
	report := TransformReport{InputNodes: len(configs)}
	if len(configs) > maxConversionNodes {
		return nil, report, fmt.Errorf("transform node count exceeds %d", maxConversionNodes)
	}
	include, err := compileTransformPatterns("include", spec.Include)
	if err != nil {
		return nil, report, err
	}
	exclude, err := compileTransformPatterns("exclude", spec.Exclude)
	if err != nil {
		return nil, report, err
	}
	renames, err := compileRenameRules(spec.Rename)
	if err != nil {
		return nil, report, err
	}
	protocols, err := compileProtocolSet(spec.Protocols)
	if err != nil {
		return nil, report, err
	}
	sortBy := strings.ToLower(strings.TrimSpace(spec.SortBy))
	if sortBy == "" {
		sortBy = "original"
	}
	if sortBy != "original" && sortBy != "name" && sortBy != "protocol" && sortBy != "address" {
		return nil, report, fmt.Errorf("unsupported transform sort_by %q", spec.SortBy)
	}
	if spec.Limit < 0 || spec.Limit > maxConversionNodes {
		return nil, report, fmt.Errorf("transform limit must be between 0 and %d", maxConversionNodes)
	}

	selected := make([]*proxyconfig.ProxyConfig, 0, len(configs))
	selectedSet := make(map[*proxyconfig.ProxyConfig]struct{}, len(configs))
	for _, cfg := range configs {
		name, protocol := "", ""
		if cfg != nil {
			name = cfg.Name
			protocol = strings.ToLower(strings.TrimSpace(string(cfg.Protocol)))
		}
		if len(include) > 0 && !matchAny(include, name) {
			report.Filtered++
			continue
		}
		if matchAny(exclude, name) {
			report.Filtered++
			continue
		}
		if len(protocols) > 0 {
			if _, ok := protocols[protocol]; !ok {
				report.Filtered++
				continue
			}
		}
		selected = append(selected, cfg)
		if cfg != nil {
			selectedSet[cfg] = struct{}{}
		}
	}

	for _, cfg := range selected {
		if cfg == nil || cfg.Detour == nil {
			continue
		}
		if _, ok := selectedSet[cfg.Detour]; !ok {
			return nil, report, fmt.Errorf("transform would orphan detour target %q referenced by %q", cfg.Detour.Name, cfg.Name)
		}
	}

	alias := make(map[*proxyconfig.ProxyConfig]*proxyconfig.ProxyConfig)
	if spec.Deduplicate {
		seen := make(map[string]*proxyconfig.ProxyConfig, len(selected))
		out := selected[:0]
		for _, cfg := range selected {
			key, ok := standaloneSemanticKey(cfg)
			if !ok {
				out = append(out, cfg)
				continue
			}
			if first := seen[key]; first != nil {
				alias[cfg] = first
				report.Deduplicated++
				continue
			}
			seen[key] = cfg
			out = append(out, cfg)
		}
		selected = out
	}

	if sortBy != "original" {
		sort.SliceStable(selected, func(i, j int) bool {
			ai, aj := transformSortKey(selected[i], sortBy), transformSortKey(selected[j], sortBy)
			if ai == aj {
				return i < j
			}
			return ai < aj
		})
	}
	if spec.Limit > 0 && len(selected) > spec.Limit {
		report.Truncated = len(selected) - spec.Limit
		selected = selected[:spec.Limit]
	}

	kept := make(map[*proxyconfig.ProxyConfig]struct{}, len(selected))
	for _, cfg := range selected {
		if cfg != nil {
			kept[cfg] = struct{}{}
		}
	}
	for _, cfg := range selected {
		if cfg == nil || cfg.Detour == nil {
			continue
		}
		target := cfg.Detour
		if mapped := alias[target]; mapped != nil {
			target = mapped
		}
		if _, ok := kept[target]; !ok {
			return nil, report, fmt.Errorf("transform limit would orphan detour target %q referenced by %q", target.Name, cfg.Name)
		}
	}

	copies := make([]*proxyconfig.ProxyConfig, len(selected))
	copyByOriginal := make(map[*proxyconfig.ProxyConfig]*proxyconfig.ProxyConfig, len(selected))
	for i, cfg := range selected {
		if cfg == nil {
			continue
		}
		clone := cloneProxyConfigShallow(cfg)
		for _, rr := range renames {
			next := rr.re.ReplaceAllString(clone.Name, rr.replacement)
			if next != clone.Name {
				clone.Name = next
				report.Renamed++
			}
		}
		if len(clone.Name) > maxTransformedNameBytes {
			return nil, report, fmt.Errorf("transformed node name exceeds %d bytes", maxTransformedNameBytes)
		}
		clone.Detour = nil
		copies[i] = clone
		copyByOriginal[cfg] = clone
	}
	for i, original := range selected {
		if original == nil || original.Detour == nil || copies[i] == nil {
			continue
		}
		target := original.Detour
		if mapped := alias[target]; mapped != nil {
			target = mapped
		}
		copyTarget := copyByOriginal[target]
		if copyTarget == nil {
			return nil, report, fmt.Errorf("internal transform detour target missing for %q", original.Name)
		}
		copies[i].Detour = copyTarget
		copies[i].DialerProxy = copyTarget.Name
	}
	report.OutputNodes = len(copies)
	return copies, report, nil
}

func compileTransformPatterns(label string, raw []string) ([]*regexp.Regexp, error) {
	if len(raw) > maxTransformPatterns {
		return nil, fmt.Errorf("%s patterns exceed %d", label, maxTransformPatterns)
	}
	out := make([]*regexp.Regexp, 0, len(raw))
	for _, pattern := range raw {
		if strings.TrimSpace(pattern) == "" {
			continue
		}
		if len(pattern) > maxTransformPatternLen {
			return nil, fmt.Errorf("%s pattern exceeds %d bytes", label, maxTransformPatternLen)
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid %s pattern %q: %w", label, pattern, err)
		}
		out = append(out, re)
	}
	return out, nil
}

func compileRenameRules(raw []RenameRule) ([]compiledRename, error) {
	if len(raw) > maxTransformPatterns {
		return nil, fmt.Errorf("rename rules exceed %d", maxTransformPatterns)
	}
	out := make([]compiledRename, 0, len(raw))
	for _, rule := range raw {
		pattern := rule.Pattern
		if strings.TrimSpace(pattern) == "" {
			return nil, fmt.Errorf("rename pattern is required")
		}
		if len(pattern) > maxTransformPatternLen {
			return nil, fmt.Errorf("rename pattern exceeds %d bytes", maxTransformPatternLen)
		}
		if len(rule.Replacement) > maxTransformReplaceLen {
			return nil, fmt.Errorf("rename replacement exceeds %d bytes", maxTransformReplaceLen)
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid rename pattern %q: %w", pattern, err)
		}
		out = append(out, compiledRename{re: re, replacement: rule.Replacement})
	}
	return out, nil
}

func compileProtocolSet(raw []string) (map[string]struct{}, error) {
	if len(raw) > maxTransformProtocols {
		return nil, fmt.Errorf("protocol filter exceeds %d entries", maxTransformProtocols)
	}
	out := make(map[string]struct{}, len(raw))
	for _, item := range raw {
		item = strings.ToLower(strings.TrimSpace(item))
		if item == "" {
			continue
		}
		if len(item) > 32 {
			return nil, fmt.Errorf("protocol filter value exceeds 32 bytes")
		}
		out[item] = struct{}{}
	}
	return out, nil
}

func matchAny(patterns []*regexp.Regexp, value string) bool {
	for _, re := range patterns {
		if re.MatchString(value) {
			return true
		}
	}
	return false
}

func standaloneSemanticKey(cfg *proxyconfig.ProxyConfig) (string, bool) {
	if cfg == nil || cfg.Detour != nil || strings.TrimSpace(cfg.DialerProxy) != "" {
		return "", false
	}
	clone := cloneProxyConfigShallow(cfg)
	clone.Name = ""
	clone.RawURI = ""
	clone.Detour = nil
	clone.DialerProxy = ""
	data, err := json.Marshal(clone)
	if err != nil {
		return "", false
	}
	return string(data), true
}

func cloneProxyConfigShallow(cfg *proxyconfig.ProxyConfig) *proxyconfig.ProxyConfig {
	if cfg == nil {
		return nil
	}
	clone := *cfg
	clone.ALPN = append([]string(nil), cfg.ALPN...)
	clone.LocalAddress = append([]string(nil), cfg.LocalAddress...)
	clone.Reserved = append([]int(nil), cfg.Reserved...)
	clone.Resolvers = append([]string(nil), cfg.Resolvers...)
	return &clone
}

func transformSortKey(cfg *proxyconfig.ProxyConfig, sortBy string) string {
	if cfg == nil {
		return "\xff"
	}
	switch sortBy {
	case "protocol":
		return strings.ToLower(string(cfg.Protocol)) + "\x00" + strings.ToLower(cfg.Name)
	case "address":
		return strings.ToLower(cfg.Address) + fmt.Sprintf(":%05d\x00", cfg.Port) + strings.ToLower(cfg.Name)
	default:
		return strings.ToLower(cfg.Name)
	}
}
