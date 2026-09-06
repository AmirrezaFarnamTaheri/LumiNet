package diagnostics

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

const (
	maxRoutingCorpusFiles  = 128
	maxRoutingRulesPerFile = 10000
	maxRoutingCorpusRules  = 100000
)

type RoutingCorpusRule struct {
	Action string `json:"action"`
	Value  string `json:"value"`
}
type RoutingCorpusFile struct {
	Name     string              `json:"name"`
	Includes []string            `json:"includes,omitempty"`
	Rules    []RoutingCorpusRule `json:"rules,omitempty"`
}
type RoutingCorpusFileAudit struct {
	Name            string         `json:"name"`
	SHA256          string         `json:"sha256"`
	Rules           int            `json:"rules"`
	DuplicateRules  int            `json:"duplicate_rules"`
	InvalidRules    int            `json:"invalid_rules"`
	MissingIncludes []string       `json:"missing_includes,omitempty"`
	ActionCounts    map[string]int `json:"action_counts"`
}
type RoutingCorpusPlan struct {
	Files                  []RoutingCorpusFileAudit `json:"files"`
	CombinedSHA256         string                   `json:"combined_sha256"`
	TotalRules             int                      `json:"total_rules"`
	DuplicateRules         int                      `json:"duplicate_rules"`
	InvalidRules           int                      `json:"invalid_rules"`
	MissingIncludes        int                      `json:"missing_includes"`
	ActionProvenance       map[string][]string      `json:"action_provenance"`
	ImportsMutableDatasets bool                     `json:"imports_mutable_datasets"`
}
type RoutingPolicyPreset struct {
	ID             string `json:"id"`
	SecurityFirst  bool   `json:"security_first"`
	DirectDomestic bool   `json:"direct_domestic"`
	DirectPrivate  bool   `json:"direct_private"`
	DefaultAction  string `json:"default_action"`
}

func RoutingPolicyPresets() []RoutingPolicyPreset {
	return []RoutingPolicyPreset{
		{ID: "balanced-security", SecurityFirst: true, DirectDomestic: true, DirectPrivate: true, DefaultAction: "proxy"},
		{ID: "security-first", SecurityFirst: true, DirectDomestic: false, DirectPrivate: true, DefaultAction: "proxy"},
		{ID: "minimal-direct", SecurityFirst: true, DirectDomestic: false, DirectPrivate: true, DefaultAction: "proxy"},
	}
}

func normalizeRoutingAction(raw string) (string, bool) {
	a := strings.ToLower(strings.TrimSpace(raw))
	switch a {
	case "direct", "proxy", "block", "reject":
		return a, true
	default:
		return a, false
	}
}
func normalizeRoutingValue(raw string) string { return strings.ToLower(strings.TrimSpace(raw)) }

// BuildRoutingCorpusPlan audits caller-supplied, already-materialized routing
// evidence. It does not fetch donor lists and does not install routing rules.
func BuildRoutingCorpusPlan(files []RoutingCorpusFile) (RoutingCorpusPlan, error) {
	if len(files) == 0 || len(files) > maxRoutingCorpusFiles {
		return RoutingCorpusPlan{}, fmt.Errorf("routing corpus file count must be between 1 and %d", maxRoutingCorpusFiles)
	}
	names := map[string]struct{}{}
	total := 0
	for _, f := range files {
		name := strings.TrimSpace(f.Name)
		if name == "" || len(name) > 256 {
			return RoutingCorpusPlan{}, fmt.Errorf("invalid routing corpus file name")
		}
		if _, ok := names[name]; ok {
			return RoutingCorpusPlan{}, fmt.Errorf("duplicate routing corpus file %q", name)
		}
		names[name] = struct{}{}
		if len(f.Rules) > maxRoutingRulesPerFile {
			return RoutingCorpusPlan{}, fmt.Errorf("file %s exceeds rule bound", name)
		}
		total += len(f.Rules)
	}
	if total > maxRoutingCorpusRules {
		return RoutingCorpusPlan{}, fmt.Errorf("routing corpus exceeds %d rules", maxRoutingCorpusRules)
	}
	plan := RoutingCorpusPlan{Files: make([]RoutingCorpusFileAudit, 0, len(files)), ActionProvenance: map[string][]string{}, ImportsMutableDatasets: false}
	global := map[string]struct{}{}
	for _, f := range files {
		name := strings.TrimSpace(f.Name)
		audit := RoutingCorpusFileAudit{Name: name, Rules: len(f.Rules), ActionCounts: map[string]int{}, MissingIncludes: []string{}}
		for _, inc := range f.Includes {
			inc = strings.TrimSpace(inc)
			if _, ok := names[inc]; !ok {
				audit.MissingIncludes = append(audit.MissingIncludes, inc)
				plan.MissingIncludes++
			}
		}
		local := map[string]struct{}{}
		canonical := make([]string, 0, len(f.Rules)+len(f.Includes))
		incs := append([]string(nil), f.Includes...)
		sort.Strings(incs)
		for _, inc := range incs {
			canonical = append(canonical, "include\x00"+strings.TrimSpace(inc))
		}
		for _, r := range f.Rules {
			action, validAction := normalizeRoutingAction(r.Action)
			value := normalizeRoutingValue(r.Value)
			key := action + "\x00" + value
			canonical = append(canonical, key)
			if !validAction || value == "" || len(value) > 2048 {
				audit.InvalidRules++
				plan.InvalidRules++
				continue
			}
			audit.ActionCounts[action]++
			if _, ok := local[key]; ok {
				audit.DuplicateRules++
				plan.DuplicateRules++
			} else {
				local[key] = struct{}{}
			}
			if _, ok := global[key]; ok {
				plan.DuplicateRules++
			} else {
				global[key] = struct{}{}
			}
		}
		sort.Strings(canonical)
		d := sha256.Sum256([]byte(strings.Join(canonical, "\n")))
		audit.SHA256 = hex.EncodeToString(d[:])
		sort.Strings(audit.MissingIncludes)
		plan.Files = append(plan.Files, audit)
		for action := range audit.ActionCounts {
			plan.ActionProvenance[action] = append(plan.ActionProvenance[action], name)
		}
		plan.TotalRules += len(f.Rules)
	}
	sort.Slice(plan.Files, func(i, j int) bool { return plan.Files[i].Name < plan.Files[j].Name })
	for k := range plan.ActionProvenance {
		sort.Strings(plan.ActionProvenance[k])
	}
	parts := make([]string, 0, len(plan.Files))
	for _, f := range plan.Files {
		parts = append(parts, f.Name+"\x00"+f.SHA256)
	}
	d := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	plan.CombinedSHA256 = hex.EncodeToString(d[:])
	return plan, nil
}
