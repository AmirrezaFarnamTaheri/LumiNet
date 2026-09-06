package diagnostics

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
)

const maxSplitTunnelEntries = 512

type SplitTunnelEntry struct {
	Kind       string `json:"kind"`
	Identifier string `json:"identifier"`
}

type SplitTunnelPlanRequest struct {
	Platform string             `json:"platform"`
	Mode     string             `json:"mode"`
	Entries  []SplitTunnelEntry `json:"entries,omitempty"`
}

type SplitTunnelPlan struct {
	Platform                string             `json:"platform"`
	Mode                    string             `json:"mode"`
	Entries                 []SplitTunnelEntry `json:"entries"`
	DuplicateCount          int                `json:"duplicate_count"`
	PortableEntryCount      int                `json:"portable_entry_count"`
	PlatformBoundEntryCount int                `json:"platform_bound_entry_count"`
	ManifestSHA256          string             `json:"manifest_sha256"`
	RuntimeSupported        bool               `json:"runtime_supported"`
	RuntimeEnforced         bool               `json:"runtime_enforced"`
	RequiresRuntimeOwner    bool               `json:"requires_runtime_owner"`
	Warnings                []string           `json:"warnings"`
	Invariants              []string           `json:"invariants"`
	ReadOnly                bool               `json:"read_only"`
}

func BuildSplitTunnelPlan(req SplitTunnelPlanRequest) (SplitTunnelPlan, error) {
	platform := strings.ToLower(strings.TrimSpace(req.Platform))
	switch platform {
	case "android", "windows", "linux", "macos":
	default:
		return SplitTunnelPlan{}, fmt.Errorf("platform must be android, windows, linux, or macos")
	}
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	switch mode {
	case "off", "include", "exclude":
	default:
		return SplitTunnelPlan{}, fmt.Errorf("mode must be off, include, or exclude")
	}
	if len(req.Entries) > maxSplitTunnelEntries {
		return SplitTunnelPlan{}, fmt.Errorf("split-tunnel entry count exceeds %d", maxSplitTunnelEntries)
	}
	if mode == "off" && len(req.Entries) != 0 {
		return SplitTunnelPlan{}, fmt.Errorf("off mode must not carry split-tunnel entries")
	}
	if mode != "off" && len(req.Entries) == 0 {
		return SplitTunnelPlan{}, fmt.Errorf("%s mode requires at least one split-tunnel entry", mode)
	}

	plan := SplitTunnelPlan{
		Platform:             platform,
		Mode:                 mode,
		RuntimeSupported:     false,
		RuntimeEnforced:      false,
		RequiresRuntimeOwner: mode != "off",
		ReadOnly:             true,
		Invariants: []string{
			"split-tunnel intent is normalized before any platform-specific enforcement",
			"include and exclude semantics remain explicit and are never inferred from an empty set",
			"portable package/process identifiers are kept distinct from platform-bound filesystem paths",
			"backup/restore identity is a deterministic hash of normalized intent, not mutable UI state",
			"the current LumiNet packet/process runtime does not claim per-app enforcement that it cannot perform",
			"this planner does not install drivers, BPF programs, firewall rules, route rules, or app exclusions",
		},
	}
	seen := map[string]bool{}
	for i, raw := range req.Entries {
		kind := strings.ToLower(strings.TrimSpace(raw.Kind))
		switch kind {
		case "package", "process", "path":
		default:
			return SplitTunnelPlan{}, fmt.Errorf("split-tunnel entry %d kind must be package, process, or path", i)
		}
		id := strings.TrimSpace(raw.Identifier)
		if id == "" || len(id) > 512 || strings.IndexByte(id, 0) >= 0 {
			return SplitTunnelPlan{}, fmt.Errorf("split-tunnel entry %d identifier must be 1..512 bytes without NUL", i)
		}
		for _, r := range id {
			if unicode.IsControl(r) {
				return SplitTunnelPlan{}, fmt.Errorf("split-tunnel entry %d identifier contains control characters", i)
			}
		}
		if kind == "package" {
			if strings.ContainsAny(id, `/\\`) || strings.Contains(id, "..") {
				return SplitTunnelPlan{}, fmt.Errorf("split-tunnel package %q is not a package identifier", id)
			}
			plan.PortableEntryCount++
		} else if kind == "process" {
			if strings.ContainsAny(id, `/\\`) {
				return SplitTunnelPlan{}, fmt.Errorf("split-tunnel process %q must be a basename, not a path", id)
			}
			plan.PortableEntryCount++
		} else {
			cleaned := filepath.Clean(id)
			if cleaned == "." || cleaned != id {
				return SplitTunnelPlan{}, fmt.Errorf("split-tunnel path %q must already be normalized", id)
			}
			plan.PlatformBoundEntryCount++
		}
		key := kind + "\x00" + strings.ToLower(id)
		if seen[key] {
			plan.DuplicateCount++
			continue
		}
		seen[key] = true
		plan.Entries = append(plan.Entries, SplitTunnelEntry{Kind: kind, Identifier: id})
	}
	sort.Slice(plan.Entries, func(i, j int) bool {
		if plan.Entries[i].Kind != plan.Entries[j].Kind {
			return plan.Entries[i].Kind < plan.Entries[j].Kind
		}
		return strings.ToLower(plan.Entries[i].Identifier) < strings.ToLower(plan.Entries[j].Identifier)
	})
	canonical, _ := json.Marshal(struct {
		Platform string             `json:"platform"`
		Mode     string             `json:"mode"`
		Entries  []SplitTunnelEntry `json:"entries"`
	}{Platform: platform, Mode: mode, Entries: plan.Entries})
	digest := sha256.Sum256(canonical)
	plan.ManifestSHA256 = hex.EncodeToString(digest[:])
	if plan.DuplicateCount > 0 {
		plan.Warnings = append(plan.Warnings, fmt.Sprintf("%d duplicate entries were removed during normalization", plan.DuplicateCount))
	}
	if plan.PlatformBoundEntryCount > 0 {
		plan.Warnings = append(plan.Warnings, "filesystem-path exclusions are platform-bound and require revalidation after restore or migration")
	}
	if mode != "off" {
		plan.Warnings = append(plan.Warnings, "current LumiNet runtime exposes this as planning/import intent only; enforcement remains unavailable")
	}
	return plan, nil
}
