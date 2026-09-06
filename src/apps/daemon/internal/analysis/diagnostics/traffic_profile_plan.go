package diagnostics

import (
	"fmt"
	"sort"
	"strings"
)

const (
	maxTrafficProfileStates       = 64
	maxTrafficActionsPerState     = 32
	maxTrafficTransitionsPerState = 32
)

type TrafficProfileAction struct {
	Kind            string  `json:"kind"`
	DelayMs         int     `json:"delay_ms,omitempty"`
	PaddingBytes    int     `json:"padding_bytes,omitempty"`
	BurstBytes      int     `json:"burst_bytes,omitempty"`
	OverheadPercent float64 `json:"overhead_percent,omitempty"`
	TimeoutMs       int     `json:"timeout_ms,omitempty"`
	Async           bool    `json:"async,omitempty"`
}

type TrafficProfileTransition struct {
	To          string  `json:"to"`
	Probability float64 `json:"probability,omitempty"`
	OnError     bool    `json:"on_error,omitempty"`
}
type TrafficProfileState struct {
	ID          string                     `json:"id"`
	Terminal    bool                       `json:"terminal,omitempty"`
	Actions     []TrafficProfileAction     `json:"actions,omitempty"`
	Transitions []TrafficProfileTransition `json:"transitions,omitempty"`
}
type TrafficProfileRequest struct {
	Version string                `json:"version"`
	Entry   string                `json:"entry"`
	States  []TrafficProfileState `json:"states"`
}
type TrafficProfileResourceSummary struct {
	MaxDelayMs         int     `json:"max_delay_ms"`
	MaxPaddingBytes    int     `json:"max_padding_bytes"`
	MaxBurstBytes      int     `json:"max_burst_bytes"`
	MaxOverheadPercent float64 `json:"max_overhead_percent"`
	MaxTimeoutMs       int     `json:"max_timeout_ms"`
}
type TrafficProfilePlan struct {
	Version           string                        `json:"version"`
	Entry             string                        `json:"entry"`
	TerminalStates    []string                      `json:"terminal_states"`
	UnreachableStates []string                      `json:"unreachable_states"`
	DeadEnds          []string                      `json:"dead_ends"`
	Cyclic            bool                          `json:"cyclic"`
	BlockingActions   int                           `json:"blocking_actions"`
	AsyncActions      int                           `json:"async_actions"`
	Resources         TrafficProfileResourceSummary `json:"resources"`
	DeclarativeOnly   bool                          `json:"declarative_only"`
	ExecutesPlugins   bool                          `json:"executes_plugins"`
}

type TrafficBehaviorPreset struct {
	ID              string  `json:"id"`
	DelayMs         int     `json:"delay_ms"`
	PaddingBytes    int     `json:"padding_bytes"`
	BurstBytes      int     `json:"burst_bytes"`
	OverheadPercent float64 `json:"overhead_percent"`
}

func TrafficBehaviorPresets() []TrafficBehaviorPreset {
	return []TrafficBehaviorPreset{
		{ID: "interactive", DelayMs: 15, PaddingBytes: 64, BurstBytes: 16 << 10, OverheadPercent: 5},
		{ID: "balanced", DelayMs: 40, PaddingBytes: 128, BurstBytes: 64 << 10, OverheadPercent: 10},
		{ID: "bulk", DelayMs: 100, PaddingBytes: 256, BurstBytes: 256 << 10, OverheadPercent: 15},
		{ID: "bursty", DelayMs: 25, PaddingBytes: 192, BurstBytes: 512 << 10, OverheadPercent: 20},
	}
}

func validateTrafficAction(a TrafficProfileAction) error {
	kind := strings.ToLower(strings.TrimSpace(a.Kind))
	switch kind {
	case "delay", "padding", "burst", "overhead", "idle":
	default:
		return fmt.Errorf("unsupported declarative traffic action %q", a.Kind)
	}
	if a.DelayMs < 0 || a.DelayMs > 60000 || a.PaddingBytes < 0 || a.PaddingBytes > 64<<10 || a.BurstBytes < 0 || a.BurstBytes > 1<<20 || a.OverheadPercent < 0 || a.OverheadPercent > 100 || a.TimeoutMs < 0 || a.TimeoutMs > 300000 {
		return fmt.Errorf("traffic action exceeds resource bounds")
	}
	return nil
}

// BuildTrafficProfilePlan analyzes a bounded declarative state graph. It does
// not execute scripts, plugins, processes, or network actions.
func BuildTrafficProfilePlan(req TrafficProfileRequest) (TrafficProfilePlan, error) {
	version := strings.TrimSpace(req.Version)
	entry := strings.TrimSpace(req.Entry)
	if version == "" || len(version) > 32 {
		return TrafficProfilePlan{}, fmt.Errorf("traffic profile version is required and must be at most 32 characters")
	}
	if entry == "" {
		return TrafficProfilePlan{}, fmt.Errorf("traffic profile entry state is required")
	}
	if len(req.States) == 0 || len(req.States) > maxTrafficProfileStates {
		return TrafficProfilePlan{}, fmt.Errorf("traffic profile state count must be between 1 and %d", maxTrafficProfileStates)
	}
	states := map[string]TrafficProfileState{}
	adjacency := map[string][]string{}
	plan := TrafficProfilePlan{Version: version, Entry: entry, DeclarativeOnly: true, TerminalStates: []string{}, UnreachableStates: []string{}, DeadEnds: []string{}}
	for _, st := range req.States {
		id := strings.TrimSpace(st.ID)
		if id == "" || len(id) > 128 {
			return TrafficProfilePlan{}, fmt.Errorf("invalid traffic profile state")
		}
		if _, ok := states[id]; ok {
			return TrafficProfilePlan{}, fmt.Errorf("duplicate traffic profile state %q", id)
		}
		if len(st.Actions) > maxTrafficActionsPerState || len(st.Transitions) > maxTrafficTransitionsPerState {
			return TrafficProfilePlan{}, fmt.Errorf("traffic profile state %q exceeds action/transition bounds", id)
		}
		states[id] = st
		for _, a := range st.Actions {
			if err := validateTrafficAction(a); err != nil {
				return TrafficProfilePlan{}, fmt.Errorf("state %s: %w", id, err)
			}
			if a.Async {
				plan.AsyncActions++
			} else {
				plan.BlockingActions++
			}
			if a.DelayMs > plan.Resources.MaxDelayMs {
				plan.Resources.MaxDelayMs = a.DelayMs
			}
			if a.PaddingBytes > plan.Resources.MaxPaddingBytes {
				plan.Resources.MaxPaddingBytes = a.PaddingBytes
			}
			if a.BurstBytes > plan.Resources.MaxBurstBytes {
				plan.Resources.MaxBurstBytes = a.BurstBytes
			}
			if a.OverheadPercent > plan.Resources.MaxOverheadPercent {
				plan.Resources.MaxOverheadPercent = a.OverheadPercent
			}
			if a.TimeoutMs > plan.Resources.MaxTimeoutMs {
				plan.Resources.MaxTimeoutMs = a.TimeoutMs
			}
		}
		if st.Terminal {
			plan.TerminalStates = append(plan.TerminalStates, id)
		}
	}
	if _, ok := states[entry]; !ok {
		return TrafficProfilePlan{}, fmt.Errorf("entry state %q not found", entry)
	}
	for id, st := range states {
		normalSum := 0.0
		errorCount := 0
		for _, tr := range st.Transitions {
			to := strings.TrimSpace(tr.To)
			if _, ok := states[to]; !ok {
				return TrafficProfilePlan{}, fmt.Errorf("state %s references unknown target %q", id, to)
			}
			if tr.Probability < 0 || tr.Probability > 1 {
				return TrafficProfilePlan{}, fmt.Errorf("state %s has invalid transition probability", id)
			}
			if tr.OnError {
				errorCount++
				if errorCount > 1 {
					return TrafficProfilePlan{}, fmt.Errorf("state %s has multiple error fallbacks", id)
				}
			} else {
				normalSum += tr.Probability
			}
			adjacency[id] = append(adjacency[id], to)
		}
		if normalSum > 1.0000001 {
			return TrafficProfilePlan{}, fmt.Errorf("state %s transition probability exceeds 1", id)
		}
		if !st.Terminal && len(st.Transitions) == 0 {
			plan.DeadEnds = append(plan.DeadEnds, id)
		}
	}
	visited := map[string]bool{}
	active := map[string]bool{}
	var dfs func(string)
	dfs = func(n string) {
		if active[n] {
			plan.Cyclic = true
			return
		}
		if visited[n] {
			return
		}
		visited[n] = true
		active[n] = true
		for _, to := range adjacency[n] {
			dfs(to)
		}
		active[n] = false
	}
	dfs(entry)
	for id := range states {
		if !visited[id] {
			plan.UnreachableStates = append(plan.UnreachableStates, id)
		}
	}
	sort.Strings(plan.TerminalStates)
	sort.Strings(plan.UnreachableStates)
	sort.Strings(plan.DeadEnds)
	return plan, nil
}
