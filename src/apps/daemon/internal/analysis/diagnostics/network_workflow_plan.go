package diagnostics

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

const (
	maxNetworkWorkflowActions = 64
	maxNetworkWorkflowEdges   = 256
	maxNetworkWorkflowDepth   = 8
)

type NetworkWorkflowAction struct {
	ID        string   `json:"id"`
	Kind      string   `json:"kind"`
	Target    string   `json:"target,omitempty"`
	Phase     string   `json:"phase,omitempty"`
	DependsOn []string `json:"depends_on,omitempty"`
	Tail      bool     `json:"tail,omitempty"`
}

type NetworkWorkflowPlan struct {
	InitOrder        []string `json:"init_order"`
	TriggerOrder     []string `json:"trigger_order"`
	CleanupOrder     []string `json:"cleanup_order"`
	RemoteReferences []string `json:"remote_references"`
	TunnelReferences []string `json:"tunnel_references"`
	Warnings         []string `json:"warnings"`
	Invariants       []string `json:"invariants"`
	ReadOnly         bool     `json:"read_only"`
	Executes         bool     `json:"executes"`
}

func normalizeWorkflowKind(raw string) (string, error) {
	kind := strings.ToLower(strings.TrimSpace(raw))
	switch kind {
	case "endpoint", "chain", "child", "remote", "tunnel", "udp-tunnel":
		return kind, nil
	case "docker-run", "docker-ns", "shell", "exec", "plugin":
		return "", fmt.Errorf("workflow action kind %q would execute or change host context and is not admissible", raw)
	default:
		return "", fmt.Errorf("unsupported workflow action kind %q", raw)
	}
}

func BuildNetworkWorkflowPlan(actions []NetworkWorkflowAction) (NetworkWorkflowPlan, error) {
	if len(actions) == 0 || len(actions) > maxNetworkWorkflowActions {
		return NetworkWorkflowPlan{}, fmt.Errorf("network workflow action count must be between 1 and %d", maxNetworkWorkflowActions)
	}

	type node struct {
		action NetworkWorkflowAction
		kind   string
		phase  string
		index  int
	}
	nodes := make(map[string]node, len(actions))
	order := make([]string, 0, len(actions))
	edges := 0
	for index, action := range actions {
		id := strings.TrimSpace(action.ID)
		if id == "" || len(id) > 64 {
			return NetworkWorkflowPlan{}, fmt.Errorf("workflow action %d id must be 1..64 bytes", index)
		}
		if _, exists := nodes[id]; exists {
			return NetworkWorkflowPlan{}, fmt.Errorf("duplicate workflow action id %q", id)
		}
		kind, err := normalizeWorkflowKind(action.Kind)
		if err != nil {
			return NetworkWorkflowPlan{}, err
		}
		phase := strings.ToLower(strings.TrimSpace(action.Phase))
		if phase == "" {
			phase = "init"
		}
		if phase != "init" && phase != "trigger" {
			return NetworkWorkflowPlan{}, fmt.Errorf("workflow action %q phase must be init or trigger", id)
		}
		target := strings.TrimSpace(action.Target)
		if len(target) > 512 {
			return NetworkWorkflowPlan{}, fmt.Errorf("workflow action %q target exceeds 512 bytes", id)
		}
		if kind == "endpoint" || kind == "remote" || kind == "tunnel" || kind == "udp-tunnel" {
			if target == "" {
				return NetworkWorkflowPlan{}, fmt.Errorf("workflow action %q kind %s requires a target", id, kind)
			}
			if parsed, err := url.Parse(target); err == nil && parsed.User != nil {
				return NetworkWorkflowPlan{}, fmt.Errorf("workflow action %q target must not embed credentials", id)
			}
		}
		if len(action.DependsOn) > maxNetworkWorkflowDepth {
			return NetworkWorkflowPlan{}, fmt.Errorf("workflow action %q has too many direct dependencies", id)
		}
		edges += len(action.DependsOn)
		if edges > maxNetworkWorkflowEdges {
			return NetworkWorkflowPlan{}, fmt.Errorf("network workflow dependency count exceeds %d", maxNetworkWorkflowEdges)
		}
		action.ID = id
		action.Target = target
		nodes[id] = node{action: action, kind: kind, phase: phase, index: index}
		order = append(order, id)
	}

	indegree := make(map[string]int, len(nodes))
	children := make(map[string][]string, len(nodes))
	depth := make(map[string]int, len(nodes))
	for id := range nodes {
		indegree[id] = 0
		depth[id] = 1
	}
	for id, current := range nodes {
		seenDep := map[string]bool{}
		for _, rawDep := range current.action.DependsOn {
			dep := strings.TrimSpace(rawDep)
			if dep == "" || seenDep[dep] {
				continue
			}
			seenDep[dep] = true
			parent, ok := nodes[dep]
			if !ok {
				return NetworkWorkflowPlan{}, fmt.Errorf("workflow action %q depends on unknown action %q", id, dep)
			}
			if dep == id {
				return NetworkWorkflowPlan{}, fmt.Errorf("workflow action %q depends on itself", id)
			}
			if current.phase == "init" && parent.phase == "trigger" {
				return NetworkWorkflowPlan{}, fmt.Errorf("init action %q cannot depend on trigger action %q", id, dep)
			}
			indegree[id]++
			children[dep] = append(children[dep], id)
		}
	}

	ready := make([]string, 0)
	for _, id := range order {
		if indegree[id] == 0 {
			ready = append(ready, id)
		}
	}
	stableSort := func(values []string) {
		sort.SliceStable(values, func(i, j int) bool { return nodes[values[i]].index < nodes[values[j]].index })
	}
	stableSort(ready)
	topo := make([]string, 0, len(nodes))
	for len(ready) > 0 {
		id := ready[0]
		ready = ready[1:]
		topo = append(topo, id)
		for _, child := range children[id] {
			if depth[child] < depth[id]+1 {
				depth[child] = depth[id] + 1
			}
			if depth[child] > maxNetworkWorkflowDepth {
				return NetworkWorkflowPlan{}, fmt.Errorf("network workflow dependency depth exceeds %d", maxNetworkWorkflowDepth)
			}
			indegree[child]--
			if indegree[child] == 0 {
				ready = append(ready, child)
				stableSort(ready)
			}
		}
	}
	if len(topo) != len(nodes) {
		return NetworkWorkflowPlan{}, fmt.Errorf("network workflow contains a dependency cycle")
	}

	plan := NetworkWorkflowPlan{ReadOnly: true, Executes: false}
	for _, id := range topo {
		current := nodes[id]
		if current.phase == "trigger" {
			plan.TriggerOrder = append(plan.TriggerOrder, id)
		} else {
			plan.InitOrder = append(plan.InitOrder, id)
		}
		switch current.kind {
		case "remote":
			plan.RemoteReferences = append(plan.RemoteReferences, current.action.Target)
		case "tunnel", "udp-tunnel":
			plan.TunnelReferences = append(plan.TunnelReferences, current.action.Target)
		}
		if current.action.Tail {
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("action %s is marked tail; callers must keep tail ownership explicit during composition", id))
		}
	}
	for i := len(topo) - 1; i >= 0; i-- {
		plan.CleanupOrder = append(plan.CleanupOrder, topo[i])
	}
	plan.Invariants = []string{
		"init actions never depend on trigger-only actions",
		"cleanup order is the reverse dependency order",
		"host-context and arbitrary-execution actions are rejected",
		"embedded target credentials are rejected",
		"workflow planning opens no sockets, starts no containers, and creates no tunnels",
	}
	return plan, nil
}
