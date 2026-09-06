package diagnostics

import (
	"fmt"
	"sort"
	"strings"
)

type GatewayService struct {
	ID        string   `json:"id"`
	Role      string   `json:"role"`
	DependsOn []string `json:"depends_on,omitempty"`
	Healthy   bool     `json:"healthy"`
}
type GatewayCompositionRequest struct {
	Services    []GatewayService `json:"services,omitempty"`
	Preset      string           `json:"preset,omitempty"`
	MaxRestarts int              `json:"max_restarts,omitempty"`
}
type GatewayCompositionPlan struct {
	Preset                string           `json:"preset,omitempty"`
	Services              []GatewayService `json:"services"`
	StartOrder            []string         `json:"start_order"`
	StopOrder             []string         `json:"stop_order"`
	RollbackOrder         []string         `json:"rollback_order"`
	Unhealthy             []string         `json:"unhealthy"`
	RestartBackoffSeconds []int            `json:"restart_backoff_seconds"`
	Downloads             bool             `json:"downloads"`
	WritesServiceConfig   bool             `json:"writes_service_config"`
	Invariants            []string         `json:"invariants"`
}

func BuildGatewayCompositionPlan(req GatewayCompositionRequest) (GatewayCompositionPlan, error) {
	preset := strings.ToLower(strings.TrimSpace(req.Preset))
	if preset != "" {
		if len(req.Services) != 0 {
			return GatewayCompositionPlan{}, fmt.Errorf("gateway preset and explicit services are mutually exclusive")
		}
		services, err := gatewayPresetServices(preset)
		if err != nil {
			return GatewayCompositionPlan{}, err
		}
		req.Services = services
	}
	if len(req.Services) == 0 || len(req.Services) > 32 {
		return GatewayCompositionPlan{}, fmt.Errorf("gateway service count must be 1..32")
	}
	roles := map[string]bool{"listener": true, "reverse-client": true, "reverse-server": true, "path-router": true, "detour": true, "health": true, "tunnel": true}
	byID := map[string]GatewayService{}
	indeg := map[string]int{}
	edges := map[string][]string{}
	for _, s := range req.Services {
		s.ID = strings.TrimSpace(s.ID)
		s.Role = strings.ToLower(strings.TrimSpace(s.Role))
		if s.ID == "" || len(s.ID) > 64 || byID[s.ID].ID != "" {
			return GatewayCompositionPlan{}, fmt.Errorf("invalid or duplicate gateway service id %q", s.ID)
		}
		if !roles[s.Role] {
			return GatewayCompositionPlan{}, fmt.Errorf("unsupported gateway service role %q", s.Role)
		}
		byID[s.ID] = s
		indeg[s.ID] = 0
	}
	for _, s := range byID {
		seen := map[string]bool{}
		for _, dep := range s.DependsOn {
			dep = strings.TrimSpace(dep)
			if dep == s.ID || byID[dep].ID == "" || seen[dep] {
				return GatewayCompositionPlan{}, fmt.Errorf("invalid dependency %q for %q", dep, s.ID)
			}
			seen[dep] = true
			indeg[s.ID]++
			edges[dep] = append(edges[dep], s.ID)
		}
	}
	var ready []string
	for id, d := range indeg {
		if d == 0 {
			ready = append(ready, id)
		}
	}
	sort.Strings(ready)
	var order []string
	for len(ready) > 0 {
		id := ready[0]
		ready = ready[1:]
		order = append(order, id)
		children := append([]string(nil), edges[id]...)
		sort.Strings(children)
		for _, c := range children {
			indeg[c]--
			if indeg[c] == 0 {
				ready = append(ready, c)
				sort.Strings(ready)
			}
		}
	}
	if len(order) != len(byID) {
		return GatewayCompositionPlan{}, fmt.Errorf("gateway dependency graph contains a cycle")
	}
	plan := GatewayCompositionPlan{Preset: preset, StartOrder: order}
	for _, id := range order {
		plan.Services = append(plan.Services, byID[id])
	}
	for i := len(order) - 1; i >= 0; i-- {
		plan.StopOrder = append(plan.StopOrder, order[i])
		plan.RollbackOrder = append(plan.RollbackOrder, order[i])
	}
	for _, id := range order {
		if !byID[id].Healthy {
			plan.Unhealthy = append(plan.Unhealthy, id)
		}
	}
	r := req.MaxRestarts
	if r == 0 {
		r = 4
	}
	if r < 0 || r > 8 {
		return GatewayCompositionPlan{}, fmt.Errorf("max_restarts must be 0..8")
	}
	for i := 0; i < r; i++ {
		d := 1 << i
		if d > 30 {
			d = 30
		}
		plan.RestartBackoffSeconds = append(plan.RestartBackoffSeconds, d)
	}
	plan.Invariants = []string{
		"dependencies start before dependents and stop in reverse order",
		"rollback order is deterministic and reverses the admitted start order",
		"health evidence remains descriptive and does not silently start an unhealthy service",
		"restart schedules are bounded and capped",
		"built-in presets describe topology only; they do not select binaries, credentials, domains, or service-manager commands",
		"the planner downloads nothing and writes no systemd, cron, runit, Caddy, or other service configuration",
	}
	return plan, nil
}

func gatewayPresetServices(preset string) ([]GatewayService, error) {
	switch preset {
	case "reverse-tls-relay":
		return []GatewayService{
			{ID: "ingress", Role: "listener", Healthy: true},
			{ID: "reverse-server", Role: "reverse-server", DependsOn: []string{"ingress"}, Healthy: true},
			{ID: "reverse-client", Role: "reverse-client", DependsOn: []string{"reverse-server"}, Healthy: true},
			{ID: "health", Role: "health", DependsOn: []string{"reverse-client"}, Healthy: true},
		}, nil
	case "websocket-edge":
		return []GatewayService{
			{ID: "ingress", Role: "listener", Healthy: true},
			{ID: "path-router", Role: "path-router", DependsOn: []string{"ingress"}, Healthy: true},
			{ID: "websocket-tunnel", Role: "tunnel", DependsOn: []string{"path-router"}, Healthy: true},
			{ID: "health", Role: "health", DependsOn: []string{"websocket-tunnel"}, Healthy: true},
		}, nil
	case "managed-edge-tunnel":
		return []GatewayService{
			{ID: "ingress", Role: "listener", Healthy: true},
			{ID: "detour", Role: "detour", DependsOn: []string{"ingress"}, Healthy: true},
			{ID: "managed-tunnel", Role: "tunnel", DependsOn: []string{"detour"}, Healthy: true},
			{ID: "health", Role: "health", DependsOn: []string{"managed-tunnel"}, Healthy: true},
		}, nil
	case "layered-fronted-egress":
		return []GatewayService{
			{ID: "ingress", Role: "listener", Healthy: true},
			{ID: "path-router", Role: "path-router", DependsOn: []string{"ingress"}, Healthy: true},
			{ID: "detour", Role: "detour", DependsOn: []string{"path-router"}, Healthy: true},
			{ID: "egress-tunnel", Role: "tunnel", DependsOn: []string{"detour"}, Healthy: true},
			{ID: "health", Role: "health", DependsOn: []string{"egress-tunnel"}, Healthy: true},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported gateway preset %q", preset)
	}
}
