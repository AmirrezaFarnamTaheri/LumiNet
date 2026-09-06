package diagnostics

import (
	"container/heap"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

const (
	maxMeshNodes = 256
	maxMeshEdges = 4096
)

type MeshRouteEdge struct {
	From        string    `json:"from"`
	To          string    `json:"to"`
	LatencyMs   float64   `json:"latency_ms"`
	LossPct     float64   `json:"loss_pct,omitempty"`
	Active      *bool     `json:"active,omitempty"`
	HealthState string    `json:"health_state,omitempty"`
	ObservedAt  time.Time `json:"observed_at,omitempty"`
}

type MeshRouteRequest struct {
	Source            string          `json:"source"`
	Policy            string          `json:"policy,omitempty"`
	Nodes             []string        `json:"nodes"`
	Edges             []MeshRouteEdge `json:"edges"`
	AsOf              time.Time       `json:"as_of,omitempty"`
	StaleAfterSeconds int             `json:"stale_after_seconds,omitempty"`
}

type MeshRoute struct {
	Destination    string   `json:"destination"`
	Path           []string `json:"path"`
	NextHop        string   `json:"next_hop,omitempty"`
	Hops           int      `json:"hops"`
	TotalLatencyMs float64  `json:"total_latency_ms"`
	ReliabilityPct float64  `json:"reliability_pct"`
	Cost           float64  `json:"cost"`
}

type MeshRoutePlan struct {
	Source string      `json:"source"`
	Policy string      `json:"policy"`
	Routes []MeshRoute `json:"routes"`
}

type meshArc struct {
	to                    string
	latency, loss, weight float64
}
type meshItem struct {
	node string
	cost float64
}
type meshPQ []meshItem

func (p meshPQ) Len() int           { return len(p) }
func (p meshPQ) Less(i, j int) bool { return p[i].cost < p[j].cost }
func (p meshPQ) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p *meshPQ) Push(x any)        { *p = append(*p, x.(meshItem)) }
func (p *meshPQ) Pop() any          { old := *p; n := len(old); x := old[n-1]; *p = old[:n-1]; return x }

func BuildMeshRoutePlan(req MeshRouteRequest) (MeshRoutePlan, error) {
	source := strings.TrimSpace(req.Source)
	if source == "" {
		return MeshRoutePlan{}, fmt.Errorf("mesh source is required")
	}
	if len(req.Nodes) == 0 || len(req.Nodes) > maxMeshNodes {
		return MeshRoutePlan{}, fmt.Errorf("mesh node count must be between 1 and %d", maxMeshNodes)
	}
	if len(req.Edges) > maxMeshEdges {
		return MeshRoutePlan{}, fmt.Errorf("mesh edge count exceeds %d", maxMeshEdges)
	}
	asOf := req.AsOf
	if asOf.IsZero() {
		asOf = time.Now()
	}
	staleAfter := req.StaleAfterSeconds
	if staleAfter == 0 {
		staleAfter = 120
	}
	if staleAfter < 1 || staleAfter > 86400 {
		return MeshRoutePlan{}, fmt.Errorf("mesh stale-after seconds must be between 1 and 86400")
	}
	policy := strings.ToLower(strings.TrimSpace(req.Policy))
	if policy == "" {
		policy = "latency-first"
	}
	if policy != "latency-first" && policy != "least-hop" {
		return MeshRoutePlan{}, fmt.Errorf("unsupported mesh policy %q", policy)
	}
	nodes := make(map[string]struct{}, len(req.Nodes))
	for _, raw := range req.Nodes {
		n := strings.TrimSpace(raw)
		if n == "" || len(n) > 128 {
			return MeshRoutePlan{}, fmt.Errorf("invalid mesh node")
		}
		if _, ok := nodes[n]; ok {
			return MeshRoutePlan{}, fmt.Errorf("duplicate mesh node %q", n)
		}
		nodes[n] = struct{}{}
	}
	if _, ok := nodes[source]; !ok {
		return MeshRoutePlan{}, fmt.Errorf("mesh source %q is not in nodes", source)
	}
	graph := make(map[string][]meshArc, len(nodes))
	for _, e := range req.Edges {
		from, to := strings.TrimSpace(e.From), strings.TrimSpace(e.To)
		if from == to || from == "" || to == "" {
			return MeshRoutePlan{}, fmt.Errorf("invalid mesh edge %q -> %q", from, to)
		}
		if _, ok := nodes[from]; !ok {
			return MeshRoutePlan{}, fmt.Errorf("unknown edge source %q", from)
		}
		if _, ok := nodes[to]; !ok {
			return MeshRoutePlan{}, fmt.Errorf("unknown edge destination %q", to)
		}
		health := strings.ToLower(strings.TrimSpace(e.HealthState))
		if health == "" {
			health = "unknown"
		}
		if health != "unknown" && health != "healthy" && health != "degraded" && health != "unhealthy" {
			return MeshRoutePlan{}, fmt.Errorf("invalid mesh edge health state")
		}
		if e.LatencyMs < 0 || e.LatencyMs > 120000 || e.LossPct < 0 || e.LossPct > 100 {
			return MeshRoutePlan{}, fmt.Errorf("invalid mesh edge metrics")
		}
		stale := !e.ObservedAt.IsZero() && asOf.Sub(e.ObservedAt) > time.Duration(staleAfter)*time.Second
		if e.Active != nil && !*e.Active || health == "unhealthy" || stale {
			continue
		}
		latency := e.LatencyMs
		if latency == 0 {
			latency = 1
		}
		weight := 1.0
		if policy == "latency-first" {
			weight = latency * (1.0 + e.LossPct/50.0)
		}
		// Degraded evidence may make an edge less attractive but never grants
		// eligibility. Stale/unhealthy edges were excluded above.
		if health == "degraded" {
			weight *= 1.25
		}
		graph[from] = append(graph[from], meshArc{to: to, latency: latency, loss: e.LossPct, weight: weight})
		graph[to] = append(graph[to], meshArc{to: from, latency: latency, loss: e.LossPct, weight: weight})
	}
	dist := map[string]float64{source: 0}
	prev := map[string]string{}
	edgeUsed := map[string]meshArc{}
	q := &meshPQ{{node: source, cost: 0}}
	heap.Init(q)
	for q.Len() > 0 {
		it := heap.Pop(q).(meshItem)
		if best := dist[it.node]; it.cost > best {
			continue
		}
		for _, a := range graph[it.node] {
			nd := it.cost + a.weight
			cur, ok := dist[a.to]
			if !ok || nd < cur {
				dist[a.to] = nd
				prev[a.to] = it.node
				edgeUsed[a.to] = a
				heap.Push(q, meshItem{node: a.to, cost: nd})
			}
		}
	}
	routes := make([]MeshRoute, 0, len(nodes)-1)
	for dest := range nodes {
		if dest == source {
			continue
		}
		cost, ok := dist[dest]
		if !ok {
			continue
		}
		path := []string{dest}
		lat := 0.0
		reliability := 1.0
		cur := dest
		for cur != source {
			a := edgeUsed[cur]
			lat += a.latency
			reliability *= 1.0 - a.loss/100.0
			cur = prev[cur]
			path = append(path, cur)
		}
		for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
			path[i], path[j] = path[j], path[i]
		}
		next := ""
		if len(path) > 1 {
			next = path[1]
		}
		routes = append(routes, MeshRoute{Destination: dest, Path: path, NextHop: next, Hops: len(path) - 1, TotalLatencyMs: math.Round(lat*100) / 100, ReliabilityPct: math.Round(reliability*10000) / 100, Cost: math.Round(cost*100) / 100})
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].Destination < routes[j].Destination })
	return MeshRoutePlan{Source: source, Policy: policy, Routes: routes}, nil
}
