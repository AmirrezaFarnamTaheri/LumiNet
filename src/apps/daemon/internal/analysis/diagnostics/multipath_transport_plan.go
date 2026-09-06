package diagnostics

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"sort"
	"strings"
)

const (
	multipathSessionIDBytes      = 8
	multipathLengthPrefixBytes   = 2
	multipathMaxPacketBytes      = 65535
	multipathDefaultQueuePackets = 32
	multipathMaxQueuePackets     = 4096
	multipathMaxPaths            = 32
	multipathMaxPreviewPackets   = 64
)

type MultipathPathObservation struct {
	ID        string  `json:"id"`
	Transport string  `json:"transport"`
	Healthy   bool    `json:"healthy"`
	Ready     bool    `json:"ready"`
	LatencyMS float64 `json:"latency_ms,omitempty"`
}

type MultipathTransportPlanRequest struct {
	Algorithm      string                     `json:"algorithm"`
	QueuePackets   int                        `json:"queue_packets,omitempty"`
	OverflowPolicy string                     `json:"overflow_policy,omitempty"`
	PreviewPackets int                        `json:"preview_packets,omitempty"`
	SelectionSeed  string                     `json:"selection_seed,omitempty"`
	Paths          []MultipathPathObservation `json:"paths"`
}

type MultipathPathPlan struct {
	ID        string  `json:"id"`
	Transport string  `json:"transport"`
	Healthy   bool    `json:"healthy"`
	Ready     bool    `json:"ready"`
	LatencyMS float64 `json:"latency_ms,omitempty"`
	Eligible  bool    `json:"eligible"`
	Reason    string  `json:"reason,omitempty"`
}

type MultipathTransportPlan struct {
	Algorithm               string              `json:"algorithm"`
	SessionIDBytes          int                 `json:"session_id_bytes"`
	PacketLengthPrefixBytes int                 `json:"packet_length_prefix_bytes"`
	MaxPacketBytes          int                 `json:"max_packet_bytes"`
	QueuePackets            int                 `json:"queue_packets"`
	OverflowPolicy          string              `json:"overflow_policy"`
	Paths                   []MultipathPathPlan `json:"paths"`
	EligiblePaths           []string            `json:"eligible_paths"`
	PreviewSchedule         []string            `json:"preview_schedule"`
	StartsTransports        bool                `json:"starts_transports"`
	PerformsNetworkIO       bool                `json:"performs_network_io"`
	WritesPackets           bool                `json:"writes_packets"`
	DropsSilently           bool                `json:"drops_silently"`
	Invariants              []string            `json:"invariants"`
	Warnings                []string            `json:"warnings,omitempty"`
}

func BuildMultipathTransportPlan(req MultipathTransportPlanRequest) (MultipathTransportPlan, error) {
	algorithm := strings.ToLower(strings.TrimSpace(req.Algorithm))
	if algorithm == "" {
		algorithm = "round-robin"
	}
	if algorithm != "round-robin" && algorithm != "random" {
		return MultipathTransportPlan{}, fmt.Errorf("algorithm must be round-robin or random")
	}
	if len(req.Paths) < 2 || len(req.Paths) > multipathMaxPaths {
		return MultipathTransportPlan{}, fmt.Errorf("paths must contain 2..%d observations", multipathMaxPaths)
	}
	queuePackets := req.QueuePackets
	if queuePackets == 0 {
		queuePackets = multipathDefaultQueuePackets
	}
	if queuePackets < 1 || queuePackets > multipathMaxQueuePackets {
		return MultipathTransportPlan{}, fmt.Errorf("queue_packets must be 1..%d", multipathMaxQueuePackets)
	}
	overflow := strings.ToLower(strings.TrimSpace(req.OverflowPolicy))
	if overflow == "" {
		overflow = "backpressure"
	}
	if overflow != "backpressure" && overflow != "reject-new" {
		return MultipathTransportPlan{}, fmt.Errorf("overflow_policy must be backpressure or reject-new")
	}
	preview := req.PreviewPackets
	if preview == 0 {
		preview = 16
	}
	if preview < 1 || preview > multipathMaxPreviewPackets {
		return MultipathTransportPlan{}, fmt.Errorf("preview_packets must be 1..%d", multipathMaxPreviewPackets)
	}

	plan := MultipathTransportPlan{
		Algorithm: algorithm, SessionIDBytes: multipathSessionIDBytes,
		PacketLengthPrefixBytes: multipathLengthPrefixBytes, MaxPacketBytes: multipathMaxPacketBytes,
		QueuePackets: queuePackets, OverflowPolicy: overflow,
		StartsTransports: false, PerformsNetworkIO: false, WritesPackets: false, DropsSilently: false,
		Invariants: []string{
			"the 8-byte session identity is carried separately from each length-prefixed packet",
			"packet payloads above 65535 bytes are rejected before uint16 framing",
			"only caller-observed healthy and ready paths are eligible for scheduling",
			"queue overflow is explicit backpressure or rejection; silent packet loss is never an implicit planner policy",
			"random scheduling is deterministic for a supplied or derived seed so a planning decision is reproducible",
			"the planner starts no pluggable transports, opens no sockets, and writes no packets",
		},
	}

	seen := make(map[string]struct{}, len(req.Paths))
	for _, raw := range req.Paths {
		id := strings.TrimSpace(raw.ID)
		transport := strings.ToLower(strings.TrimSpace(raw.Transport))
		if id == "" || len(id) > 96 || strings.ContainsAny(id, "\r\n\x00") {
			return MultipathTransportPlan{}, fmt.Errorf("path id is required and must be bounded")
		}
		if _, exists := seen[id]; exists {
			return MultipathTransportPlan{}, fmt.Errorf("duplicate path id %q", id)
		}
		seen[id] = struct{}{}
		if transport == "" || len(transport) > 48 || strings.ContainsAny(transport, "\r\n\x00") {
			return MultipathTransportPlan{}, fmt.Errorf("path %q transport is required and must be bounded", id)
		}
		if math.IsNaN(raw.LatencyMS) || math.IsInf(raw.LatencyMS, 0) || raw.LatencyMS < 0 || raw.LatencyMS > 120000 {
			return MultipathTransportPlan{}, fmt.Errorf("path %q latency_ms must be finite and 0..120000", id)
		}
		p := MultipathPathPlan{ID: id, Transport: transport, Healthy: raw.Healthy, Ready: raw.Ready, LatencyMS: raw.LatencyMS}
		switch {
		case !raw.Healthy:
			p.Reason = "unhealthy"
		case !raw.Ready:
			p.Reason = "not-ready"
		default:
			p.Eligible = true
			plan.EligiblePaths = append(plan.EligiblePaths, id)
		}
		plan.Paths = append(plan.Paths, p)
	}
	if len(plan.EligiblePaths) < 2 {
		return MultipathTransportPlan{}, fmt.Errorf("at least two healthy ready paths are required for traffic splitting")
	}
	// Normalize path order so schedule previews do not depend on map/UI ordering.
	sort.Strings(plan.EligiblePaths)
	seed := strings.TrimSpace(req.SelectionSeed)
	if seed == "" {
		seed = strings.Join(plan.EligiblePaths, "|")
		plan.Warnings = append(plan.Warnings, "selection_seed omitted; deterministic path identity seed derived from eligible path IDs")
	}
	for i := 0; i < preview; i++ {
		var index int
		if algorithm == "round-robin" {
			index = i % len(plan.EligiblePaths)
		} else {
			h := sha256.Sum256([]byte(fmt.Sprintf("%s|%d", seed, i)))
			index = int(binary.BigEndian.Uint64(h[:8]) % uint64(len(plan.EligiblePaths)))
		}
		plan.PreviewSchedule = append(plan.PreviewSchedule, plan.EligiblePaths[index])
	}
	return plan, nil
}
