package diagnostics

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

const (
	maxSNIPathCandidates = 128
	maxSNIActivePool     = 16
)

type SNIPathObservation struct {
	IP                  string    `json:"ip"`
	SNI                 string    `json:"sni"`
	TCPConnected        *bool     `json:"tcp_connected,omitempty"`
	TLSVerified         *bool     `json:"tls_verified,omitempty"`
	FirstResponse       *bool     `json:"first_response,omitempty"`
	PayloadBytes        int64     `json:"payload_bytes,omitempty"`
	Successes           int       `json:"successes,omitempty"`
	Failures            int       `json:"failures,omitempty"`
	LatencyMs           float64   `json:"latency_ms,omitempty"`
	Health              string    `json:"health,omitempty"`
	ConsecutiveFailures int       `json:"consecutive_failures,omitempty"`
	ObservedAt          time.Time `json:"observed_at,omitempty"`
	Capacity            int       `json:"capacity,omitempty"`
	InFlight            int       `json:"in_flight,omitempty"`
	PreviouslyActive    bool      `json:"previously_active,omitempty"`
	PathMTU             int       `json:"path_mtu,omitempty"`
	IPHeaderBytes       int       `json:"ip_header_bytes,omitempty"`
	TCPHeaderBytes      int       `json:"tcp_header_bytes,omitempty"`
}

type SNIPathPlanRequest struct {
	Candidates            []SNIPathObservation `json:"candidates"`
	AsOf                  time.Time            `json:"as_of,omitempty"`
	MaxEvidenceAgeSeconds int                  `json:"max_evidence_age_seconds,omitempty"`
	ActivePoolSize        int                  `json:"active_pool_size,omitempty"`
	DrainTimeoutSeconds   int                  `json:"drain_timeout_seconds,omitempty"`
}

type SNIPathRank struct {
	IP                                string    `json:"ip"`
	SNI                               string    `json:"sni"`
	Eligible                          bool      `json:"eligible"`
	ResponseQualified                 bool      `json:"response_qualified"`
	TLSVerified                       bool      `json:"tls_verified"`
	Score                             float64   `json:"score"`
	Recommendation                    string    `json:"recommendation"`
	Reason                            string    `json:"reason,omitempty"`
	DrainUntil                        time.Time `json:"drain_until,omitempty"`
	RecommendedMaxSegmentPayloadBytes int       `json:"recommended_max_segment_payload_bytes,omitempty"`
}

type SNIPathPlan struct {
	Ranked          []SNIPathRank `json:"ranked"`
	Active          []string      `json:"active"`
	Reserve         []string      `json:"reserve"`
	Drain           []string      `json:"drain"`
	SelectionBasis  []string      `json:"selection_basis"`
	ReadOnly        bool          `json:"read_only"`
	MutationAllowed bool          `json:"mutation_allowed"`
}

func boolEvidence(v *bool) bool { return v != nil && *v }

// TCPSeqAtOrAfter compares 32-bit TCP sequence numbers using RFC-style serial
// arithmetic so wraparound does not turn a later ACK into an apparent rewind.
func TCPSeqAtOrAfter(value, baseline uint32) bool { return int32(value-baseline) >= 0 }

// RecommendMaxSegmentPayload derives a read-only TCP payload ceiling from
// observed path MTU and actual header sizes. It never changes interface MTU/MSS.
func RecommendMaxSegmentPayload(pathMTU, ipHeaderBytes, tcpHeaderBytes int) (int, error) {
	if pathMTU < 576 || pathMTU > 65535 {
		return 0, fmt.Errorf("path MTU must be between 576 and 65535")
	}
	if ipHeaderBytes == 0 {
		ipHeaderBytes = 20
	}
	if tcpHeaderBytes == 0 {
		tcpHeaderBytes = 20
	}
	if (ipHeaderBytes != 20 && ipHeaderBytes != 40) || tcpHeaderBytes < 20 || tcpHeaderBytes > 60 || tcpHeaderBytes%4 != 0 {
		return 0, fmt.Errorf("invalid IP/TCP header evidence")
	}
	payload := pathMTU - ipHeaderBytes - tcpHeaderBytes
	if payload <= 0 {
		return 0, fmt.Errorf("headers exceed path MTU")
	}
	return payload, nil
}

func BuildSNIPathPlan(req SNIPathPlanRequest) (SNIPathPlan, error) {
	if len(req.Candidates) == 0 || len(req.Candidates) > maxSNIPathCandidates {
		return SNIPathPlan{}, fmt.Errorf("SNI path candidate count must be between 1 and %d", maxSNIPathCandidates)
	}
	asOf := req.AsOf
	if asOf.IsZero() {
		asOf = time.Now()
	}
	maxAge := req.MaxEvidenceAgeSeconds
	if maxAge == 0 {
		maxAge = 300
	}
	if maxAge < 1 || maxAge > 86400 {
		return SNIPathPlan{}, fmt.Errorf("max evidence age must be between 1 and 86400 seconds")
	}
	poolSize := req.ActivePoolSize
	if poolSize == 0 {
		poolSize = 3
	}
	if poolSize < 1 || poolSize > maxSNIActivePool {
		return SNIPathPlan{}, fmt.Errorf("active pool size must be between 1 and %d", maxSNIActivePool)
	}
	drainSeconds := req.DrainTimeoutSeconds
	if drainSeconds == 0 {
		drainSeconds = 60
	}
	if drainSeconds < 1 || drainSeconds > 3600 {
		return SNIPathPlan{}, fmt.Errorf("drain timeout must be between 1 and 3600 seconds")
	}

	seen := map[string]struct{}{}
	plan := SNIPathPlan{ReadOnly: true, MutationAllowed: false, SelectionBasis: []string{"first-response-qualified", "strict-tls-trust", "bounded-active-pool", "health-and-capacity"}}
	for _, c := range req.Candidates {
		ip := strings.TrimSpace(c.IP)
		sni := strings.ToLower(strings.TrimSpace(c.SNI))
		if net.ParseIP(ip) == nil || !validSNI(sni) {
			return SNIPathPlan{}, fmt.Errorf("invalid SNI path identity %q/%q", ip, sni)
		}
		key := ip + "|" + sni
		if _, ok := seen[key]; ok {
			return SNIPathPlan{}, fmt.Errorf("duplicate SNI path %s", key)
		}
		seen[key] = struct{}{}
		if c.PayloadBytes < 0 || c.Successes < 0 || c.Failures < 0 || c.LatencyMs < 0 || c.LatencyMs > 120000 || c.ConsecutiveFailures < 0 || c.InFlight < 0 || c.Capacity < 0 {
			return SNIPathPlan{}, fmt.Errorf("invalid SNI path metrics for %s", key)
		}
		health := strings.ToLower(strings.TrimSpace(c.Health))
		if health == "" {
			health = "unknown"
		}
		if health != "unknown" && health != "healthy" && health != "degraded" && health != "unhealthy" {
			return SNIPathPlan{}, fmt.Errorf("invalid health for %s", key)
		}
		responseQualified := boolEvidence(c.FirstResponse) || c.PayloadBytes > 0
		tlsVerified := boolEvidence(c.TLSVerified)
		stale := !c.ObservedAt.IsZero() && asOf.Sub(c.ObservedAt) > time.Duration(maxAge)*time.Second
		capacityFull := c.Capacity > 0 && c.InFlight >= c.Capacity
		eligible := boolEvidence(c.TCPConnected) && responseQualified && tlsVerified && health != "unhealthy" && !stale && !capacityFull && c.ConsecutiveFailures < 3
		reason := ""
		switch {
		case !boolEvidence(c.TCPConnected):
			reason = "TCP reachability not proven"
		case !responseQualified:
			reason = "first response/payload not proven"
		case !tlsVerified:
			reason = "strict TLS trust not proven"
		case health == "unhealthy":
			reason = "health marked unhealthy"
		case stale:
			reason = "evidence stale"
		case capacityFull:
			reason = "capacity full"
		case c.ConsecutiveFailures >= 3:
			reason = "failure circuit threshold reached"
		}
		total := c.Successes + c.Failures
		successRate := 0.5
		if total > 0 {
			successRate = float64(c.Successes) / float64(total)
		}
		score := successRate*100 - c.LatencyMs/100 - float64(c.ConsecutiveFailures*8)
		if health == "degraded" {
			score -= 10
		}
		rank := SNIPathRank{IP: ip, SNI: sni, Eligible: eligible, ResponseQualified: responseQualified, TLSVerified: tlsVerified, Score: score, Reason: reason}
		if c.PathMTU != 0 {
			payload, err := RecommendMaxSegmentPayload(c.PathMTU, c.IPHeaderBytes, c.TCPHeaderBytes)
			if err != nil {
				return SNIPathPlan{}, fmt.Errorf("%s MTU evidence: %w", key, err)
			}
			rank.RecommendedMaxSegmentPayloadBytes = payload
		}
		if !eligible && c.PreviouslyActive {
			rank.Recommendation = "drain"
			rank.DrainUntil = asOf.Add(time.Duration(drainSeconds) * time.Second)
		} else if eligible {
			rank.Recommendation = "reserve"
		} else {
			rank.Recommendation = "excluded"
		}
		plan.Ranked = append(plan.Ranked, rank)
	}

	sort.SliceStable(plan.Ranked, func(i, j int) bool {
		if plan.Ranked[i].Eligible != plan.Ranked[j].Eligible {
			return plan.Ranked[i].Eligible
		}
		if plan.Ranked[i].Score != plan.Ranked[j].Score {
			return plan.Ranked[i].Score > plan.Ranked[j].Score
		}
		return plan.Ranked[i].IP+"|"+plan.Ranked[i].SNI < plan.Ranked[j].IP+"|"+plan.Ranked[j].SNI
	})
	active := 0
	for i := range plan.Ranked {
		r := &plan.Ranked[i]
		key := r.IP + "|" + r.SNI
		if r.Eligible && active < poolSize {
			r.Recommendation = "active"
			plan.Active = append(plan.Active, key)
			active++
		} else if r.Eligible {
			r.Recommendation = "reserve"
			plan.Reserve = append(plan.Reserve, key)
		} else if r.Recommendation == "drain" {
			plan.Drain = append(plan.Drain, key)
		}
	}
	return plan, nil
}
