package diagnostics

import (
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strings"
)

const maxDNSIntegrityAnswers = 64

type DNSTransportObservation struct {
	Reachable         bool     `json:"reachable"`
	Poisoned          bool     `json:"poisoned"`
	InjectionObserved bool     `json:"injection_observed"`
	Answers           []string `json:"answers,omitempty"`
	LatencyMs         float64  `json:"latency_ms,omitempty"`
	Error             string   `json:"error,omitempty"`
}

type DNSTransportIntegrityRequest struct {
	UDP DNSTransportObservation `json:"udp"`
	TCP DNSTransportObservation `json:"tcp"`
}

type DNSTransportIntegrityPlan struct {
	Verdict            string   `json:"verdict"`
	PreferredTransport string   `json:"preferred_transport"`
	AnswerSetsEqual    bool     `json:"answer_sets_equal"`
	PoisoningObserved  bool     `json:"poisoning_observed"`
	UDPAnswers         []string `json:"udp_answers,omitempty"`
	TCPAnswers         []string `json:"tcp_answers,omitempty"`
	Evidence           []string `json:"evidence"`
	SafetyBoundary     string   `json:"safety_boundary"`
}

func BuildDNSTransportIntegrityPlan(req DNSTransportIntegrityRequest) (DNSTransportIntegrityPlan, error) {
	udpAnswers, err := normalizeDNSIntegrityObservation("udp", req.UDP)
	if err != nil {
		return DNSTransportIntegrityPlan{}, err
	}
	tcpAnswers, err := normalizeDNSIntegrityObservation("tcp", req.TCP)
	if err != nil {
		return DNSTransportIntegrityPlan{}, err
	}
	plan := DNSTransportIntegrityPlan{
		PreferredTransport: "none", UDPAnswers: udpAnswers, TCPAnswers: tcpAnswers,
		PoisoningObserved: req.UDP.Poisoned || req.UDP.InjectionObserved || req.TCP.Poisoned || req.TCP.InjectionObserved,
		SafetyBoundary:    "read-only comparison; answer disagreement alone is not poisoning evidence",
	}
	plan.AnswerSetsEqual = equalStringSlices(udpAnswers, tcpAnswers)
	udpBad := req.UDP.Poisoned || req.UDP.InjectionObserved
	tcpBad := req.TCP.Poisoned || req.TCP.InjectionObserved
	switch {
	case !req.UDP.Reachable && !req.TCP.Reachable:
		plan.Verdict = "unavailable"
		plan.Evidence = append(plan.Evidence, "neither UDP nor TCP produced usable DNS evidence")
	case req.UDP.Reachable && !req.TCP.Reachable:
		if udpBad {
			plan.Verdict = "udp-only-poisoned"
		} else {
			plan.Verdict = "udp-only"
			plan.PreferredTransport = "udp"
		}
		plan.Evidence = append(plan.Evidence, "only UDP DNS was reachable")
	case !req.UDP.Reachable && req.TCP.Reachable:
		if tcpBad {
			plan.Verdict = "tcp-only-poisoned"
		} else {
			plan.Verdict = "tcp-only"
			plan.PreferredTransport = "tcp"
		}
		plan.Evidence = append(plan.Evidence, "only TCP DNS was reachable")
	case udpBad && tcpBad:
		plan.Verdict = "cross-transport-poisoning"
		plan.Evidence = append(plan.Evidence, "trusted poisoning/injection evidence exists on both DNS transports")
	case udpBad:
		if req.UDP.InjectionObserved {
			plan.Verdict = "udp-injection"
		} else {
			plan.Verdict = "udp-poisoning"
		}
		plan.PreferredTransport = "tcp"
		plan.Evidence = append(plan.Evidence, "UDP carries trusted poisoning/injection evidence while TCP does not")
	case tcpBad:
		if req.TCP.InjectionObserved {
			plan.Verdict = "tcp-injection"
		} else {
			plan.Verdict = "tcp-poisoning"
		}
		plan.PreferredTransport = "udp"
		plan.Evidence = append(plan.Evidence, "TCP carries trusted poisoning/injection evidence while UDP does not")
	default:
		if len(udpAnswers) == 0 && len(tcpAnswers) == 0 {
			plan.Verdict = "insufficient-evidence"
			plan.PreferredTransport = "none"
			plan.Evidence = append(plan.Evidence, "both DNS transports were reachable but produced no answer evidence; absence of evidence is not classified as clean")
			break
		}
		plan.PreferredTransport = lowerLatencyTransport(req.UDP.LatencyMs, req.TCP.LatencyMs)
		if plan.AnswerSetsEqual {
			plan.Verdict = "clean"
			plan.Evidence = append(plan.Evidence, "UDP and TCP returned the same normalized answer set without trusted poisoning evidence")
		} else {
			plan.Verdict = "answer-disagreement"
			plan.Evidence = append(plan.Evidence, "UDP and TCP answer sets differ; disagreement is not automatically classified as poisoning")
		}
	}
	return plan, nil
}

func normalizeDNSIntegrityObservation(label string, observation DNSTransportObservation) ([]string, error) {
	if len(observation.Answers) > maxDNSIntegrityAnswers {
		return nil, fmt.Errorf("%s answers exceed %d-entry limit", label, maxDNSIntegrityAnswers)
	}
	if math.IsNaN(observation.LatencyMs) || math.IsInf(observation.LatencyMs, 0) || observation.LatencyMs < 0 || observation.LatencyMs > 600000 {
		return nil, fmt.Errorf("%s latency is invalid", label)
	}
	if len(observation.Error) > 512 {
		return nil, fmt.Errorf("%s error detail exceeds 512-byte limit", label)
	}
	if !observation.Reachable && len(observation.Answers) > 0 {
		return nil, fmt.Errorf("%s has answers while marked unreachable", label)
	}
	seen := make(map[string]struct{}, len(observation.Answers))
	out := make([]string, 0, len(observation.Answers))
	for _, raw := range observation.Answers {
		addr, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("%s contains invalid IP answer", label)
		}
		addr = addr.Unmap()
		value := addr.String()
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func lowerLatencyTransport(udp, tcp float64) string {
	if tcp > 0 && (udp == 0 || tcp < udp) {
		return "tcp"
	}
	return "udp"
}
