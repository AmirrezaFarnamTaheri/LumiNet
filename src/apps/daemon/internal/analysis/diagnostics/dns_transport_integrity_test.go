package diagnostics

import "testing"

func dnsPath(reachable, poisoned, injected bool, answers ...string) DNSTransportObservation {
	return DNSTransportObservation{Reachable: reachable, Poisoned: poisoned, InjectionObserved: injected, Answers: answers, LatencyMs: 20}
}

func TestDNSTransportIntegrityVerdicts(t *testing.T) {
	cases := []struct {
		name               string
		req                DNSTransportIntegrityRequest
		verdict, preferred string
	}{
		{"clean same", DNSTransportIntegrityRequest{UDP: dnsPath(true, false, false, "1.1.1.1"), TCP: dnsPath(true, false, false, "1.1.1.1")}, "clean", "udp"},
		{"clean disagreement", DNSTransportIntegrityRequest{UDP: dnsPath(true, false, false, "1.1.1.1"), TCP: dnsPath(true, false, false, "1.0.0.1")}, "answer-disagreement", "udp"},
		{"udp injected", DNSTransportIntegrityRequest{UDP: dnsPath(true, false, true, "203.0.113.9"), TCP: dnsPath(true, false, false, "1.1.1.1")}, "udp-injection", "tcp"},
		{"tcp poisoned", DNSTransportIntegrityRequest{UDP: dnsPath(true, false, false, "1.1.1.1"), TCP: dnsPath(true, true, false, "203.0.113.8")}, "tcp-poisoning", "udp"},
		{"both poisoned", DNSTransportIntegrityRequest{UDP: dnsPath(true, true, false, "203.0.113.9"), TCP: dnsPath(true, true, false, "203.0.113.8")}, "cross-transport-poisoning", "none"},
		{"udp only", DNSTransportIntegrityRequest{UDP: dnsPath(true, false, false, "1.1.1.1"), TCP: dnsPath(false, false, false)}, "udp-only", "udp"},
		{"tcp only", DNSTransportIntegrityRequest{UDP: dnsPath(false, false, false), TCP: dnsPath(true, false, false, "1.1.1.1")}, "tcp-only", "tcp"},
		{"unavailable", DNSTransportIntegrityRequest{UDP: dnsPath(false, false, false), TCP: dnsPath(false, false, false)}, "unavailable", "none"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := BuildDNSTransportIntegrityPlan(tc.req)
			if err != nil {
				t.Fatal(err)
			}
			if p.Verdict != tc.verdict || p.PreferredTransport != tc.preferred {
				t.Fatalf("plan=%+v", p)
			}
		})
	}
}

func TestDNSTransportIntegrityDoesNotInferPoisoningFromDifferentCleanAnswers(t *testing.T) {
	p, err := BuildDNSTransportIntegrityPlan(DNSTransportIntegrityRequest{UDP: dnsPath(true, false, false, "1.1.1.1", "1.0.0.1"), TCP: dnsPath(true, false, false, "1.0.0.1", "1.1.1.1")})
	if err != nil {
		t.Fatal(err)
	}
	if !p.AnswerSetsEqual || p.Verdict != "clean" {
		t.Fatalf("normalization failed: %+v", p)
	}
	p, err = BuildDNSTransportIntegrityPlan(DNSTransportIntegrityRequest{UDP: dnsPath(true, false, false, "1.1.1.1"), TCP: dnsPath(true, false, false, "1.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	if p.Verdict != "answer-disagreement" || p.PoisoningObserved {
		t.Fatalf("difference was overclaimed: %+v", p)
	}
}

func TestDNSTransportIntegrityBoundsAndValidatesEvidence(t *testing.T) {
	tooMany := make([]string, maxDNSIntegrityAnswers+1)
	for i := range tooMany {
		tooMany[i] = "1.1.1.1"
	}
	if _, err := BuildDNSTransportIntegrityPlan(DNSTransportIntegrityRequest{UDP: DNSTransportObservation{Reachable: true, Answers: tooMany}, TCP: dnsPath(true, false, false)}); err == nil {
		t.Fatal("answer bound not enforced")
	}
	if _, err := BuildDNSTransportIntegrityPlan(DNSTransportIntegrityRequest{UDP: dnsPath(true, false, false, "not-an-ip"), TCP: dnsPath(true, false, false)}); err == nil {
		t.Fatal("invalid IP accepted")
	}
	if _, err := BuildDNSTransportIntegrityPlan(DNSTransportIntegrityRequest{UDP: DNSTransportObservation{Reachable: true, LatencyMs: -1}, TCP: dnsPath(true, false, false)}); err == nil {
		t.Fatal("negative latency accepted")
	}
}

func TestDNSTransportIntegrityEmptyReachableEvidenceIsNotClean(t *testing.T) {
	p, err := BuildDNSTransportIntegrityPlan(DNSTransportIntegrityRequest{
		UDP: DNSTransportObservation{Reachable: true},
		TCP: DNSTransportObservation{Reachable: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.Verdict != "insufficient-evidence" || p.PreferredTransport != "none" {
		t.Fatalf("absence of DNS answer evidence must not become clean: %+v", p)
	}
}
