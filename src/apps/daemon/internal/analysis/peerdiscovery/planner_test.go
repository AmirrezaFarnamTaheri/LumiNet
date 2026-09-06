package peerdiscovery

import (
	"bytes"
	"net/netip"
	"testing"
)

func testID(t *testing.T, ip string, random byte, fill byte) string {
	t.Helper()
	id, err := GenerateIPv4NodeID(netip.MustParseAddr(ip), random, bytes.NewReader(bytes.Repeat([]byte{fill}, 17)))
	if err != nil {
		t.Fatal(err)
	}
	return id.String()
}

func TestBuildPlanAdmitsPublicBEP42PeersAndSortsByDistance(t *testing.T) {
	local := testID(t, "1.1.1.1", 1, 0x11)
	first := testID(t, "8.8.8.8", 2, 0x22)
	second := testID(t, "9.9.9.9", 3, 0x33)
	plan, err := BuildPlan(PlanRequest{
		LocalNodeID: local,
		Candidates: []Candidate{
			{NodeID: second, Address: "9.9.9.9", Port: 443},
			{NodeID: first, Address: "8.8.8.8", Port: 8443},
		},
		MaxResults: 2,
	}, map[string]float64{first: 0.91})
	if err != nil {
		t.Fatal(err)
	}
	if plan.EligibleCount != 2 || plan.RejectedCount != 0 || len(plan.Accepted) != 2 {
		t.Fatalf("unexpected plan: %+v", plan)
	}
	if plan.Accepted[0].Distance > plan.Accepted[1].Distance {
		t.Fatalf("not sorted by XOR distance: %+v", plan.Accepted)
	}
	for _, peer := range plan.Accepted {
		if peer.NodeID == first && (!peer.TrustObserved || peer.TrustScore != 0.91) {
			t.Fatalf("observed trust not attached: %+v", peer)
		}
	}
}

func TestBuildPlanRejectsIdentityPolicyAndDuplicateFailuresIndividually(t *testing.T) {
	local := testID(t, "1.1.1.1", 1, 0x11)
	good := testID(t, "8.8.8.8", 2, 0x22)
	private := testID(t, "10.0.0.1", 3, 0x33)
	mismatch := testID(t, "9.9.9.9", 4, 0x44)
	plan, err := BuildPlan(PlanRequest{
		LocalNodeID: local,
		Candidates: []Candidate{
			{NodeID: good, Address: "8.8.8.8", Port: 443},
			{NodeID: good, Address: "8.8.4.4", Port: 443},
			{NodeID: private, Address: "10.0.0.1", Port: 443},
			{NodeID: mismatch, Address: "8.8.4.4", Port: 443},
			{NodeID: local, Address: "1.1.1.1", Port: 443},
			{NodeID: "bad", Address: "8.8.8.8", Port: 443},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.EligibleCount != 1 || plan.RejectedCount != 5 {
		t.Fatalf("unexpected counts: %+v", plan)
	}
	reasons := map[string]bool{}
	for _, rejection := range plan.Rejected {
		reasons[rejection.Reason] = true
	}
	for _, want := range []string{"duplicate-node-id", "non-public-address", "bep42-mismatch", "self", "invalid-node-id"} {
		if !reasons[want] {
			t.Fatalf("missing rejection reason %q in %+v", want, plan.Rejected)
		}
	}
}

func TestBuildPlanRejectsDocumentationIPv4AndBounds(t *testing.T) {
	local := testID(t, "1.1.1.1", 1, 0x11)
	doc := testID(t, "192.0.2.5", 2, 0x22)
	plan, err := BuildPlan(PlanRequest{
		LocalNodeID: local,
		Candidates:  []Candidate{{NodeID: doc, Address: "192.0.2.5", Port: 443}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Accepted) != 0 || len(plan.Rejected) != 1 || plan.Rejected[0].Reason != "non-public-address" {
		t.Fatalf("documentation address was not rejected: %+v", plan)
	}
	if _, err := BuildPlan(PlanRequest{LocalNodeID: local, Candidates: []Candidate{{NodeID: doc, Address: "192.0.2.5", Port: 443}}, MaxResults: MaxResults + 1}, nil); err == nil {
		t.Fatal("expected max_results bound error")
	}
}

func TestBuildPlanInvalidCandidateCannotPoisonLaterValidObservation(t *testing.T) {
	local := testID(t, "1.1.1.1", 1, 0x11)
	valid := testID(t, "8.8.8.8", 2, 0x22)
	invalidForAddress := testID(t, "9.9.9.9", 3, 0x33)
	plan, err := BuildPlan(PlanRequest{
		LocalNodeID: local,
		Candidates: []Candidate{
			{NodeID: invalidForAddress, Address: "8.8.8.8", Port: 443},
			{NodeID: valid, Address: "8.8.8.8", Port: 443},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Accepted) != 1 || plan.Accepted[0].NodeID != valid {
		t.Fatalf("invalid candidate poisoned later valid observation: %+v", plan)
	}
	if len(plan.Rejected) != 1 || plan.Rejected[0].Reason != "bep42-mismatch" {
		t.Fatalf("unexpected rejection evidence: %+v", plan.Rejected)
	}
}

func TestBuildPlanAppliesBoundedLocalCIDRBlocklist(t *testing.T) {
	local := testID(t, "1.1.1.1", 1, 0x11)
	blocked := testID(t, "8.8.8.8", 2, 0x22)
	allowed := testID(t, "9.9.9.9", 3, 0x33)
	plan, err := BuildPlan(PlanRequest{
		LocalNodeID:  local,
		BlockedCIDRs: []string{"8.8.8.0/24", "8.8.8.0/24"},
		Candidates: []Candidate{
			{NodeID: blocked, Address: "8.8.8.8", Port: 443},
			{NodeID: allowed, Address: "9.9.9.9", Port: 443},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.BlockedPrefixCount != 1 || len(plan.Accepted) != 1 || plan.Accepted[0].NodeID != allowed {
		t.Fatalf("unexpected local blocklist result: %+v", plan)
	}
	if len(plan.Rejected) != 1 || plan.Rejected[0].Reason != "blocked-address" {
		t.Fatalf("blocked candidate did not retain explicit rejection evidence: %+v", plan.Rejected)
	}
	if _, err := BuildPlan(PlanRequest{LocalNodeID: local, Candidates: []Candidate{{NodeID: allowed, Address: "9.9.9.9", Port: 443}}, BlockedCIDRs: []string{"not-a-cidr"}}, nil); err == nil {
		t.Fatal("expected invalid CIDR rejection")
	}
	tooMany := make([]string, MaxBlockedCIDRs+1)
	for i := range tooMany {
		tooMany[i] = "8.8.8.8/32"
	}
	if _, err := BuildPlan(PlanRequest{LocalNodeID: local, Candidates: []Candidate{{NodeID: allowed, Address: "9.9.9.9", Port: 443}}, BlockedCIDRs: tooMany}, nil); err == nil {
		t.Fatal("expected blocked CIDR count bound")
	}
}

func TestBuildPlanSharedPublicAddressIsEvidenceNotFalseRejection(t *testing.T) {
	local := testID(t, "1.1.1.1", 1, 0x11)
	first := testID(t, "8.8.8.8", 2, 0x22)
	second := testID(t, "8.8.8.8", 3, 0x33)
	plan, err := BuildPlan(PlanRequest{
		LocalNodeID: local,
		Candidates: []Candidate{
			{NodeID: first, Address: "8.8.8.8", Port: 443},
			{NodeID: second, Address: "8.8.8.8", Port: 8443},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Accepted) != 2 || len(plan.Rejected) != 0 {
		t.Fatalf("shared NAT address was treated as an identity failure: %+v", plan)
	}
	for _, peer := range plan.Accepted {
		if !peer.SharedAddressObserved || peer.SharedAddressCount != 2 {
			t.Fatalf("shared-address evidence missing: %+v", peer)
		}
	}
}
