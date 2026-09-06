package diagnostics

import "testing"

func coherentSNIDecoyRequest() SNIDecoyHandshakePlanRequest {
	return SNIDecoyHandshakePlanRequest{
		SYNSeen: true, SYNSeq: 1000,
		SYNACKSeen: true, SYNACKAck: 1001, ServerSeq: 7000,
		ThirdACKSeen: true, ThirdACKSeq: 1001, ThirdACKAck: 7001,
		FakePayloadBytes: 517,
	}
}

func TestSNIDecoyHandshakePlanRequiresCoherentThreeWayHandshake(t *testing.T) {
	req := coherentSNIDecoyRequest()
	plan, err := BuildSNIDecoyHandshakePlan(req)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.ReadyToInject || plan.ReadyToRelay || plan.State != "ready-to-inject" {
		t.Fatalf("unexpected plan: %+v", plan)
	}
	if plan.ExpectedFakeSeq != 484 || plan.ExpectedRealSeq != 1001 || plan.ExpectedThirdACK != 7001 {
		t.Fatalf("unexpected sequence evidence: %+v", plan)
	}

	req.ThirdACKAck = 7002
	plan, err = BuildSNIDecoyHandshakePlan(req)
	if err != nil {
		t.Fatal(err)
	}
	if plan.ReadyToInject || plan.State != "invalid-third-ack" {
		t.Fatalf("mismatched ACK must fail closed: %+v", plan)
	}
}

func TestSNIDecoyHandshakePlanRequiresServerConfirmationBeforeRelay(t *testing.T) {
	req := coherentSNIDecoyRequest()
	req.FakeInjected = true
	plan, err := BuildSNIDecoyHandshakePlan(req)
	if err != nil {
		t.Fatal(err)
	}
	if plan.ReadyToRelay || plan.State != "awaiting-server-confirmation" {
		t.Fatalf("relay must wait for confirmation: %+v", plan)
	}

	req.ServerACKSeen = true
	req.ServerACK = 1001
	plan, err = BuildSNIDecoyHandshakePlan(req)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.ReadyToRelay || plan.State != "fake-confirmed" || plan.PerformsNetworkIO {
		t.Fatalf("unexpected confirmation: %+v", plan)
	}
}

func TestSNIDecoyHandshakePlanRSTAndBoundsFailClosed(t *testing.T) {
	req := coherentSNIDecoyRequest()
	req.RSTSeen = true
	plan, err := BuildSNIDecoyHandshakePlan(req)
	if err != nil {
		t.Fatal(err)
	}
	if plan.State != "failed-rst" || plan.ReadyToInject || plan.ReadyToRelay {
		t.Fatalf("RST did not fail closed: %+v", plan)
	}

	req = coherentSNIDecoyRequest()
	req.FakePayloadBytes = 0
	if _, err := BuildSNIDecoyHandshakePlan(req); err == nil {
		t.Fatal("zero fake payload must be rejected")
	}
	req.FakePayloadBytes = maxSNIDecoyPayloadBytes + 1
	if _, err := BuildSNIDecoyHandshakePlan(req); err == nil {
		t.Fatal("oversized fake payload must be rejected")
	}
}
