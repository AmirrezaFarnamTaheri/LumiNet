package tlsdecoy

import (
	"bytes"
	"testing"
	"time"
)

func TestCombinedBypassPlanner_Plan(t *testing.T) {
	planner := NewCombinedBypassPlanner()

	realHello := []byte("123456789012345678901234567890123456789012345678901234567890")
	fakeHello := []byte("FAKE_CLIENT_HELLO_SNI")

	cfg := DefaultCombinedBypassConfig()
	cfg.TTLHops = 3
	cfg.FragmentDelayMs = 12

	plan, err := planner.Plan(realHello, fakeHello, cfg)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}

	if plan.DecoyProbe == nil {
		t.Fatalf("Expected DecoyProbe to be present")
	}
	if plan.DecoyProbe.TTL != 3 {
		t.Errorf("Expected TTL 3, got %d", plan.DecoyProbe.TTL)
	}
	if !bytes.Equal(plan.DecoyProbe.Payload, fakeHello) {
		t.Errorf("Decoy payload mismatch")
	}

	if len(plan.Fragments) < 2 {
		t.Fatalf("Expected at least 2 fragments, got %d", len(plan.Fragments))
	}
	if plan.Fragments[0].DelayMs != 0 {
		t.Errorf("First fragment delay must be 0, got %d", plan.Fragments[0].DelayMs)
	}
	if plan.Fragments[1].DelayMs != 12 {
		t.Errorf("Second fragment delay must be 12, got %d", plan.Fragments[1].DelayMs)
	}

	reconstructed := ReconstructPayload(plan)
	if !bytes.Equal(reconstructed, realHello) {
		t.Errorf("Reconstructed payload does not match original realHello")
	}
}

func TestCombinedBypassPlanner_NoDecoy(t *testing.T) {
	planner := NewCombinedBypassPlanner()
	realHello := []byte("test_tls_client_hello")

	cfg := CombinedBypassConfig{
		Mode:             BypassModeSniFragment,
		UseTTLTrick:      false,
		FragmentStrategy: "half",
		FragmentDelayMs:  5,
	}

	plan, err := planner.Plan(realHello, nil, cfg)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}

	if plan.DecoyProbe != nil {
		t.Errorf("Decoy probe should be nil when UseTTLTrick is false and mode is SniFragment")
	}
	if len(plan.Fragments) != 2 {
		t.Errorf("Expected 2 fragments, got %d", len(plan.Fragments))
	}
}

func TestDomainBypassEvaluator_SelectOptimalMode(t *testing.T) {
	evaluator := &DomainBypassEvaluator{}

	results := []DomainEvaluationResult{
		{
			Domain:    "youtube.com",
			Mode:      BypassModeDirect,
			Success:   false,
			LatencyMs: 4000,
			TestedAt:  time.Now(),
		},
		{
			Domain:    "youtube.com",
			Mode:      BypassModeSniFragment,
			Success:   false,
			LatencyMs: 3500,
			TestedAt:  time.Now(),
		},
		{
			Domain:    "youtube.com",
			Mode:      BypassModeCombinedTtlDecoy,
			Success:   true,
			LatencyMs: 150,
			TestedAt:  time.Now(),
		},
	}

	mode, ok := evaluator.SelectOptimalMode(results)
	if !ok {
		t.Fatalf("Expected optimal mode to be found")
	}
	if mode != BypassModeCombinedTtlDecoy {
		t.Errorf("Expected CombinedTtlDecoy, got %s", mode)
	}

	// Now add a successful SniFragment which has higher priority
	results = append(results, DomainEvaluationResult{
		Domain:    "youtube.com",
		Mode:      BypassModeSniFragment,
		Success:   true,
		LatencyMs: 110,
		TestedAt:  time.Now(),
	})

	mode2, ok2 := evaluator.SelectOptimalMode(results)
	if !ok2 || mode2 != BypassModeSniFragment {
		t.Errorf("Expected SniFragment to be preferred over CombinedTtlDecoy, got %s", mode2)
	}
}
