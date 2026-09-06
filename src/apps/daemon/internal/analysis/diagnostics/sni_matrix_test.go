package diagnostics

import (
	"context"
	"testing"
	"time"
)

func TestDiagnostics_SniMatrix(t *testing.T) {
	pipeline := NewPipeline()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Target 127.0.0.1 (fails fast because port is likely closed or filtered)
	job := &DiagnosticJob{
		Type:    MetricSniMatrix,
		Target:  "127.0.0.1",
		Timeout: 3 * time.Second,
		Options: map[string]string{
			"fake_sni": "challenges.cloudflare.com",
		},
	}

	result, err := pipeline.Run(ctx, job)
	if err != nil {
		t.Fatalf("Failed to run SniMatrix diagnostic: %v", err)
	}

	// It should return the populated results list
	results, ok := result.Metrics["results"].([]MatrixResult)
	if !ok {
		t.Fatalf("Expected results list to be populated in Metrics")
	}

	if len(results) == 0 {
		t.Error("Expected at least one matrix test case result")
	}

	for _, r := range results {
		if r.FakeRepeat != 1 || r.FakeRepeatApplied {
			t.Fatalf("matrix must not manufacture fake-repeat evidence: %+v", r)
		}
	}

	// Verify that each case has proper parameters populated
	for _, r := range results {
		if r.UTLS == "" {
			t.Error("Expected UTLS name to be populated")
		}
		if r.FakeRepeat <= 0 {
			t.Error("Expected positive FakeRepeat value")
		}
	}
}
