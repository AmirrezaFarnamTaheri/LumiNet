package jobs

import (
	"testing"
	"time"

	"github.com/maybeknott/luminet/internal/analysis/diagnostics"
)

func TestBuildDiagnosticPlanPreservesSingleMetricContract(t *testing.T) {
	t.Parallel()

	plan, single, err := buildDiagnosticPlan(DiagnosticIntent{
		Type:    "sni_matrix",
		Target:  "104.16.124.96",
		Timeout: 30,
		Options: map[string]string{"fake_sni": "challenges.cloudflare.com"},
	})
	if err != nil {
		t.Fatalf("buildDiagnosticPlan() error = %v", err)
	}
	if !single {
		t.Fatal("buildDiagnosticPlan() single = false, want true")
	}
	if len(plan) != 1 {
		t.Fatalf("len(plan) = %d, want 1", len(plan))
	}
	phase := plan[0]
	if phase.metric != diagnostics.MetricSniMatrix {
		t.Fatalf("phase.metric = %q, want %q", phase.metric, diagnostics.MetricSniMatrix)
	}
	if phase.target != "104.16.124.96" {
		t.Fatalf("phase.target = %q", phase.target)
	}
	if phase.timeout != 30*time.Second {
		t.Fatalf("phase.timeout = %v, want 30s", phase.timeout)
	}
	if phase.options["fake_sni"] != "challenges.cloudflare.com" {
		t.Fatalf("fake_sni = %q", phase.options["fake_sni"])
	}
}

func TestBuildDiagnosticPlanUsesFullPlanOnlyWhenRequested(t *testing.T) {
	t.Parallel()

	plan, single, err := buildDiagnosticPlan(DiagnosticIntent{Type: "full"})
	if err != nil {
		t.Fatalf("buildDiagnosticPlan() error = %v", err)
	}
	if single {
		t.Fatal("buildDiagnosticPlan() single = true, want false")
	}
	if len(plan) != 11 {
		t.Fatalf("len(plan) = %d, want 11", len(plan))
	}
}

func TestBuildDiagnosticPlanRejectsUnknownMetric(t *testing.T) {
	t.Parallel()

	if _, _, err := buildDiagnosticPlan(DiagnosticIntent{Type: "not-a-diagnostic"}); err == nil {
		t.Fatal("buildDiagnosticPlan() accepted an unknown diagnostic type")
	}
}
