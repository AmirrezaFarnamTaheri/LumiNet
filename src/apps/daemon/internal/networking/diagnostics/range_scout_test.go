package diagnostics

import (
	"testing"
	"time"
)

func TestScoutSubnetRange(t *testing.T) {
	cfg := RangeScoutConfig{
		CidrBlock:       "192.168.1.0/24",
		SampleCount:     8,
		Timeout:         200 * time.Millisecond,
		MaxRTTThreshold: 100 * time.Millisecond,
	}

	report, err := ScoutSubnetRange(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.TestedCount != 8 {
		t.Errorf("expected 8 tested targets, got %d", report.TestedCount)
	}
	if len(report.BestTargets) == 0 {
		t.Errorf("expected non-empty best targets")
	}
}

func TestScoutSubnetRangeInvalidCIDR(t *testing.T) {
	cfg := RangeScoutConfig{
		CidrBlock: "invalid-cidr",
	}
	_, err := ScoutSubnetRange(cfg)
	if err == nil {
		t.Errorf("expected error on invalid CIDR")
	}
}
