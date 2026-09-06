package netutil

import "testing"

func TestRatePolicyNormalization(t *testing.T) {
	policy, err := (RatePolicy{BytesPerSecond: 100}).Normalize()
	if err != nil || policy.BurstBytes != 100 {
		t.Fatalf("Normalize() = %+v, %v", policy, err)
	}
	if _, err := (RatePolicy{}).Normalize(); err == nil {
		t.Fatal("expected invalid zero rate")
	}
}
