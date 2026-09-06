package sub

import (
	"math"
	"slices"
	"testing"
	"time"
)

func TestEvaluateProfileEntitlementUnknownWithoutMetadata(t *testing.T) {
	got := EvaluateProfileEntitlement(nil, time.Unix(1_700_000_000, 0))
	if got.Status != "unknown" || got.QuotaKnown || got.ExpiryKnown || len(got.Warnings) != 0 {
		t.Fatalf("unexpected unknown entitlement: %+v", got)
	}
}

func TestEvaluateProfileEntitlementActive(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	got := EvaluateProfileEntitlement(&ProfileInfo{
		Upload:   100,
		Download: 200,
		Total:    1000,
		Expire:   now.Add(7 * 24 * time.Hour),
	}, now)
	if got.Status != "active" || got.UsedBytes != 300 || got.RemainingBytes != 700 {
		t.Fatalf("unexpected active entitlement: %+v", got)
	}
	if math.Abs(got.UsagePercent-30) > 0.0001 || got.SecondsUntilExpiry != int64((7*24*time.Hour)/time.Second) {
		t.Fatalf("unexpected percentages/timing: %+v", got)
	}
}

func TestEvaluateProfileEntitlementWarningsAndPrecedence(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	warning := EvaluateProfileEntitlement(&ProfileInfo{
		Upload:   450,
		Download: 460,
		Total:    1000,
		Expire:   now.Add(24 * time.Hour),
	}, now)
	if warning.Status != "warning" || !slices.Contains(warning.Warnings, "quota_low") || !slices.Contains(warning.Warnings, "expires_soon") {
		t.Fatalf("expected quota and expiry warnings: %+v", warning)
	}

	exhausted := EvaluateProfileEntitlement(&ProfileInfo{
		Download: 1200,
		Total:    1000,
		Expire:   now.Add(24 * time.Hour),
	}, now)
	if exhausted.Status != "exhausted" || exhausted.RemainingBytes != 0 || exhausted.UsagePercent != 100 {
		t.Fatalf("unexpected exhausted entitlement: %+v", exhausted)
	}

	expired := EvaluateProfileEntitlement(&ProfileInfo{
		Download: 1200,
		Total:    1000,
		Expire:   now.Add(-time.Minute),
	}, now)
	if expired.Status != "expired" || !slices.Contains(expired.Warnings, "expired") {
		t.Fatalf("expiry must take precedence over quota exhaustion: %+v", expired)
	}
}

func TestEvaluateProfileEntitlementUnlimitedQuotaAndRefill(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	got := EvaluateProfileEntitlement(&ProfileInfo{
		Upload:     1000,
		Download:   2000,
		Total:      0,
		RefillDate: now.Add(2 * time.Hour),
	}, now)
	if got.QuotaKnown || got.Status != "unknown" || got.SecondsUntilRefill != int64((2*time.Hour)/time.Second) {
		t.Fatalf("quota/expiry authority must remain unknown when only refill metadata is reported: %+v", got)
	}
}

func TestEvaluateProfileEntitlementSaturatesMalformedProviderCounters(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	got := EvaluateProfileEntitlement(&ProfileInfo{
		Upload:   math.MaxInt64,
		Download: math.MaxInt64,
		Total:    1000,
	}, now)
	if got.UsedBytes != math.MaxInt64 || got.Status != "exhausted" || got.UsagePercent != 100 {
		t.Fatalf("overflowing provider counters must saturate, got %+v", got)
	}

	negative := EvaluateProfileEntitlement(&ProfileInfo{Upload: -500, Download: 250, Total: 1000}, now)
	if negative.UsedBytes != 250 || negative.RemainingBytes != 750 {
		t.Fatalf("negative provider counter must not cancel valid usage, got %+v", negative)
	}
}
