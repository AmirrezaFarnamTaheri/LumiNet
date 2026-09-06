package sub

import (
	"math"
	"time"
)

const (
	profileEntitlementExpiryWarning = 72 * time.Hour
	profileEntitlementQuotaWarning  = 10.0
)

// ProfileEntitlement is a derived, non-authoritative operator projection over
// provider-reported subscription metadata. It must never be used to grant,
// revoke, or meter connectivity: remote metadata can be stale, missing, or
// provider-specific. Its purpose is to make quota and expiry evidence explicit
// and consistent across API and UI surfaces.
type ProfileEntitlement struct {
	Status             string   `json:"status"`
	QuotaKnown         bool     `json:"quota_known"`
	ExpiryKnown        bool     `json:"expiry_known"`
	UsedBytes          int64    `json:"used_bytes"`
	RemainingBytes     int64    `json:"remaining_bytes"`
	UsagePercent       float64  `json:"usage_percent"`
	SecondsUntilExpiry int64    `json:"seconds_until_expiry,omitempty"`
	SecondsUntilRefill int64    `json:"seconds_until_refill,omitempty"`
	Warnings           []string `json:"warnings,omitempty"`
}

// EvaluateProfileEntitlement derives advisory quota/expiry health at one
// explicit instant so callers can render a coherent snapshot.
func EvaluateProfileEntitlement(info *ProfileInfo, now time.Time) ProfileEntitlement {
	result := ProfileEntitlement{Status: "unknown"}
	if info == nil {
		return result
	}
	if now.IsZero() {
		now = time.Now()
	}

	used := saturatingProviderUsage(info.Upload, info.Download)
	result.UsedBytes = used

	if info.Total > 0 {
		result.QuotaKnown = true
		remaining := info.Total - used
		if remaining < 0 {
			remaining = 0
		}
		result.RemainingBytes = remaining
		result.UsagePercent = float64(used) / float64(info.Total) * 100
		if result.UsagePercent > 100 {
			result.UsagePercent = 100
		}
		if remaining == 0 {
			result.Warnings = append(result.Warnings, "quota_exhausted")
		} else if 100-result.UsagePercent <= profileEntitlementQuotaWarning {
			result.Warnings = append(result.Warnings, "quota_low")
		}
	}

	if !info.Expire.IsZero() {
		result.ExpiryKnown = true
		untilExpiry := info.Expire.Sub(now)
		if untilExpiry <= 0 {
			result.Warnings = append(result.Warnings, "expired")
		} else {
			result.SecondsUntilExpiry = int64(untilExpiry / time.Second)
			if untilExpiry <= profileEntitlementExpiryWarning {
				result.Warnings = append(result.Warnings, "expires_soon")
			}
		}
	}

	if !info.RefillDate.IsZero() {
		untilRefill := info.RefillDate.Sub(now)
		if untilRefill > 0 {
			result.SecondsUntilRefill = int64(untilRefill / time.Second)
		}
	}

	switch {
	case result.ExpiryKnown && !info.Expire.After(now):
		result.Status = "expired"
	case result.QuotaKnown && result.RemainingBytes == 0:
		result.Status = "exhausted"
	case len(result.Warnings) > 0:
		result.Status = "warning"
	case result.QuotaKnown || result.ExpiryKnown:
		result.Status = "active"
	default:
		result.Status = "unknown"
	}
	return result
}

// saturatingProviderUsage treats malformed negative provider counters as zero
// and saturates addition so hostile or corrupt metadata cannot wrap int64 and
// make heavy usage appear as zero.
func saturatingProviderUsage(upload, download int64) int64 {
	if upload < 0 {
		upload = 0
	}
	if download < 0 {
		download = 0
	}
	if download > math.MaxInt64-upload {
		return math.MaxInt64
	}
	return upload + download
}
