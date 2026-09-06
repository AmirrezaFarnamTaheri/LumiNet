package relayclient

import (
	"bytes"
	"strings"
	"time"
)

// Backoff constants for classified relay endpoint errors.
const (
	TransientBackoffInitial = 3 * time.Second
	RateLimitBackoffFloor   = 24 * time.Second
	QuotaBackoffFloor       = 5 * time.Minute
	LocalOfflineBlacklistTTL = 15 * time.Second
)

// IsLikelyNonBatchRelayPayload checks whether the response body cannot be a valid
// base64 AES-GCM sealed batch envelope, allowing early detection of HTML error pages
// or plain-text sentinels without expensive decryption attempts.
func IsLikelyNonBatchRelayPayload(body []byte) bool {
	t := bytes.TrimSpace(body)
	if len(t) == 0 {
		return false
	}
	l := bytes.ToLower(t)
	if bytes.HasPrefix(l, []byte("<!doctype")) || bytes.HasPrefix(l, []byte("<html")) {
		return true
	}
	if t[0] == '{' || t[0] == '[' || bytes.HasPrefix(t, []byte("HTTP/")) {
		return true
	}
	// Legacy and current Code.gs error sentinels
	if bytes.HasPrefix(t, []byte("Exception:")) ||
		bytes.HasPrefix(t, []byte("relay_loop_detected:")) ||
		bytes.HasPrefix(t, []byte("upstream status ")) ||
		bytes.HasPrefix(t, []byte("upstream fetch error:")) {
		return true
	}
	return false
}

// ClassifyRelayErrorBody inspects a non-batch response body (HTML or JSON error
// page returned by Apps Script instead of an encrypted payload) and returns a
// human-readable explanation and whether the failure is "hard" (quota / auth /
// admin — will not self-heal quickly) or "soft" (transient Google-side error).
func ClassifyRelayErrorBody(body []byte) (reason string, hard bool) {
	trimmed := bytes.TrimSpace(body)
	lower := strings.ToLower(string(trimmed))

	// 1. Code.gs sentinels
	if bytes.HasPrefix(trimmed, []byte("relay_loop_detected:")) {
		return "Code.gs RELAY_URLS points at script.google.com — set it to your VPS endpoint and redeploy", true
	}
	if bytes.HasPrefix(trimmed, []byte("upstream fetch error:")) || bytes.HasPrefix(trimmed, []byte("Exception:")) {
		return "Code.gs could not reach VPS endpoint — check VPS firewall and routing", false
	}
	if bytes.HasPrefix(trimmed, []byte("upstream status ")) {
		return "VPS returned a non-200 status to Apps Script forwarder", false
	}

	// 2. Quota / rate-limit
	quotaPatterns := []string{
		"service invoked too many times",
		"invoked too many times",
		"bandwidth quota exceeded",
		"too much upload bandwidth",
		"too much traffic",
		"urlfetch",
		"quota",
		"exceeded",
		"daily",
		"rate limit",
	}
	for _, p := range quotaPatterns {
		if strings.Contains(lower, p) {
			return "Apps Script quota exhausted (20k requests/day limit) — wait for midnight Pacific reset or add secondary account", true
		}
	}

	// 3. Auth / permission
	authPatterns := []string{
		"authorization is required",
		"unauthorized",
		"not authorized",
		"permission denied",
		"access denied",
	}
	for _, p := range authPatterns {
		if strings.Contains(lower, p) {
			return "Apps Script auth error — verify script execution access and account authorizations", true
		}
	}

	// 4. Deployment not found
	deployPatterns := []string{
		"error code not_found",
		"not_found",
		"deployment",
		"script id",
		"scriptid",
		"no script",
	}
	for _, p := range deployPatterns {
		if strings.Contains(lower, p) {
			return "Apps Script deployment not found — verify deployment ID is active and up to date", true
		}
	}

	// 5. Admin / Workspace policy
	adminPatterns := []string{
		"not permitted by your admin",
		"contact your administrator",
		"disabled. please contact",
		"domain policy has disabled",
		"administrator to enable",
	}
	for _, p := range adminPatterns {
		if strings.Contains(lower, p) {
			return "Apps Script blocked by Google Workspace domain administration policy", true
		}
	}

	// 6. Transient Google-side errors
	transientPatterns := []string{
		"server not available",
		"server error occurred",
		"please try again",
		"temporarily unavailable",
	}
	for _, p := range transientPatterns {
		if strings.Contains(lower, p) {
			return "Google Apps Script server temporarily unavailable — will retry", false
		}
	}

	return "", false
}

// ClassifiedEndpointBackoff calculates the backoff duration for an endpoint failure.
func ClassifiedEndpointBackoff(statusCode int, hard bool, currentBackoff time.Duration) time.Duration {
	if hard {
		if currentBackoff < QuotaBackoffFloor {
			return QuotaBackoffFloor
		}
		return currentBackoff
	}

	if statusCode == 429 {
		if currentBackoff < RateLimitBackoffFloor {
			return RateLimitBackoffFloor
		}
		return currentBackoff * 2
	}

	if currentBackoff == 0 {
		return TransientBackoffInitial
	}
	next := currentBackoff * 2
	if next > 30*time.Second {
		next = 30 * time.Second
	}
	return next
}
