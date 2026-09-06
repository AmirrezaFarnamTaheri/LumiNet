package relayclient

import (
	"testing"
	"time"
)

func TestIsLikelyNonBatchRelayPayload(t *testing.T) {
	// HTML doctype / tags
	if !IsLikelyNonBatchRelayPayload([]byte("<!DOCTYPE html><html><body>Error</body></html>")) {
		t.Errorf("expected HTML doctype to be classified as non-batch")
	}
	if !IsLikelyNonBatchRelayPayload([]byte("<html>Error</html>")) {
		t.Errorf("expected HTML tag to be classified as non-batch")
	}

	// JSON object / array
	if !IsLikelyNonBatchRelayPayload([]byte("{\"error\": \"not_found\"}")) {
		t.Errorf("expected JSON object to be classified as non-batch")
	}

	// Code.gs sentinels
	if !IsLikelyNonBatchRelayPayload([]byte("Exception: Service invoked too many times")) {
		t.Errorf("expected Exception sentinel to be classified as non-batch")
	}
	if !IsLikelyNonBatchRelayPayload([]byte("relay_loop_detected: invalid upstream")) {
		t.Errorf("expected loop sentinel to be classified as non-batch")
	}

	// Valid base64 payload should not be flagged
	if IsLikelyNonBatchRelayPayload([]byte("dGVzdF9iYXNlNjRfcGF5bG9hZA==")) {
		t.Errorf("expected valid base64 payload not to be flagged as non-batch")
	}
}

func TestClassifyRelayErrorBody(t *testing.T) {
	// Quota exhaustion
	quotaBody := []byte("Service invoked too many times for one day: urlfetch.")
	reason, hard := ClassifyRelayErrorBody(quotaBody)
	if !hard || reason == "" {
		t.Errorf("expected hard quota error, got hard=%v, reason=%s", hard, reason)
	}

	// Auth error
	authBody := []byte("Authorization is required to perform that action.")
	reason, hard = ClassifyRelayErrorBody(authBody)
	if !hard || reason == "" {
		t.Errorf("expected hard auth error, got hard=%v, reason=%s", hard, reason)
	}

	// Deployment not found
	notFoundBody := []byte("Error code Not_Found: script deployment does not exist")
	reason, hard = ClassifyRelayErrorBody(notFoundBody)
	if !hard || reason == "" {
		t.Errorf("expected hard deployment not found error, got hard=%v, reason=%s", hard, reason)
	}

	// Transient server error
	transientBody := []byte("Server error occurred, please try again.")
	reason, hard = ClassifyRelayErrorBody(transientBody)
	if hard || reason == "" {
		t.Errorf("expected soft transient error, got hard=%v, reason=%s", hard, reason)
	}
}

func TestClassifiedEndpointBackoff(t *testing.T) {
	// Hard error gets at least QuotaBackoffFloor (5 min)
	b1 := ClassifiedEndpointBackoff(200, true, 0)
	if b1 < QuotaBackoffFloor {
		t.Errorf("expected at least QuotaBackoffFloor (5m), got %v", b1)
	}

	// 429 Rate limit gets at least RateLimitBackoffFloor (24s)
	b2 := ClassifiedEndpointBackoff(429, false, 0)
	if b2 < RateLimitBackoffFloor {
		t.Errorf("expected at least RateLimitBackoffFloor (24s), got %v", b2)
	}

	// Transient soft error starts at TransientBackoffInitial (3s)
	b3 := ClassifiedEndpointBackoff(500, false, 0)
	if b3 != TransientBackoffInitial {
		t.Errorf("expected initial 3s backoff, got %v", b3)
	}

	// Ramping transient error doubles
	b4 := ClassifiedEndpointBackoff(500, false, 3*time.Second)
	if b4 != 6*time.Second {
		t.Errorf("expected 6s backoff, got %v", b4)
	}
}
