package safety

import (
	"fmt"
	"sync"
	"time"
)

const (
	DefaultWindowSeconds    int64 = 86400
	DefaultDailyMaxRequests int64 = 20000
)

// MaskScriptID masks an identifier to "first4...last4" for audit logging.
func MaskScriptID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return fmt.Sprintf("%s...%s", id[:4], id[len(id)-4:])
}

// AccountBucket tracks usage metrics for a specific endpoint or credentials.
type AccountBucket struct {
	MaskedID       string `json:"masked_id"`
	RequestsUsed   int64  `json:"requests_used"`
	FailedRequests int64  `json:"failed_requests"`
	BytesUp        int64  `json:"bytes_up"`
	BytesDown      int64  `json:"bytes_down"`
	BytesTotal     int64  `json:"bytes_total"`
	LastRequestAt  int64  `json:"last_request_at"`
	NextResetAt    int64  `json:"next_reset_at"`
	Exhausted      bool   `json:"exhausted"`
	Quarantined    bool   `json:"quarantined"`
}

// TokenBucketLimiter provides rate limiting using standard token bucket algorithm.
type TokenBucketLimiter struct {
	mu         sync.Mutex
	rate       float64 // tokens per second
	capacity   float64 // max burst capacity
	tokens     float64
	lastRefill time.Time
}

// NewTokenBucketLimiter creates a new token bucket rate limiter.
func NewTokenBucketLimiter(rate, capacity float64) *TokenBucketLimiter {
	return &TokenBucketLimiter{
		rate:       rate,
		capacity:   capacity,
		tokens:     capacity,
		lastRefill: time.Now(),
	}
}

// Allow checks if a single token is available and consumes it.
func (tb *TokenBucketLimiter) Allow() bool {
	return tb.Take(1)
}

// Take attempts to consume n tokens. Returns true if granted.
func (tb *TokenBucketLimiter) Take(n float64) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	tb.lastRefill = now

	tb.tokens += elapsed * tb.rate
	if tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}

	if tb.tokens >= n {
		tb.tokens -= n
		return true
	}
	return false
}

// MultiQuotaTracker manages rolling 24-hour quota limits across endpoints.
type MultiQuotaTracker struct {
	mu             sync.Mutex
	buckets        map[string]*AccountBucket
	windowDuration int64
	requestLimit   int64
}

// NewMultiQuotaTracker creates a multi-endpoint quota tracker.
func NewMultiQuotaTracker(windowSecs, requestLimit int64) *MultiQuotaTracker {
	if windowSecs <= 0 {
		windowSecs = DefaultWindowSeconds
	}
	if requestLimit <= 0 {
		requestLimit = DefaultDailyMaxRequests
	}
	return &MultiQuotaTracker{
		buckets:        make(map[string]*AccountBucket),
		windowDuration: windowSecs,
		requestLimit:   requestLimit,
	}
}

// Register ensures an account is tracked.
func (mqt *MultiQuotaTracker) Register(id string) {
	mqt.mu.Lock()
	defer mqt.mu.Unlock()

	if _, exists := mqt.buckets[id]; !exists {
		mqt.buckets[id] = &AccountBucket{
			MaskedID: MaskScriptID(id),
		}
	}
}

// RecordOutcome updates stats after a request and adjusts quarantine/exhaustion.
func (mqt *MultiQuotaTracker) RecordOutcome(id string, nowUnix, upBytes, downBytes int64, success bool) {
	mqt.mu.Lock()
	defer mqt.mu.Unlock()

	b, exists := mqt.buckets[id]
	if !exists {
		b = &AccountBucket{MaskedID: MaskScriptID(id)}
		mqt.buckets[id] = b
	}

	// Check window reset
	if b.NextResetAt > 0 && nowUnix >= b.NextResetAt {
		b.RequestsUsed = 0
		b.FailedRequests = 0
		b.BytesUp = 0
		b.BytesDown = 0
		b.BytesTotal = 0
		b.NextResetAt = 0
		b.Exhausted = false
		b.Quarantined = false
	}

	if b.NextResetAt == 0 {
		b.NextResetAt = nowUnix + mqt.windowDuration
	}

	b.LastRequestAt = nowUnix
	b.RequestsUsed++
	b.BytesUp += upBytes
	b.BytesDown += downBytes
	b.BytesTotal += upBytes + downBytes

	if !success {
		b.FailedRequests++
		if b.FailedRequests >= 5 {
			b.Quarantined = true
		}
	}

	if b.RequestsUsed >= mqt.requestLimit {
		b.Exhausted = true
	}
}

// SelectBestAccount returns the active un-exhausted account with lowest usage.
func (mqt *MultiQuotaTracker) SelectBestAccount(nowUnix int64) (string, bool) {
	mqt.mu.Lock()
	defer mqt.mu.Unlock()

	var bestID string
	var lowestUsage int64 = -1

	for id, b := range mqt.buckets {
		// Reset check
		if b.NextResetAt > 0 && nowUnix >= b.NextResetAt {
			b.RequestsUsed = 0
			b.FailedRequests = 0
			b.BytesUp = 0
			b.BytesDown = 0
			b.BytesTotal = 0
			b.NextResetAt = 0
			b.Exhausted = false
			b.Quarantined = false
		}

		if b.Exhausted || b.Quarantined {
			continue
		}

		if lowestUsage == -1 || b.RequestsUsed < lowestUsage {
			lowestUsage = b.RequestsUsed
			bestID = id
		}
	}

	if lowestUsage != -1 {
		return bestID, true
	}
	return "", false
}
