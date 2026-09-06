// Package proxy implements Apps Script quota tracking models ported from MasterHttpRelayVPN-RUST-main.
// Source: src/quota_tracker.rs (AccountBucket, QuotaSummary)
// Target: server/internal/proxy/master_http_relay_quota.go

package proxy

// MasterHTTPRelayAccountBucket tracks Apps Script quota for one account (script_id).
// Source: quota_tracker.rs AccountBucket struct
//
// Model: each script_id = one Google account; quota is per-user/account (not per deployment).
// A 24-hour rolling window resets 24h after first request, not at a fixed midnight boundary.
type MasterHTTPRelayAccountBucket struct {
	// MaskedID is the first 4 + "..." + last 4 chars of the script_id.
	MaskedID string
	// RequestsUsed is the number of requests used in the current 24-hour window.
	RequestsUsed uint64
	// FailedRequests is the count of failed requests in the current 24-hour window.
	FailedRequests uint64
	// BytesUp is total bytes of JSON payload uploaded to Apps Script (all attempts).
	BytesUp uint64
	// BytesDown is total bytes received from Apps Script (successful only).
	BytesDown uint64
	// BytesTotal is BytesUp + BytesDown.
	BytesTotal uint64
	// LastRequestAt is the Unix timestamp of the last recorded request.
	LastRequestAt *uint64
	// NextResetAt is the Unix timestamp when this bucket's 24-hour window resets.
	NextResetAt *uint64
	// Exhausted is true when this account has hit its quota limit.
	Exhausted bool
	// HardStopped means no more dispatches until manually cleared or window resets.
	HardStopped bool
	// ExhaustionReason is the human-readable reason for exhaustion/stop.
	ExhaustionReason string
	// QuotaErrorCount counts responses with quota-like error messages.
	QuotaErrorCount uint64
}

func (b *MasterHTTPRelayAccountBucket) GetMaskedID() string          { return b.MaskedID }
func (b *MasterHTTPRelayAccountBucket) SetMaskedID(v string)         { b.MaskedID = v }
func (b *MasterHTTPRelayAccountBucket) GetRequestsUsed() uint64      { return b.RequestsUsed }
func (b *MasterHTTPRelayAccountBucket) SetRequestsUsed(v uint64)     { b.RequestsUsed = v }
func (b *MasterHTTPRelayAccountBucket) GetFailedRequests() uint64    { return b.FailedRequests }
func (b *MasterHTTPRelayAccountBucket) SetFailedRequests(v uint64)   { b.FailedRequests = v }
func (b *MasterHTTPRelayAccountBucket) GetBytesUp() uint64           { return b.BytesUp }
func (b *MasterHTTPRelayAccountBucket) SetBytesUp(v uint64)          { b.BytesUp = v }
func (b *MasterHTTPRelayAccountBucket) GetBytesDown() uint64         { return b.BytesDown }
func (b *MasterHTTPRelayAccountBucket) SetBytesDown(v uint64)        { b.BytesDown = v }
func (b *MasterHTTPRelayAccountBucket) GetBytesTotal() uint64        { return b.BytesTotal }
func (b *MasterHTTPRelayAccountBucket) SetBytesTotal(v uint64)       { b.BytesTotal = v }
func (b *MasterHTTPRelayAccountBucket) GetLastRequestAt() *uint64    { return b.LastRequestAt }
func (b *MasterHTTPRelayAccountBucket) SetLastRequestAt(v *uint64)   { b.LastRequestAt = v }
func (b *MasterHTTPRelayAccountBucket) GetNextResetAt() *uint64      { return b.NextResetAt }
func (b *MasterHTTPRelayAccountBucket) SetNextResetAt(v *uint64)     { b.NextResetAt = v }
func (b *MasterHTTPRelayAccountBucket) GetExhausted() bool           { return b.Exhausted }
func (b *MasterHTTPRelayAccountBucket) SetExhausted(v bool)          { b.Exhausted = v }
func (b *MasterHTTPRelayAccountBucket) GetHardStopped() bool         { return b.HardStopped }
func (b *MasterHTTPRelayAccountBucket) SetHardStopped(v bool)        { b.HardStopped = v }
func (b *MasterHTTPRelayAccountBucket) GetExhaustionReason() string  { return b.ExhaustionReason }
func (b *MasterHTTPRelayAccountBucket) SetExhaustionReason(v string) { b.ExhaustionReason = v }
func (b *MasterHTTPRelayAccountBucket) GetQuotaErrorCount() uint64   { return b.QuotaErrorCount }
func (b *MasterHTTPRelayAccountBucket) SetQuotaErrorCount(v uint64)  { b.QuotaErrorCount = v }

// MasterHTTPRelayQuotaSummary is an aggregate quota view across all account buckets.
// Source: quota_tracker.rs QuotaSummary struct
type MasterHTTPRelayQuotaSummary struct {
	// AccountCount is the number of tracked account buckets.
	AccountCount int
	// DailyCapacityTotal is AccountCount × per-account daily limit.
	DailyCapacityTotal uint64
	// RequestsUsedTotal is total requests used across all active windows.
	RequestsUsedTotal uint64
	// RequestsRemainingTotal is total requests before aggregate safety reserve is hit.
	RequestsRemainingTotal uint64
	// FailedRequestsTotal is total failed requests across all buckets.
	FailedRequestsTotal uint64
	// BytesUpTotal is total bytes uploaded across all buckets.
	BytesUpTotal uint64
	// BytesDownTotal is total bytes downloaded across all buckets.
	BytesDownTotal uint64
	// BytesTotal is total bytes transferred (up + down).
	BytesTotal uint64
	// ExhaustedCount is the number of accounts currently marked exhausted.
	ExhaustedCount int
	// HardStoppedCount is the number of accounts currently hard-stopped.
	HardStoppedCount int
	// GlobalHardStop is true when all buckets are exhausted or quota aggregate is below threshold.
	GlobalHardStop bool
	// NextResetAt is the soonest window reset timestamp across non-exhausted buckets.
	NextResetAt *uint64
	// NextResetAtAny is the soonest reset across ALL buckets including hard-stopped ones.
	NextResetAtAny *uint64
	// TotalRelayCalls is total relay() calls today (all paths), persisted across restarts, resets at UTC midnight.
	TotalRelayCalls uint64
}

func (s *MasterHTTPRelayQuotaSummary) GetAccountCount() int           { return s.AccountCount }
func (s *MasterHTTPRelayQuotaSummary) SetAccountCount(v int)          { s.AccountCount = v }
func (s *MasterHTTPRelayQuotaSummary) GetDailyCapacityTotal() uint64  { return s.DailyCapacityTotal }
func (s *MasterHTTPRelayQuotaSummary) SetDailyCapacityTotal(v uint64) { s.DailyCapacityTotal = v }
func (s *MasterHTTPRelayQuotaSummary) GetRequestsUsedTotal() uint64   { return s.RequestsUsedTotal }
func (s *MasterHTTPRelayQuotaSummary) SetRequestsUsedTotal(v uint64)  { s.RequestsUsedTotal = v }
func (s *MasterHTTPRelayQuotaSummary) GetRequestsRemainingTotal() uint64 {
	return s.RequestsRemainingTotal
}
func (s *MasterHTTPRelayQuotaSummary) SetRequestsRemainingTotal(v uint64) {
	s.RequestsRemainingTotal = v
}
func (s *MasterHTTPRelayQuotaSummary) GetFailedRequestsTotal() uint64  { return s.FailedRequestsTotal }
func (s *MasterHTTPRelayQuotaSummary) SetFailedRequestsTotal(v uint64) { s.FailedRequestsTotal = v }
func (s *MasterHTTPRelayQuotaSummary) GetBytesUpTotal() uint64         { return s.BytesUpTotal }
func (s *MasterHTTPRelayQuotaSummary) SetBytesUpTotal(v uint64)        { s.BytesUpTotal = v }
func (s *MasterHTTPRelayQuotaSummary) GetBytesDownTotal() uint64       { return s.BytesDownTotal }
func (s *MasterHTTPRelayQuotaSummary) SetBytesDownTotal(v uint64)      { s.BytesDownTotal = v }
func (s *MasterHTTPRelayQuotaSummary) GetBytesTotal() uint64           { return s.BytesTotal }
func (s *MasterHTTPRelayQuotaSummary) SetBytesTotal(v uint64)          { s.BytesTotal = v }
func (s *MasterHTTPRelayQuotaSummary) GetExhaustedCount() int          { return s.ExhaustedCount }
func (s *MasterHTTPRelayQuotaSummary) SetExhaustedCount(v int)         { s.ExhaustedCount = v }
func (s *MasterHTTPRelayQuotaSummary) GetHardStoppedCount() int        { return s.HardStoppedCount }
func (s *MasterHTTPRelayQuotaSummary) SetHardStoppedCount(v int)       { s.HardStoppedCount = v }
func (s *MasterHTTPRelayQuotaSummary) GetGlobalHardStop() bool         { return s.GlobalHardStop }
func (s *MasterHTTPRelayQuotaSummary) SetGlobalHardStop(v bool)        { s.GlobalHardStop = v }
func (s *MasterHTTPRelayQuotaSummary) GetNextResetAt() *uint64         { return s.NextResetAt }
func (s *MasterHTTPRelayQuotaSummary) SetNextResetAt(v *uint64)        { s.NextResetAt = v }
func (s *MasterHTTPRelayQuotaSummary) GetNextResetAtAny() *uint64      { return s.NextResetAtAny }
func (s *MasterHTTPRelayQuotaSummary) SetNextResetAtAny(v *uint64)     { s.NextResetAtAny = v }
func (s *MasterHTTPRelayQuotaSummary) GetTotalRelayCalls() uint64      { return s.TotalRelayCalls }
func (s *MasterHTTPRelayQuotaSummary) SetTotalRelayCalls(v uint64)     { s.TotalRelayCalls = v }
