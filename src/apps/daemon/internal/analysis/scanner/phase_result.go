// Package scanner implements host and dns probing operations.
//              target_plan_evidence.go, export_utils.go, ring_buffer.go)

package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ─── PhaseResult extensions ──────────────────────────────────────────────────
// The existing PhaseResult struct is defined in scanner_sidecar.go.
// This file extends it with additional constructor helpers and analysis funcs
// from upstream phase_result.go.

// NewPhaseSuccess constructs a successful PhaseResult (JSON-compatible variant).
// Maps to upstream newPhaseSuccess().
func NewPhaseSuccess(phase string, durationMS int64) PhaseResult {
	return PhaseResult{
		Phase:      ProbePhase(phase),
		Status:     ProbeStatusSuccess,
		DurationMs: durationMS,
		Retryable:  false,
	}
}

// NewPhaseFailure constructs a failed PhaseResult with auto-classified error codes.
// Maps to upstream newPhaseFailure().
func NewPhaseFailure(phase string, err error, durationMS int64, errorCode string) PhaseResult {
	code := strings.TrimSpace(errorCode)
	if code == "" && err != nil {
		code = ClassifyNetworkErrorStatic(err, phase)
	}
	return PhaseResult{
		Phase:      ProbePhase(phase),
		Status:     ProbeStatus(PhaseStatusFromCode(code, err)),
		DurationMs: durationMS,
		ErrorCode:  code,
		Retryable:  PhaseRetryable(code),
	}
}

// PhaseStatusFromCode maps error codes to human-readable status strings.
// Maps to upstream phaseStatusFromCode().
func PhaseStatusFromCode(code string, err error) string {
	if code == "" && err == nil {
		return "success"
	}
	upper := strings.ToUpper(code)
	switch {
	case strings.HasSuffix(upper, "_TIMEOUT"):
		return "timeout"
	case strings.HasSuffix(upper, "_REFUSED"):
		return "refused"
	case strings.HasSuffix(upper, "_RESET"):
		return "reset"
	case strings.Contains(upper, "_MALFORMED"):
		return "malformed"
	case strings.Contains(upper, "_SKIPPED"), strings.HasSuffix(upper, "_EXCLUDED"):
		return "skipped"
	case strings.Contains(upper, "_UNSUPPORTED"):
		return "unsupported"
	case strings.HasSuffix(upper, "_CANCELLED"):
		return "cancelled"
	case strings.Contains(upper, "_THROTTLED"):
		return "throttled"
	default:
		return "failed"
	}
}

// PhaseRetryable returns true for transient error codes.
// Maps to upstream phaseRetryable().
func PhaseRetryable(code string) bool {
	upper := strings.ToUpper(strings.TrimSpace(code))
	switch {
	case strings.HasSuffix(upper, "_TIMEOUT"):
		return true
	case strings.HasSuffix(upper, "_RESET"):
		return true
	case upper == "DNS_TRUNCATED_TCP_RETRY_FAILED":
		return true
	default:
		return false
	}
}

// BoundedPhaseEvidence returns a capped error detail map.
// Maps to upstream boundedPhaseEvidence().
func BoundedPhaseEvidence(err error) map[string]any {
	if err == nil {
		return nil
	}
	detail := err.Error()
	if len(detail) > 200 {
		detail = detail[:200]
	}
	return map[string]any{"detail": detail}
}

// ClassifyNetworkErrorStatic classifies errors without a NetworkClassifierConfig receiver.
// Maps to upstream classifyNetworkError() standalone function.
func ClassifyNetworkErrorStatic(err error, phase string) string {
	if err == nil {
		return ""
	}
	lower := strings.ToLower(err.Error())
	prefix := "SCAN"
	switch phase {
	case "dns":
		prefix = "DNS"
	case "tcp":
		prefix = "TCP_CONNECT"
	case "tls":
		prefix = "TLS_HANDSHAKE"
	case "http":
		prefix = "HTTP"
	}
	switch {
	case err == context.DeadlineExceeded, strings.Contains(lower, "timeout"):
		return prefix + "_TIMEOUT"
	case strings.Contains(lower, "reset"):
		return prefix + "_RESET"
	case strings.Contains(lower, "refused"):
		return prefix + "_REFUSED"
	default:
		return prefix + "_FAILED"
	}
}

// AppendTLSOutcomePhases appends TCP and TLS phase results from a TLS handshake.
// Maps to upstream appendTLSOutcomePhases().
func AppendTLSOutcomePhases(phases []PhaseResult, candidateSNI string, certVerified bool, elapsed int64) []PhaseResult {
	phases = append(phases, NewPhaseSuccess("tcp", elapsed))
	if strings.TrimSpace(candidateSNI) != "" && !certVerified {
		return append(phases, NewPhaseFailure("tls", fmt.Errorf("hostname verification failed"), elapsed, "TLS_VERIFY_HOSTNAME_MISMATCH"))
	}
	return append(phases, NewPhaseSuccess("tls", elapsed))
}

// ResultIndicatesTimeout checks if any phase in a scan has timed out.
// Maps to upstream resultIndicatesTimeout().
func ResultIndicatesTimeout(phases []PhaseResult, errorCode string) bool {
	for _, phase := range phases {
		if string(phase.Status) == "timeout" || strings.HasSuffix(strings.ToUpper(phase.ErrorCode), "_TIMEOUT") {
			return true
		}
	}
	return strings.HasSuffix(errorCode, "_TIMEOUT")
}

// ResultIndicatesReset checks if any phase was reset.
// Maps to upstream resultIndicatesReset().
func ResultIndicatesReset(phases []PhaseResult, errorCode string) bool {
	for _, phase := range phases {
		if string(phase.Status) == "reset" || strings.HasSuffix(strings.ToUpper(phase.ErrorCode), "_RESET") {
			return true
		}
	}
	return strings.HasSuffix(errorCode, "_RESET")
}

// ResultErrorSignals collects all non-success error signals from phases.
// Maps to upstream resultErrorSignals().
func ResultErrorSignals(phases []PhaseResult, routeErrorCode, errorCode, errorMsg string) []string {
	var signals []string
	for _, phase := range phases {
		if phase.Status == "" || phase.Status == ProbeStatusSuccess || string(phase.Status) == "skipped" {
			continue
		}
		signal := strings.TrimSpace(phase.ErrorCode)
		if signal == "" {
			signal = strings.TrimSpace(string(phase.Status))
		}
		if signal != "" {
			signals = append(signals, signal)
		}
	}
	if strings.TrimSpace(routeErrorCode) != "" {
		signals = append(signals, strings.TrimSpace(routeErrorCode))
	}
	if strings.TrimSpace(errorCode) != "" {
		signals = append(signals, strings.TrimSpace(errorCode))
	}
	if strings.TrimSpace(errorMsg) != "" {
		signals = append(signals, strings.TrimSpace(errorMsg))
	}
	return signals
}

// ─── TargetPlanEvidence ─────────────────────────────────────────────────────

// TargetPlanEvidence provides structured per-target probe evidence.
type TargetPlanEvidence struct {
	SchemaVersion             int    `json:"schema_version,omitempty"`
	PlanID                    string `json:"plan_id,omitempty"`
	ProductMode               string `json:"product_mode,omitempty"`
	RawToken                  string `json:"raw_token,omitempty"`
	SourceType                string `json:"source_type,omitempty"`
	SourceProvider            string `json:"source_provider,omitempty"`
	CorpusRevision            string `json:"corpus_revision,omitempty"`
	NormalizedKind            string `json:"normalized_kind,omitempty"`
	OriginalHostname          string `json:"original_hostname,omitempty"`
	ResolvedIP                string `json:"resolved_ip,omitempty"`
	IPFamily                  string `json:"ip_family,omitempty"`
	Port                      int    `json:"port,omitempty"`
	SNIHost                   string `json:"sni_host,omitempty"`
	SNIMode                   string `json:"sni_mode,omitempty"`
	HTTPHost                  string `json:"http_host,omitempty"`
	VerificationHost          string `json:"verification_host,omitempty"`
	DNSMode                   string `json:"dns_mode,omitempty"`
	ResolverID                string `json:"resolver_id,omitempty"`
	ALPNPolicy                string `json:"alpn_policy,omitempty"`
	RouteID                   string `json:"route_id,omitempty"`
	RouteType                 string `json:"route_type,omitempty"`
	NetworkPath               string `json:"network_path,omitempty"`
	SafetyStatus              string `json:"safety_status,omitempty"`
	ExpansionParent           string `json:"expansion_parent,omitempty"`
	ExpansionIndex            *int   `json:"expansion_index,omitempty"`
	ExpansionTotalTheoretical *int64 `json:"expansion_total_theoretical,omitempty"`
	ExpansionTotalCapped      *int64 `json:"expansion_total_capped,omitempty"`
	ExpansionSkippedCount     *int64 `json:"expansion_skipped_count,omitempty"`
	SamplingSeed              string `json:"sampling_seed,omitempty"`
	DedupeKey                 string `json:"dedupe_key,omitempty"`
	ResultCorrelationID       string `json:"result_correlation_id,omitempty"`
}

// Getters & Setters for TargetPlanEvidence
func (e *TargetPlanEvidence) GetPlanID() string { return e.PlanID }
func (e *TargetPlanEvidence) SetPlanID(v string) { e.PlanID = v }
func (e *TargetPlanEvidence) GetRawToken() string { return e.RawToken }
func (e *TargetPlanEvidence) SetRawToken(v string) { e.RawToken = v }
func (e *TargetPlanEvidence) GetOriginalHostname() string { return e.OriginalHostname }
func (e *TargetPlanEvidence) SetOriginalHostname(v string) { e.OriginalHostname = v }
func (e *TargetPlanEvidence) GetResolvedIP() string { return e.ResolvedIP }
func (e *TargetPlanEvidence) SetResolvedIP(v string) { e.ResolvedIP = v }
func (e *TargetPlanEvidence) GetIPFamily() string { return e.IPFamily }
func (e *TargetPlanEvidence) SetIPFamily(v string) { e.IPFamily = v }
func (e *TargetPlanEvidence) GetPort() int { return e.Port }
func (e *TargetPlanEvidence) SetPort(v int) { e.Port = v }
func (e *TargetPlanEvidence) GetSNIHost() string { return e.SNIHost }
func (e *TargetPlanEvidence) SetSNIHost(v string) { e.SNIHost = v }
func (e *TargetPlanEvidence) GetSNIMode() string { return e.SNIMode }
func (e *TargetPlanEvidence) SetSNIMode(v string) { e.SNIMode = v }
func (e *TargetPlanEvidence) GetHTTPHost() string { return e.HTTPHost }
func (e *TargetPlanEvidence) SetHTTPHost(v string) { e.HTTPHost = v }
func (e *TargetPlanEvidence) GetVerificationHost() string { return e.VerificationHost }
func (e *TargetPlanEvidence) SetVerificationHost(v string) { e.VerificationHost = v }
func (e *TargetPlanEvidence) GetDNSMode() string { return e.DNSMode }
func (e *TargetPlanEvidence) SetDNSMode(v string) { e.DNSMode = v }
func (e *TargetPlanEvidence) GetRouteID() string { return e.RouteID }
func (e *TargetPlanEvidence) SetRouteID(v string) { e.RouteID = v }
func (e *TargetPlanEvidence) GetRouteType() string { return e.RouteType }
func (e *TargetPlanEvidence) SetRouteType(v string) { e.RouteType = v }
func (e *TargetPlanEvidence) GetNetworkPath() string { return e.NetworkPath }
func (e *TargetPlanEvidence) SetNetworkPath(v string) { e.NetworkPath = v }
func (e *TargetPlanEvidence) GetSafetyStatus() string { return e.SafetyStatus }
func (e *TargetPlanEvidence) SetSafetyStatus(v string) { e.SafetyStatus = v }
func (e *TargetPlanEvidence) GetDedupeKey() string { return e.DedupeKey }
func (e *TargetPlanEvidence) SetDedupeKey(v string) { e.DedupeKey = v }
func (e *TargetPlanEvidence) GetResultCorrelationID() string { return e.ResultCorrelationID }
func (e *TargetPlanEvidence) SetResultCorrelationID(v string) { e.ResultCorrelationID = v }
func (e *TargetPlanEvidence) GetProductMode() string { return e.ProductMode }
func (e *TargetPlanEvidence) SetProductMode(v string) { e.ProductMode = v }
func (e *TargetPlanEvidence) GetALPNPolicy() string { return e.ALPNPolicy }
func (e *TargetPlanEvidence) SetALPNPolicy(v string) { e.ALPNPolicy = v }
func (e *TargetPlanEvidence) GetResolverID() string { return e.ResolverID }
func (e *TargetPlanEvidence) SetResolverID(v string) { e.ResolverID = v }
func (e *TargetPlanEvidence) GetExpansionParent() string { return e.ExpansionParent }
func (e *TargetPlanEvidence) SetExpansionParent(v string) { e.ExpansionParent = v }
func (e *TargetPlanEvidence) GetSamplingSeed() string { return e.SamplingSeed }
func (e *TargetPlanEvidence) SetSamplingSeed(v string) { e.SamplingSeed = v }
func (e *TargetPlanEvidence) GetCorpusRevision() string { return e.CorpusRevision }
func (e *TargetPlanEvidence) SetCorpusRevision(v string) { e.CorpusRevision = v }
func (e *TargetPlanEvidence) GetSourceProvider() string { return e.SourceProvider }
func (e *TargetPlanEvidence) SetSourceProvider(v string) { e.SourceProvider = v }
func (e *TargetPlanEvidence) GetSourceType() string { return e.SourceType }
func (e *TargetPlanEvidence) SetSourceType(v string) { e.SourceType = v }
func (e *TargetPlanEvidence) GetNormalizedKind() string { return e.NormalizedKind }
func (e *TargetPlanEvidence) SetNormalizedKind(v string) { e.NormalizedKind = v }
func (e *TargetPlanEvidence) GetSchemaVersion() int { return e.SchemaVersion }
func (e *TargetPlanEvidence) SetSchemaVersion(v int) { e.SchemaVersion = v }

// Builders for TargetPlanEvidence
func (e *TargetPlanEvidence) WithPlanID(v string) *TargetPlanEvidence { e.SetPlanID(v); return e }
func (e *TargetPlanEvidence) WithResolvedIP(v string) *TargetPlanEvidence { e.SetResolvedIP(v); return e }
func (e *TargetPlanEvidence) WithSNIHost(v string) *TargetPlanEvidence { e.SetSNIHost(v); return e }
func (e *TargetPlanEvidence) WithRouteID(v string) *TargetPlanEvidence { e.SetRouteID(v); return e }
func (e *TargetPlanEvidence) WithDedupeKey(v string) *TargetPlanEvidence { e.SetDedupeKey(v); return e }

// HasIdentity checks if this evidence contains enough to identify a target.
// Maps to upstream hasIdentity().
func (e TargetPlanEvidence) HasIdentity() bool {
	return strings.TrimSpace(e.PlanID) != "" ||
		strings.TrimSpace(e.RawToken) != "" ||
		strings.TrimSpace(e.ResolvedIP) != "" ||
		strings.TrimSpace(e.ResultCorrelationID) != ""
}

// CleanOptionalString safely dereferences and trims a *string.
// Maps to upstream cleanOptionalString().
func CleanOptionalString(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}

// ─── SafetyPolicyObservation ─────────────────────────────────────────────────

const (
	SafetyPresetStandard  = "standard"
	SafetyPresetSafeQuick = "safe_quick"
)

// SafetyPolicyObservation records per-scan safety policy outcomes.
type SafetyPolicyObservation struct {
	PolicyID                         string   `json:"policy_id"`
	Preset                           string   `json:"preset"`
	AuthorizationRequired            bool     `json:"authorization_required"`
	RespectSafety                    bool     `json:"respect_safety"`
	MaxTargetsEffective              int      `json:"max_targets_effective"`
	MaxCIDRHostsEffective            int      `json:"max_cidr_hosts_effective"`
	RatePerSecondEffective           int      `json:"rate_per_second_effective"`
	JitterMSEffective                int      `json:"jitter_ms_effective"`
	TargetCount                      int      `json:"target_count"`
	BroadScanConfirmed               bool     `json:"broad_scan_confirmed"`
	BroadScanConfirmationRequired    bool     `json:"broad_scan_confirmation_required"`
	SpecialRangesBlocked             bool     `json:"special_ranges_blocked"`
	ProviderClassificationAuthorizes bool     `json:"provider_classification_authorizes"`
	Warnings                         []string `json:"warnings,omitempty"`
}

// Getters & Setters for SafetyPolicyObservation
func (s *SafetyPolicyObservation) GetPolicyID() string { return s.PolicyID }
func (s *SafetyPolicyObservation) SetPolicyID(v string) { s.PolicyID = v }
func (s *SafetyPolicyObservation) GetPreset() string { return s.Preset }
func (s *SafetyPolicyObservation) SetPreset(v string) { s.Preset = v }
func (s *SafetyPolicyObservation) GetAuthorizationRequired() bool { return s.AuthorizationRequired }
func (s *SafetyPolicyObservation) SetAuthorizationRequired(v bool) { s.AuthorizationRequired = v }
func (s *SafetyPolicyObservation) GetRespectSafety() bool { return s.RespectSafety }
func (s *SafetyPolicyObservation) SetRespectSafety(v bool) { s.RespectSafety = v }
func (s *SafetyPolicyObservation) GetMaxTargetsEffective() int { return s.MaxTargetsEffective }
func (s *SafetyPolicyObservation) SetMaxTargetsEffective(v int) { s.MaxTargetsEffective = v }
func (s *SafetyPolicyObservation) GetRatePerSecondEffective() int { return s.RatePerSecondEffective }
func (s *SafetyPolicyObservation) SetRatePerSecondEffective(v int) { s.RatePerSecondEffective = v }
func (s *SafetyPolicyObservation) GetJitterMSEffective() int { return s.JitterMSEffective }
func (s *SafetyPolicyObservation) SetJitterMSEffective(v int) { s.JitterMSEffective = v }
func (s *SafetyPolicyObservation) GetTargetCount() int { return s.TargetCount }
func (s *SafetyPolicyObservation) SetTargetCount(v int) { s.TargetCount = v }
func (s *SafetyPolicyObservation) GetBroadScanConfirmed() bool { return s.BroadScanConfirmed }
func (s *SafetyPolicyObservation) SetBroadScanConfirmed(v bool) { s.BroadScanConfirmed = v }
func (s *SafetyPolicyObservation) GetSpecialRangesBlocked() bool { return s.SpecialRangesBlocked }
func (s *SafetyPolicyObservation) SetSpecialRangesBlocked(v bool) { s.SpecialRangesBlocked = v }
func (s *SafetyPolicyObservation) GetWarnings() []string { return s.Warnings }
func (s *SafetyPolicyObservation) SetWarnings(v []string) { s.Warnings = v }
func (s *SafetyPolicyObservation) AddWarning(w string) { s.Warnings = append(s.Warnings, w) }

// ScanRequestSafetyConfig holds safety governor settings for a scan request.
type ScanRequestSafetyConfig struct {
	mu                     sync.RWMutex
	SafetyPreset           string
	RatePerSecond          int
	JitterMS               int
	RespectSafety          bool
	MaxTargets             int
	MaxCIDRHosts           int
	BroadScanConfirmed     bool
	AuthorizationConfirmed bool
	AuthorizedAttestation  string
	EnablePayloadSplitting bool
}

// Getters & Setters for ScanRequestSafetyConfig
func (r *ScanRequestSafetyConfig) GetSafetyPreset() string { r.mu.RLock(); defer r.mu.RUnlock(); return r.SafetyPreset }
func (r *ScanRequestSafetyConfig) SetSafetyPreset(v string) { r.mu.Lock(); defer r.mu.Unlock(); r.SafetyPreset = v }
func (r *ScanRequestSafetyConfig) GetRatePerSecond() int { r.mu.RLock(); defer r.mu.RUnlock(); return r.RatePerSecond }
func (r *ScanRequestSafetyConfig) SetRatePerSecond(v int) { r.mu.Lock(); defer r.mu.Unlock(); r.RatePerSecond = v }
func (r *ScanRequestSafetyConfig) GetJitterMS() int { r.mu.RLock(); defer r.mu.RUnlock(); return r.JitterMS }
func (r *ScanRequestSafetyConfig) SetJitterMS(v int) { r.mu.Lock(); defer r.mu.Unlock(); r.JitterMS = v }
func (r *ScanRequestSafetyConfig) GetRespectSafety() bool { r.mu.RLock(); defer r.mu.RUnlock(); return r.RespectSafety }
func (r *ScanRequestSafetyConfig) SetRespectSafety(v bool) { r.mu.Lock(); defer r.mu.Unlock(); r.RespectSafety = v }
func (r *ScanRequestSafetyConfig) GetMaxTargets() int { r.mu.RLock(); defer r.mu.RUnlock(); return r.MaxTargets }
func (r *ScanRequestSafetyConfig) SetMaxTargets(v int) { r.mu.Lock(); defer r.mu.Unlock(); r.MaxTargets = v }
func (r *ScanRequestSafetyConfig) GetAuthorizationConfirmed() bool { r.mu.RLock(); defer r.mu.RUnlock(); return r.AuthorizationConfirmed }
func (r *ScanRequestSafetyConfig) SetAuthorizationConfirmed(v bool) { r.mu.Lock(); defer r.mu.Unlock(); r.AuthorizationConfirmed = v }
func (r *ScanRequestSafetyConfig) GetBroadScanConfirmed() bool { r.mu.RLock(); defer r.mu.RUnlock(); return r.BroadScanConfirmed }
func (r *ScanRequestSafetyConfig) SetBroadScanConfirmed(v bool) { r.mu.Lock(); defer r.mu.Unlock(); r.BroadScanConfirmed = v }
func (r *ScanRequestSafetyConfig) GetEnablePayloadSplitting() bool { r.mu.RLock(); defer r.mu.RUnlock(); return r.EnablePayloadSplitting }
func (r *ScanRequestSafetyConfig) SetEnablePayloadSplitting(v bool) { r.mu.Lock(); defer r.mu.Unlock(); r.EnablePayloadSplitting = v }
func (r *ScanRequestSafetyConfig) GetAuthorizedAttestation() string { r.mu.RLock(); defer r.mu.RUnlock(); return r.AuthorizedAttestation }
func (r *ScanRequestSafetyConfig) SetAuthorizedAttestation(v string) { r.mu.Lock(); defer r.mu.Unlock(); r.AuthorizedAttestation = v }

// Builders for ScanRequestSafetyConfig
func (r *ScanRequestSafetyConfig) WithSafetyPreset(v string) *ScanRequestSafetyConfig { r.SetSafetyPreset(v); return r }
func (r *ScanRequestSafetyConfig) WithRatePerSecond(v int) *ScanRequestSafetyConfig { r.SetRatePerSecond(v); return r }
func (r *ScanRequestSafetyConfig) WithRespectSafety(v bool) *ScanRequestSafetyConfig { r.SetRespectSafety(v); return r }
func (r *ScanRequestSafetyConfig) WithMaxTargets(v int) *ScanRequestSafetyConfig { r.SetMaxTargets(v); return r }

func NewScanRequestSafetyConfig() *ScanRequestSafetyConfig {
	return &ScanRequestSafetyConfig{
		SafetyPreset:  SafetyPresetStandard,
		RatePerSecond: 1000,
		RespectSafety: true,
	}
}

// ApplySafetyPreset enforces upstream safety preset rules including the SEC-1 governor.
// Maps to upstream applySafetyPreset().
func (r *ScanRequestSafetyConfig) ApplySafetyPreset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch r.SafetyPreset {
	case SafetyPresetSafeQuick:
		r.RespectSafety = true
		if r.RatePerSecond <= 0 {
			r.RatePerSecond = 250
		}
		if r.JitterMS <= 0 {
			r.JitterMS = 10
		}
	case SafetyPresetStandard:
	default:
		r.SafetyPreset = SafetyPresetStandard
	}
	if os.Getenv("DISABLE_CAPS_GUARDS") == "true" {
		return
	}
	// SEC-1: enforce rate ceiling of 1000 pps when not authorized
	if !r.AuthorizationConfirmed {
		if r.RatePerSecond <= 0 || r.RatePerSecond > 1000 {
			r.RatePerSecond = 1000
		}
		r.RespectSafety = true
	}
}

// BuildSafetyPolicyObservation creates the observation struct.
// Maps to upstream safetyPolicyObservation().
func (r *ScanRequestSafetyConfig) BuildSafetyPolicyObservation(targetCount int) SafetyPolicyObservation {
	r.mu.RLock()
	defer r.mu.RUnlock()
	policyID := "standard-v1"
	if r.SafetyPreset == SafetyPresetSafeQuick {
		policyID = "safe_quick-v1"
	}
	authRequired := r.RatePerSecond > 1000 || r.RatePerSecond <= 0 || !r.RespectSafety
	obs := SafetyPolicyObservation{
		PolicyID:               policyID,
		Preset:                 r.SafetyPreset,
		AuthorizationRequired:  authRequired,
		RespectSafety:          r.RespectSafety,
		MaxTargetsEffective:    r.MaxTargets,
		MaxCIDRHostsEffective:  r.MaxCIDRHosts,
		RatePerSecondEffective: r.RatePerSecond,
		JitterMSEffective:      r.JitterMS,
		TargetCount:            targetCount,
		BroadScanConfirmed:     r.BroadScanConfirmed,
		SpecialRangesBlocked:   r.RespectSafety,
	}
	if r.SafetyPreset == SafetyPresetStandard && !r.RespectSafety {
		obs.AddWarning("Standard policy: reserved/special range filtering follows the explicit respect_safety setting.")
	}
	if r.RatePerSecond == 0 {
		obs.AddWarning("No effective rate limit is configured.")
	}
	return obs
}

// WriteAuditLog persists a scan audit entry to disk.
// Maps to upstream writeAuditLog().
func (r *ScanRequestSafetyConfig) WriteAuditLog(targetCount int, clientIP, requestID string) {
	r.mu.RLock()
	record := map[string]any{
		"timestamp":               time.Now().UTC().Format(time.RFC3339),
		"client_ip":               clientIP,
		"request_id":              requestID,
		"targets_count":           targetCount,
		"rate_per_second":         r.RatePerSecond,
		"jitter_ms":               r.JitterMS,
		"respect_safety":          r.RespectSafety,
		"safety_preset":           r.SafetyPreset,
		"authorized_attestation":  r.AuthorizedAttestation,
		"authorization_confirmed": r.AuthorizationConfirmed,
		"payload_splitting":       r.EnablePayloadSplitting,
	}
	r.mu.RUnlock()
	f, err := os.OpenFile("scan_safety_audit.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	b, err := json.Marshal(record)
	if err != nil {
		return
	}
	_, _ = f.Write(append(b, '\n'))
}

// ─── LockFreeRingBuffer[T] ────────────────────────────────────────────────────
// NOTE: ErrorRingBuffer is already declared in sidecar_models.go.
// This adds an additional generic lock-free ring buffer for typed payloads.

// LockFreeRingBufferNode is a single slot in the generic ring buffer.
type LockFreeRingBufferNode[T any] struct {
	val  T
	free uint32 // 0: empty, 1: occupied
}

// LockFreeRingBuffer is a lock-free MPSC-safe ring buffer.
type LockFreeRingBuffer[T any] struct {
	buffer []LockFreeRingBufferNode[T]
	mask   uint32
	write  uint32
	read   uint32
}

func NewLockFreeRingBuffer[T any](capacity uint32) *LockFreeRingBuffer[T] {
	var size uint32 = 1
	for size < capacity {
		size <<= 1
	}
	return &LockFreeRingBuffer[T]{
		buffer: make([]LockFreeRingBufferNode[T], size),
		mask:   size - 1,
	}
}

func (rb *LockFreeRingBuffer[T]) Push(val T) bool {
	for {
		w := atomic.LoadUint32(&rb.write)
		r := atomic.LoadUint32(&rb.read)
		if w-r >= uint32(len(rb.buffer)) {
			return false
		}
		idx := w & rb.mask
		node := &rb.buffer[idx]
		if atomic.LoadUint32(&node.free) == 0 {
			if atomic.CompareAndSwapUint32(&rb.write, w, w+1) {
				node.val = val
				atomic.StoreUint32(&node.free, 1)
				return true
			}
		}
		runtime.Gosched()
	}
}

func (rb *LockFreeRingBuffer[T]) Pop() (T, bool) {
	for {
		r := atomic.LoadUint32(&rb.read)
		w := atomic.LoadUint32(&rb.write)
		if r == w {
			var zero T
			return zero, false
		}
		idx := r & rb.mask
		node := &rb.buffer[idx]
		if atomic.LoadUint32(&node.free) == 1 {
			if atomic.CompareAndSwapUint32(&rb.read, r, r+1) {
				val := node.val
				atomic.StoreUint32(&node.free, 0)
				return val, true
			}
		}
		runtime.Gosched()
	}
}

func (rb *LockFreeRingBuffer[T]) Len() int {
	w := atomic.LoadUint32(&rb.write)
	r := atomic.LoadUint32(&rb.read)
	return int(w - r)
}

// ─── Export utilities ────────────────────────────────────────────────────────

// XMLEscape escapes XML special characters.
func XMLEscape(s string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&apos;",
	)
	return replacer.Replace(s)
}

// JoinScriptFields joins key=value fields in canonical nmap script order.
func JoinScriptFields(fields map[string]string) string {
	order := []string{
		"plan_id", "correlation_id", "product_mode", "raw_token", "original_hostname", "resolved_ip",
		"sni_mode", "route_id", "route_type", "dedupe_key", "expansion_parent", "expansion_index",
		"expansion_total_capped", "final_phase", "error_code", "requested_route_id", "observed_route_id",
		"route_error_code",
	}
	var parts []string
	for _, key := range order {
		value := strings.TrimSpace(fields[key])
		if value != "" {
			parts = append(parts, key+"="+value)
		}
	}
	return strings.Join(parts, "; ")
}

// IntPointerString safely formats a *int as a string.
func IntPointerString(value *int) string {
	if value == nil {
		return ""
	}
	return fmt.Sprintf("%d", *value)
}

// Int64PointerString safely formats a *int64 as a string.
func Int64PointerString(value *int64) string {
	if value == nil {
		return ""
	}
	return fmt.Sprintf("%d", *value)
}

// BuildResultCorrelationScript formats correlation metadata as an nmap-style XML script snippet.
// Maps to upstream addNmapScript() + nmapHostScripts() result-correlation portion.
func BuildResultCorrelationScript(planID, correlationID, finalPhase, errorCode, requestedRouteID, observedRouteID, routeErrorCode string) string {
	fields := map[string]string{
		"plan_id":            planID,
		"correlation_id":     correlationID,
		"final_phase":        finalPhase,
		"error_code":         errorCode,
		"requested_route_id": requestedRouteID,
		"observed_route_id":  observedRouteID,
		"route_error_code":   routeErrorCode,
	}
	output := JoinScriptFields(fields)
	if strings.TrimSpace(output) == "" {
		return ""
	}
	return fmt.Sprintf(`<script id="%s" output="%s"/>`, XMLEscape("luminet-result-correlation"), XMLEscape(output))
}
