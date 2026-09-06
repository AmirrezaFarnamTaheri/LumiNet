package scanner

// scanner_edge_routing.go — WindscribeAuthManager scoring/redaction, WindscribeAuthSession,
// BasebandCapabilityReport, RouteProfileValidator.
// Source: MaybeEdgeScanner Java source (exhaustive audit, all files read)

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
)

// ---------------------------------------------------------------------------
// WindscribeAuthManager — credential redaction, route scoring, failover
// Source: MaybeEdgeScanner/WindscribeAuthManager.java
// ---------------------------------------------------------------------------

// WindscribeRefPrefix constants match what MaybeEdgeScanner uses to store and identify references.
// All raw credentials are hashed; only "ref:..." tokens are stored.
// Source: MaybeEdgeScanner/WindscribeAuthManager.java redactCredential() / redactProfile()
const (
	WindscribeCredRefPrefix   = "ref:ws_session_"  // prefix for session credential refs
	WindscribeProfileRefPrefix = "ref:ws_profile_" // prefix for profile refs
	WindscribeRefMarker       = "ref:"             // any string starting with this is already a ref
)

// RedactWindscribeCredential returns a stable "ref:ws_session_<8hex>" for a raw credential,
// or returns the input unchanged if it already starts with "ref:".
// Source: MaybeEdgeScanner/WindscribeAuthManager.java redactCredential()
func RedactWindscribeCredential(rawCredential string) string {
	rawCredential = strings.TrimSpace(rawCredential)
	if rawCredential == "" {
		return ""
	}
	if strings.HasPrefix(rawCredential, WindscribeRefMarker) {
		return rawCredential
	}
	h := sha256.Sum256([]byte(rawCredential))
	return fmt.Sprintf("%s%02x%02x%02x%02x%02x%02x%02x%02x",
		WindscribeCredRefPrefix,
		h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7])
}

// RedactWindscribeProfile returns a stable "ref:ws_profile_<8hex>" for a raw profile string,
// or returns the input unchanged if it already starts with "ref:".
// Source: MaybeEdgeScanner/WindscribeAuthManager.java redactProfile()
func RedactWindscribeProfile(rawProfile string) string {
	rawProfile = strings.TrimSpace(rawProfile)
	if rawProfile == "" {
		return ""
	}
	if strings.HasPrefix(rawProfile, WindscribeRefMarker) {
		return rawProfile
	}
	h := sha256.Sum256([]byte(rawProfile))
	return fmt.Sprintf("%s%02x%02x%02x%02x%02x%02x%02x%02x",
		WindscribeProfileRefPrefix,
		h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7])
}

// WindscribeCheckClockDrift returns true if the server time is within the allowed drift of local time.
// Source: MaybeEdgeScanner/WindscribeAuthManager.java checkClockDrift()
func WindscribeCheckClockDrift(serverTimeMs, localTimeMs, maxDriftMs int64) bool {
	drift := serverTimeMs - localTimeMs
	if drift < 0 {
		drift = -drift
	}
	return drift <= maxDriftMs
}

// WindscribeProviderSettingsSnapshot holds a snapshot of Windscribe provider settings.
// Credentials are stored only as refs, never raw values.
// Source: MaybeEdgeScanner/WindscribeAuthManager.java ProviderSettingsSnapshot
type WindscribeProviderSettingsSnapshot struct {
	Source           string // e.g. "api", "cached"
	Version          string
	ExpiryEpochMs    int64  // 0 = no expiry
	RouteScope       string
	CredentialRef    string // always a "ref:..." value
	FreshnessEvidence string // short hex entropy hash
}

// IsExpired returns true if the snapshot has a non-zero expiry that has passed.
func (s *WindscribeProviderSettingsSnapshot) IsExpired(nowMs int64) bool {
	return s.ExpiryEpochMs > 0 && nowMs > s.ExpiryEpochMs
}

// CalculateWindscribeRouteScore computes a 1–100 route quality score.
// Deducts points for poor UDP reachability, high TCP connect, TLS handshake,
// and API response times. Returns 0 if the sample window is exhausted.
// Source: MaybeEdgeScanner/WindscribeAuthManager.java calculateRouteScore()
//
//   udpReachability: <= 0 means UDP is not reachable (-25 pts)
//   tcpConnectMs:    each 40ms deducts 1 pt, max -30 pts
//   tlsHandshakeMs:  each 50ms deducts 1 pt, max -25 pts
//   apiResponseMs:   each 100ms deducts 1 pt, max -20 pts
//   sampleWindow:    if failureCount >= sampleWindow → 0 (circuit broken)
func CalculateWindscribeRouteScore(udpReachability, tcpConnectMs, tlsHandshakeMs, apiResponseMs, sampleWindow, failureCount int) int {
	if sampleWindow > 0 && failureCount >= sampleWindow {
		return 0
	}
	score := 100
	if udpReachability <= 0 {
		score -= 25
	}
	if tcpConnectMs > 0 {
		score -= int(math.Min(30, float64(tcpConnectMs/40)))
	}
	if tlsHandshakeMs > 0 {
		score -= int(math.Min(25, float64(tlsHandshakeMs/50)))
	}
	if apiResponseMs > 0 {
		score -= int(math.Min(20, float64(apiResponseMs/100)))
	}
	if score < 1 {
		return 1
	}
	return score
}

// WindscribeAdvanceFailover returns the next failover attempt index, or -1 if exhausted.
// Source: MaybeEdgeScanner/WindscribeAuthManager.java advanceFailover()
func WindscribeAdvanceFailover(currentAttempt, maxRetries int, policy string) int {
	if strings.EqualFold(policy, "exhausted") || currentAttempt >= maxRetries {
		return -1
	}
	return currentAttempt + 1
}

// ---------------------------------------------------------------------------
// WindscribeAuthSession — session reference boundary
// Source: MaybeEdgeScanner/WindscribeAuthSession.java
// ---------------------------------------------------------------------------

// WindscribeAuthSession holds credential and profile references for Windscribe routing.
// Only "ref:..." tokens are stored (raw credentials are never kept in memory).
// Source: MaybeEdgeScanner/WindscribeAuthSession.java
type WindscribeAuthSession struct {
	CredentialRef     string // "ref:ws_session_<hex>" or ""
	ProfileRef        string // "ref:ws_profile_<hex>" or ""
	SessionRefAvailable bool  // true if credentialRef starts with "ref:"
	LoginRequired     bool   // !SessionRefAvailable
}

// NewWindscribeAuthSession creates a session from (possibly raw) credential and profile values.
// Raw values are redacted to "ref:..." form.
// Source: MaybeEdgeScanner/WindscribeAuthSession.java fromRefs()
func NewWindscribeAuthSession(credentialRef, profileRef string) WindscribeAuthSession {
	credentialRef = strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(credentialRef), "\r", " "), "\n", " ")
	profileRef = strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(profileRef), "\r", " "), "\n", " ")
	sessionRefAvailable := strings.HasPrefix(credentialRef, WindscribeRefMarker)
	return WindscribeAuthSession{
		CredentialRef:       credentialRef,
		ProfileRef:          profileRef,
		SessionRefAvailable: sessionRefAvailable,
		LoginRequired:       !sessionRefAvailable,
	}
}

// AuthBoundary returns a user-facing description of the authentication boundary.
// Source: MaybeEdgeScanner/WindscribeAuthSession.java authBoundary()
func (s *WindscribeAuthSession) AuthBoundary() string {
	if s.SessionRefAvailable {
		return "Windscribe stays external; this scan attaches only a stored session/profile reference."
	}
	return "Connect Windscribe first or enter a stored session/profile reference. No Windscribe password is collected here."
}

// ---------------------------------------------------------------------------
// RouteProfileValidator — readiness gate checks
// Source: MaybeEdgeScanner/RouteProfileValidator.java (validation logic)
// ---------------------------------------------------------------------------

// RouteProfileValidation summarises what a route profile needs before it can be used.
type RouteProfileValidation struct {
	NeedsEndpoint    bool   // local_proxy mode with no endpoint set
	NeedsProfileRef  bool   // external_vpn/apk with no profile or package
	NeedsConfigRef   bool   // psiphon with no config ref
	NeedsPackageName bool   // external_vpn_apk with no package
	Issues           []string
	Ready            bool
}

// ValidateEdgeRouteProfile checks whether an EdgeRouteProfile has all required fields.
// Source: MaybeEdgeScanner/RouteProfileValidator.java (validation gate logic)
func ValidateEdgeRouteProfile(profile EdgeRouteProfile) RouteProfileValidation {
	v := RouteProfileValidation{Ready: true}
	if !profile.Enabled {
		return v // direct/disabled profiles always pass
	}
	switch profile.ProtocolMode {
	case RouteProtocolLocalProxy:
		if profile.Endpoint == "" {
			v.NeedsEndpoint = true
			v.Issues = append(v.Issues, "local_proxy mode requires endpoint (socks5:// or http://)")
			v.Ready = false
		} else if !strings.HasPrefix(profile.Endpoint, "socks5://") && !strings.HasPrefix(profile.Endpoint, "http://") {
			v.Issues = append(v.Issues, "endpoint must start with socks5:// or http://")
			v.Ready = false
		}
	case RouteProtocolExternalVPN, RouteProtocolExternalVPNAPK:
		if !strings.HasPrefix(profile.ProfileRef, WindscribeRefMarker) && profile.PackageName == "" {
			v.NeedsProfileRef = true
			v.NeedsPackageName = true
			v.Issues = append(v.Issues, "external_vpn mode requires profile_ref or package_name")
			v.Ready = false
		}
	case RouteProtocolTunnelCoreSupervised: // Psiphon
		if !strings.HasPrefix(profile.ConfigRef, WindscribeRefMarker) {
			v.NeedsConfigRef = true
			v.Issues = append(v.Issues, "psiphon mode requires config_ref starting with ref:")
			v.Ready = false
		}
	}
	return v
}

// ---------------------------------------------------------------------------
// BasebandCapabilityReport — Shizuku + ITelephony capability check
// Source: MaybeScanner/diagnostics/PrivilegedTelephonyBasebandManager.java PrivilegedCapabilityReport
// ---------------------------------------------------------------------------

// BasebandCapabilityReport holds the result of a Shizuku + baseband capability probe.
// Source: MaybeScanner/diagnostics/PrivilegedTelephonyBasebandManager.java
type BasebandCapabilityReport struct {
	ShizukuAvailable              bool
	ShizukuPermissionGranted      bool
	ShizukuAPIVersion             int    // -1 if unknown
	Mode                          string // "root" | "adb" | "unknown"
	BinderAlive                   bool
	UserServiceAvailable          bool
	NewProcessAvailable           bool
	PublicSubscriptionDataAvail   bool
	HiddenTelephonyAccessAvailable bool
	RadioMutationSupported        bool
	ShellUID                      int    // -1 if unknown, 0=root, 2000=adb
	ObservedCapabilities          []string
}

// BasebandMutationResult holds the result of a setPreferredNetworkType call.
// Source: MaybeScanner/diagnostics/PrivilegedTelephonyBasebandManager.java invokeBasebandRadioMutation()
type BasebandMutationResult struct {
	OperationID         int64
	Success             bool
	Classification      string // "verified" | "readback_mismatch_or_settling_timeout" | "carrier_or_framework_rejected" | "permission_denied" | "ipc_fault"
	SubID               int
	RequestedMode       int
	ReadbackInitial     int // confirmed state immediately after set
	ReadbackAfterSettle int // state after RADIO_SETTLE_MS
	SettleMs            int // always BasebandRadioSettleMs
	ErrorDetail         string
}

// BasebandMutationClassifications are the classification strings in the mutation result.
const (
	BasebandMutationVerified               = "verified"
	BasebandMutationReadbackMismatch       = "readback_mismatch_or_settling_timeout"
	BasebandMutationCarrierRejected        = "carrier_or_framework_rejected"
	BasebandMutationPermissionDenied       = "permission_denied"
	BasebandMutationIPCFault               = "ipc_fault"
)

// ---------------------------------------------------------------------------
// EdgeVpnProfileLinks — profile URL export/import link serialization
// Source: MaybeEdgeScanner/model/EdgeVpnProfileLinks.java
// ---------------------------------------------------------------------------

const (
	EdgeVpnProfileScheme = "edgevpn"
	EdgeVpnProfileSchema = "edgevpn.profile"
	EdgeVpnProfileVersion = 1
)

// EdgeVpnProfileLink represents the decoded import parameters from an edgevpn:// link.
type EdgeVpnProfileLink struct {
	Name             string `json:"name"`
	Domain           string `json:"domain"`
	EncryptionKey    string `json:"encryption_key"`
	EncryptionMethod int    `json:"encryption_method"`
}

type edgeVpnProfileLinkRoot struct {
	Schema  string                 `json:"schema"`
	Version int                    `json:"version"`
	Profile edgeVpnProfilePayload  `json:"profile"`
}

type edgeVpnProfilePayload struct {
	Name   string                  `json:"name"`
	Server edgeVpnServerPayload    `json:"server"`
}

type edgeVpnServerPayload struct {
	Domain           string `json:"domain"`
	EncryptionKey    string `json:"encryption_key"`
	EncryptionMethod int    `json:"encryption_method"`
}

// ExportEdgeVpnProfileLink serializes profile details into an edgevpn:// Base64 URL link.
func ExportEdgeVpnProfileLink(name, domain, encryptionKey string, encryptionMethod int) (string, error) {
	domain = strings.TrimSpace(domain)
	encryptionKey = strings.TrimSpace(encryptionKey)
	if domain == "" || encryptionKey == "" {
		return "", errors.New("Domain and encryption key are required to export")
	}

	// Clean domain trailing dots
	domain = strings.TrimRight(domain, ".")
	if encryptionMethod < 0 {
		encryptionMethod = 0
	}
	if encryptionMethod > 5 {
		encryptionMethod = 5
	}
	if name == "" {
		name = "EdgeVPN Profile"
	}

	root := edgeVpnProfileLinkRoot{
		Schema:  EdgeVpnProfileSchema,
		Version: EdgeVpnProfileVersion,
		Profile: edgeVpnProfilePayload{
			Name: name,
			Server: edgeVpnServerPayload{
				Domain:           domain,
				EncryptionKey:    encryptionKey,
				EncryptionMethod: encryptionMethod,
			},
		},
	}

	jsonBytes, err := json.Marshal(root)
	if err != nil {
		return "", err
	}

	base64Payload := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(jsonBytes)
	return EdgeVpnProfileScheme + "://" + base64Payload, nil
}

// ImportEdgeVpnProfileLink parses and validates an edgevpn:// link, returning the decoded profile.
func ImportEdgeVpnProfileLink(rawLink string) (*EdgeVpnProfileLink, error) {
	link := strings.TrimSpace(rawLink)
	prefix := EdgeVpnProfileScheme + "://"
	if !strings.HasPrefix(link, prefix) {
		return nil, errors.New("Profile link must start with " + prefix)
	}

	payload := strings.TrimSpace(link[len(prefix):])
	if payload == "" {
		return nil, errors.New("Profile link is empty")
	}

	// Strip off query or anchor elements if present
	if idx := strings.Index(payload, "#"); idx != -1 {
		payload = payload[:idx]
	}
	if idx := strings.Index(payload, "?"); idx != -1 {
		payload = payload[:idx]
	}

	decodedBytes, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(payload)
	if err != nil {
		return nil, errors.New("Profile link payload is not valid base64: " + err.Error())
	}

	var root edgeVpnProfileLinkRoot
	err = json.Unmarshal(decodedBytes, &root)
	if err != nil {
		return nil, errors.New("Profile link payload is not valid JSON: " + err.Error())
	}

	if root.Schema != EdgeVpnProfileSchema {
		return nil, errors.New("Unsupported profile schema: " + root.Schema)
	}
	if root.Version != EdgeVpnProfileVersion {
		return nil, errors.New("Unsupported profile version: " + itoa(int64(root.Version)))
	}

	p := root.Profile
	s := p.Server

	domain := strings.TrimRight(strings.TrimSpace(s.Domain), ".")
	encryptionKey := strings.TrimSpace(s.EncryptionKey)

	if domain == "" {
		return nil, errors.New("Server domain is required")
	}
	if encryptionKey == "" {
		return nil, errors.New("Server encryption key is required")
	}
	if s.EncryptionMethod < 0 || s.EncryptionMethod > 5 {
		return nil, errors.New("Server encryption method must be between 0 and 5")
	}

	return &EdgeVpnProfileLink{
		Name:             strings.TrimSpace(p.Name),
		Domain:           domain,
		EncryptionKey:    encryptionKey,
		EncryptionMethod: s.EncryptionMethod,
	}, nil
}

