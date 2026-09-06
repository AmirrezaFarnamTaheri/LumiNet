// Package scanner implements host and dns probing operations.

package scanner

import (
	"context"
	"math"
	mrand "math/rand"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/maybeknott/luminet/internal/networking/geoip"
)

// ─── Adaptive Backoff ─────────────────────────────────────────────────────────

// ComputeAdaptiveBackoff determines if a backoff delay should be applied based
// on recent error signals. Returns the backoff duration in nanoseconds.
// Maps to upstream trackAdaptiveBackoff().
func ComputeAdaptiveBackoff(recentErrors []string, ratePerSecond int) time.Duration {
	if ratePerSecond <= 0 || len(recentErrors) < 24 {
		return 0
	}
	noisy := 0
	for _, errText := range recentErrors {
		lower := strings.ToLower(errText)
		if strings.Contains(lower, "timeout") || strings.Contains(lower, "reset") {
			noisy++
		}
	}
	if noisy*100/len(recentErrors) >= 40 {
		delay := min(2000, 250+noisy*25)
		return time.Duration(delay) * time.Millisecond
	}
	return 0
}

// ─── Scan Warnings ────────────────────────────────────────────────────────────

// GenerateScanWarnings produces a list of human-readable scan advisory warnings.
// Maps to upstream scanWarnings().
func GenerateScanWarnings(ratePerSecond, batchSize int, targets []string) []string {
	var warnings []string
	if batchSize > ScanResultBufferSize(batchSize) {
		warnings = append(warnings, "Batch size is preserved; the internal result channel buffer is bounded to protect process memory.")
	}
	if ratePerSecond == 0 {
		warnings = append(warnings, "No rate limit configured: scans may look bursty to IDS/IPS systems.")
	}
	unsafe := 0
	for _, target := range targets {
		if addr, err := netip.ParseAddr(target); err == nil {
			if IsReservedOrUnsafeAddr(addr) {
				unsafe++
				if unsafe >= 5 {
					break
				}
			}
		}
	}
	if unsafe > 0 {
		warnings = append(warnings, "Reserved/private/special-use addresses were present and are skipped when safety mode is enabled.")
	}
	return warnings
}

// ScanResultBufferSize returns the capped result channel buffer size for a batch.
// Maps to upstream resultBufferSize().
func ScanResultBufferSize(batchSize int) int {
	if batchSize <= 0 {
		return 1
	}
	if batchSize < 1048576 {
		return batchSize
	}
	return 1048576
}

// IsReservedOrUnsafeAddr returns true if the address is in a reserved or unsafe range.
// Maps to upstream isReservedOrUnsafe().
func IsReservedOrUnsafeAddr(addr netip.Addr) bool {
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() || addr.IsLinkLocalMulticast() {
		return true
	}
	return geoip.IsLocalOrLanIP(addr.String())
}

// ─── String Utilities ─────────────────────────────────────────────────────────

// UniqueStrings deduplicates and sorts a string slice, splitting on common delimiters.
// Maps to upstream unique().
func UniqueStrings(xs []string) []string {
	set := make(map[string]bool)
	var out []string
	for _, x := range xs {
		for _, part := range strings.FieldsFunc(x, func(r rune) bool {
			return r == ',' || r == ';' || r == '\r' || r == '\n' || r == '\t' || r == ' '
		}) {
			part = strings.TrimSpace(part)
			if part != "" && !set[part] {
				set[part] = true
				out = append(out, part)
			}
		}
	}
	sort.Strings(out)
	return out
}

// ShuffleStrings randomly shuffles a string slice in place.
// Maps to upstream shuffleStrings().
func ShuffleStrings(xs []string) {
	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	r.Shuffle(len(xs), func(i, j int) { xs[i], xs[j] = xs[j], xs[i] })
}

// Atoi parses a string to int, returning fallback on error.
// Maps to upstream atoi().
func Atoi(s string, fallback int) int {
	v, err := strconv.Atoi(s)
	if err != nil {
		return fallback
	}
	return v
}

// ─── Rate Limiter & Jitter ────────────────────────────────────────────────────

// WaitRateAndJitter sleeps for a jitter delay up to jitterMS milliseconds.
// Maps to upstream waitRate() without the rate.Limiter dependency.
func WaitRateAndJitter(ctx context.Context, jitterMS int) {
	if jitterMS > 0 {
		delay := time.Duration(mrand.Intn(jitterMS+1)) * time.Millisecond
		select {
		case <-ctx.Done():
		case <-time.After(delay):
		}
	}
}

// ─── TLS Profile Utilities ────────────────────────────────────────────────────

// NormalizeTLSFingerprint normalizes a TLS fingerprint name to canonical form.
// Maps to upstream normalizeTLSFingerprint().
func NormalizeTLSFingerprint(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "auto", "rotate":
		return "rotate"
	case "chrome", "firefox", "ios", "randomized", "randomized-no-alpn":
		return strings.ToLower(strings.TrimSpace(v))
	default:
		return "rotate"
	}
}

// ChooseTLSFingerprint selects a concrete TLS fingerprint from a mode string.
// Maps to upstream chooseTLSFingerprint().
func ChooseTLSFingerprint(mode string) string {
	if mode != "rotate" {
		return mode
	}
	choices := []string{"chrome", "firefox", "randomized"}
	return choices[mrand.Intn(len(choices))]
}

// TLSFingerprintName returns a human-readable fingerprint ID for a TLS profile.
// Extended version of upstream chooseTLSFingerprint + clientHelloID.
func TLSFingerprintName(fingerprint string) string {
	switch strings.ToLower(fingerprint) {
	case "chrome":
		return "Chrome Auto"
	case "firefox":
		return "Firefox Auto"
	case "ios":
		return "iOS Auto"
	case "randomized-no-alpn":
		return "Randomized (No ALPN)"
	case "randomized":
		return "Randomized ALPN"
	default:
		return "Randomized ALPN"
	}
}

// ─── Cipher Suite Name ────────────────────────────────────────────────────────

// TLSCipherSuiteName maps TLS cipher suite uint16 IDs to name strings.
// Maps to upstream cipherSuiteName() with stdlib-compatible fallback.
func TLSCipherSuiteName(id uint16) string {
	switch id {
	case 0x1301:
		return "TLS_AES_128_GCM_SHA256"
	case 0x1302:
		return "TLS_AES_256_GCM_SHA384"
	case 0x1303:
		return "TLS_CHACHA20_POLY1305_SHA256"
	case 0xc02b:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case 0xc02f:
		return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case 0xc02c:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	case 0xc030:
		return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case 0xcca9:
		return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305"
	case 0xcca8:
		return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"
	case 0x002f:
		return "TLS_RSA_WITH_AES_128_CBC_SHA"
	case 0x0035:
		return "TLS_RSA_WITH_AES_256_CBC_SHA"
	case 0xc013:
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
	case 0xc014:
		return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
	default:
		return CipherSuiteName(id)
	}
}

// ─── Math Helpers ─────────────────────────────────────────────────────────────

// ComputeLogScore computes a logarithmic latency score for target ranking.
// Maps to upstream score computation using math.Log1p.
func ComputeLogScore(latencyMS int64) float64 {
	if latencyMS <= 0 {
		return 0
	}
	return 1.0 / math.Log1p(float64(latencyMS))
}

// ClampInt clamps an integer value between min and max.
func ClampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// FirstNonEmpty returns the first non-empty string from candidates.
func FirstNonEmpty(candidates ...string) string {
	for _, c := range candidates {
		if strings.TrimSpace(c) != "" {
			return c
		}
	}
	return ""
}
