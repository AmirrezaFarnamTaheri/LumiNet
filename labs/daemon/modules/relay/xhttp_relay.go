// Package relay provides XHTTP streaming relay functionality.
// Ported from XHTTPRelayECO-master/api/index.js.
//
// Key behaviors transplanted verbatim:
//   - GET/HEAD/POST allowed; all other methods → 405
//   - x-relay-key header auth (fail-closed 403); skipped when RelayKey is empty
//   - Concurrency gate: atomic inflight counter → 503 + Retry-After: 1
//   - Streaming: io.Copy from req.Body to upstream + io.Copy from upstream.Body to w
//   - Token-bucket upload + download throttling via GlobalLimiter
//   - Hop-by-hop header stripping (exact set from ECO)
//   - Forward-header allowlist (exact set + sec-ch-/sec-fetch- prefixes from ECO)
//   - Path normalization: normalizeRelayPath + normalizeIncomingPath
//   - Path remapping: PUBLIC_RELAY_PATH → RELAY_PATH
//   - Upstream timeout → 504; other upstream errors → 502
//   - Per-request unique ID for logs
package relay

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// hop-by-hop headers that must never be forwarded upstream or downstream.
// Mirrors STRIP_HEADERS set from XHTTPRelayECO and XHTTPRelayAzure.
var xhttpStripHeaders = map[string]bool{
	"host":                true,
	"connection":          true,
	"proxy-connection":    true,
	"keep-alive":          true,
	"via":                 true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailer":             true,
	"transfer-encoding":   true,
	"upgrade":             true,
	"forwarded":           true,
	"x-forwarded-host":    true,
	"x-forwarded-proto":   true,
	"x-forwarded-port":    true,
	"x-forwarded-for":     true,
	"x-real-ip":           true,
	"x-original-url":      true, // Azure variant extra
	"x-relay-key":         true, // internal auth header
}

// forwardHeaderExact is the allowlist of headers forwarded verbatim to upstream.
// Mirrors FORWARD_HEADER_EXACT from XHTTPRelayECO.
var forwardHeaderExact = map[string]bool{
	"accept":          true,
	"accept-encoding": true,
	"accept-language": true,
	"cache-control":   true,
	"content-length":  true,
	"content-type":    true,
	"pragma":          true,
	"range":           true,
	"referer":         true,
	"user-agent":      true,
}

// forwardHeaderPrefixes contains prefixes of headers that are always forwarded.
// Mirrors FORWARD_HEADER_PREFIXES from XHTTPRelayECO.
var forwardHeaderPrefixes = []string{"sec-ch-", "sec-fetch-"}

// allowedMethods mirrors ALLOWED_METHODS from XHTTPRelayECO.
var allowedMethods = map[string]bool{
	http.MethodGet:  true,
	http.MethodHead: true,
	http.MethodPost: true,
}

// XHTTPRelayConfig holds the configuration for a single XHTTP relay handler.
// All fields mirror the environment variables from XHTTPRelayECO.
type XHTTPRelayConfig struct {
	// TargetDomain is the upstream base URL (e.g. "https://example.com:443").
	// Mirrors TARGET_DOMAIN env; trailing slash stripped.
	TargetDomain string

	// RelayPath is the upstream path prefix (e.g. "/xhttp").
	// Mirrors RELAY_PATH env; must not be empty or "/".
	RelayPath string

	// PublicRelayPath is the public-facing path clients connect to (e.g. "/api").
	// Mirrors PUBLIC_RELAY_PATH env; default "/api".
	PublicRelayPath string

	// RelayKey is the shared secret sent as X-Relay-Key.
	// When non-empty, must be ≥ 16 characters. Empty = no auth.
	RelayKey string

	// UpstreamTimeout is the per-request timeout for the upstream fetch.
	// Default 25s (mirrors UPSTREAM_TIMEOUT_MS=25000).
	UpstreamTimeout time.Duration

	// MaxInflight is the maximum number of concurrent relay requests.
	// Default 128 (mirrors MAX_INFLIGHT=128). 503 returned when exceeded.
	MaxInflight int32

	// UploadLimiter throttles request body upload bandwidth. nil = unlimited.
	UploadLimiter *GlobalLimiter

	// DownloadLimiter throttles response body download bandwidth. nil = unlimited.
	DownloadLimiter *GlobalLimiter
}

// DefaultXHTTPRelayConfig returns a config with all ECO defaults applied.
func DefaultXHTTPRelayConfig(targetDomain, relayPath string) XHTTPRelayConfig {
	return XHTTPRelayConfig{
		TargetDomain:    strings.TrimRight(targetDomain, "/"),
		RelayPath:       normalizeRelayPath(relayPath),
		PublicRelayPath: "/api",
		UpstreamTimeout: 25 * time.Second,
		MaxInflight:     128,
	}
}

// XHTTPRelayHandler returns an http.Handler that proxies requests to the upstream Xray inbound.
// It implements the full ECO relay logic including auth, concurrency gating, streaming, and throttling.
func XHTTPRelayHandler(cfg XHTTPRelayConfig) http.Handler {
	// Validate config eagerly so misconfiguration surfaces at startup.
	if err := validateXHTTPConfig(&cfg); err != nil {
		panic("xhttp relay misconfigured: " + err.Error())
	}

	var inflight atomic.Int32

	transport := &http.Transport{
		MaxIdleConns:        512,
		MaxIdleConnsPerHost: 128,
		IdleConnTimeout:     90 * time.Second,
		// Disable compression so we stream raw bytes through the throttle.
		DisableCompression: true,
	}
	client := &http.Client{
		Transport: transport,
		// Do not follow redirects; mirror ECO's redirect:"manual" fetch option.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		// No client-level timeout — we use per-request context.
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := newRequestID()
		startedAt := time.Now()

		// ── Path normalisation & routing ──────────────────────────────────────
		normalizedPath := normalizeIncomingPath(r.URL.Path)
		if !isAllowedRelayPath(normalizedPath, cfg.PublicRelayPath) {
			http.NotFound(w, r)
			return
		}

		// ── Method gate ────────────────────────────────────────────────────────
		if !allowedMethods[r.Method] {
			w.Header().Set("Allow", "GET, HEAD, POST")
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		// ── Auth ───────────────────────────────────────────────────────────────
		if cfg.RelayKey != "" {
			token := r.Header.Get("X-Relay-Key")
			if token != cfg.RelayKey {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}

		// ── Concurrency gate ───────────────────────────────────────────────────
		// Mirrors tryAcquireSlot() / releaseSlot() from ECO.
		if inflight.Add(1) > cfg.MaxInflight {
			inflight.Add(-1)
			w.Header().Set("Retry-After", "1")
			http.Error(w, "Server Busy: Too Many Inflight Requests", http.StatusServiceUnavailable)
			return
		}
		defer inflight.Add(-1)

		// ── Build upstream URL ─────────────────────────────────────────────────
		upstreamPath := mapPublicPathToRelayPath(normalizedPath, cfg.PublicRelayPath, cfg.RelayPath)
		targetURL := cfg.TargetDomain + upstreamPath
		if r.URL.RawQuery != "" {
			targetURL += "?" + r.URL.RawQuery
		}

		// ── Build upstream headers ─────────────────────────────────────────────
		upstreamHeaders := buildForwardHeaders(r)

		// ── Build upstream request with timeout ────────────────────────────────
		ctx, cancel := context.WithTimeout(r.Context(), cfg.UpstreamTimeout)
		defer cancel()

		var reqBody io.Reader
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Body != nil {
			reqBody = NewThrottledReader(r.Body, cfg.UploadLimiter)
		}

		upstreamReq, err := http.NewRequestWithContext(ctx, r.Method, targetURL, reqBody)
		if err != nil {
			slog.Error("xhttp relay: failed to build upstream request",
				"requestId", requestID, "error", err)
			http.Error(w, "Bad Gateway: Failed to Build Request", http.StatusBadGateway)
			return
		}
		upstreamReq.Header = upstreamHeaders

		// ── Execute upstream fetch ─────────────────────────────────────────────
		resp, err := client.Do(upstreamReq)
		if err != nil {
			durationMs := time.Since(startedAt).Milliseconds()
			if ctx.Err() != nil {
				slog.Warn("xhttp relay: upstream timeout",
					"requestId", requestID, "method", r.Method,
					"durationMs", durationMs, "timeoutMs", cfg.UpstreamTimeout.Milliseconds())
				http.Error(w, "Gateway Timeout: Upstream Timeout", http.StatusGatewayTimeout)
				return
			}
			slog.Error("xhttp relay: upstream error",
				"requestId", requestID, "method", r.Method,
				"durationMs", durationMs, "error", err)
			http.Error(w, "Bad Gateway: Tunnel Failed", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		// ── Copy response headers ──────────────────────────────────────────────
		for k, vals := range resp.Header {
			kl := strings.ToLower(k)
			if kl == "transfer-encoding" || kl == "connection" {
				continue
			}
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)

		// ── Stream response body ───────────────────────────────────────────────
		downReader := NewThrottledReader(resp.Body, cfg.DownloadLimiter)
		if _, err := io.Copy(w, downReader); err != nil {
			// Client likely disconnected; not actionable.
			slog.Debug("xhttp relay: response body copy interrupted",
				"requestId", requestID, "error", err)
			return
		}

		durationMs := time.Since(startedAt).Milliseconds()
		if resp.StatusCode >= 400 || durationMs >= 3000 {
			slog.Warn("xhttp relay: completed with non-2xx or slow response",
				"requestId", requestID, "status", resp.StatusCode, "durationMs", durationMs)
		}
	})
}

// ── Helper functions ──────────────────────────────────────────────────────────

// validateXHTTPConfig returns an error if the config is invalid.
// Mirrors the startup validation in ECO handler().
func validateXHTTPConfig(cfg *XHTTPRelayConfig) error {
	if cfg.TargetDomain == "" {
		return fmt.Errorf("TargetDomain is not set")
	}
	if cfg.RelayPath == "" {
		return fmt.Errorf("RelayPath is not set")
	}
	if cfg.RelayPath == "/" {
		return fmt.Errorf("RelayPath cannot be '/'")
	}
	if cfg.PublicRelayPath == "" {
		cfg.PublicRelayPath = "/api"
	}
	if cfg.PublicRelayPath == "/" {
		return fmt.Errorf("PublicRelayPath cannot be '/'")
	}
	if cfg.RelayKey != "" && len(cfg.RelayKey) < 16 {
		return fmt.Errorf("RelayKey is too short (minimum 16 characters)")
	}
	if cfg.UpstreamTimeout <= 0 {
		cfg.UpstreamTimeout = 25 * time.Second
	}
	if cfg.MaxInflight <= 0 {
		cfg.MaxInflight = 128
	}
	return nil
}

// shouldForwardHeader reports whether the lowercased header name should be forwarded.
// Mirrors shouldForwardHeader() from XHTTPRelayECO.
func shouldForwardHeader(name string) bool {
	if forwardHeaderExact[name] {
		return true
	}
	for _, prefix := range forwardHeaderPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// buildForwardHeaders builds the header set to send to the upstream.
// Strips hop-by-hop and platform-internal headers; forwards the allowlisted set.
func buildForwardHeaders(r *http.Request) http.Header {
	out := make(http.Header)
	for k, vals := range r.Header {
		kl := strings.ToLower(k)
		if xhttpStripHeaders[kl] {
			continue
		}
		if !shouldForwardHeader(kl) {
			continue
		}
		for _, v := range vals {
			out.Add(k, v)
		}
	}
	// Preserve the original client IP for logging on the upstream.
	if ip := r.Header.Get("X-Real-IP"); ip == "" {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			out.Set("X-Forwarded-For", fwd)
		}
	}
	return out
}

// isAllowedRelayPath mirrors isAllowedRelayPath() from XHTTPRelayECO.
// pathname must equal publicPath or start with publicPath + "/".
func isAllowedRelayPath(pathname, publicPath string) bool {
	return pathname == publicPath || strings.HasPrefix(pathname, publicPath+"/")
}

// mapPublicPathToRelayPath mirrors mapPublicPathToRelayPath() from XHTTPRelayECO.
func mapPublicPathToRelayPath(pathname, publicPath, relayPath string) string {
	if pathname == publicPath {
		return relayPath
	}
	return relayPath + pathname[len(publicPath):]
}

// normalizeRelayPath mirrors normalizeRelayPath() from XHTTPRelayECO.
func normalizeRelayPath(raw string) string {
	if raw == "" {
		return ""
	}
	if !strings.HasPrefix(raw, "/") {
		raw = "/" + raw
	}
	if len(raw) > 1 && strings.HasSuffix(raw, "/") {
		raw = raw[:len(raw)-1]
	}
	return raw
}

// normalizeIncomingPath mirrors normalizeIncomingPath() from XHTTPRelayECO.
func normalizeIncomingPath(pathname string) string {
	if pathname == "" {
		return "/"
	}
	// Collapse multiple slashes
	for strings.Contains(pathname, "//") {
		pathname = strings.ReplaceAll(pathname, "//", "/")
	}
	if !strings.HasPrefix(pathname, "/") {
		pathname = "/" + pathname
	}
	if len(pathname) > 1 && strings.HasSuffix(pathname, "/") {
		pathname = pathname[:len(pathname)-1]
	}
	return pathname
}

// newRequestID generates a short unique request identifier for logging.
func newRequestID() string {
	return fmt.Sprintf("%x-%06x", time.Now().UnixMilli(), rand.Int63n(1<<24))
}
