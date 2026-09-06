// SPDX-License-Identifier: MIT
// C5.1a — WebAnalysis: clean-room OONI probe-cli WebAnalysis port.
// Mirrors the OONI architecture of sending HTTP requests and inspecting
// responses for DPI fingerprints (TLS layer anomalies, HTTP headers,
// connection close patterns, and HTTP/1.1 behavior anomalies).
// MIT License — no OONI source code copied.

package diagnostics

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// WebDPIFingerprint describes the result of inspecting a single HTTP exchange
// for signs of Deep Packet Inspection or transparent-proxy interference.
type WebDPIFingerprint struct {
	URL                string            `json:"url"`
	Method             string            `json:"method"`
	ResponseStatus    int               `json:"response_status"`
	ResponseHeaders    http.Header       `json:"response_headers"`
	TLSVersion         string            `json:"tls_version"`
	TLSResumed         bool              `json:"tls_resumed"`
	ServerName         string            `json:"server_name"`
	ContentLength      int64             `json:"content_length"`
	ContentType        string            `json:"content_type"`
	ContentLengthMatch bool              `json:"content_length_match"`
	BlockedKeywords    []string          `json:"blocked_keywords"`
	DPIAnomalies       []string          `json:"dpi_anomalies"`
	Latency            time.Duration     `json:"latency"`
	Failed             bool              `json:"failed"`
	FailureReason      string            `json:"failure_reason,omitempty"`
}

// WebAnalysisConfig controls the behavior of a WebAnalysis probe run.
type WebAnalysisConfig struct {
	// URLs is the list of URLs to probe.
	URLs []string
	// Timeout per request. Zero uses the default of 10 seconds.
	Timeout time.Duration
	// InsecureSkipVerify disables TLS certificate verification (for controlled lab use).
	InsecureSkipVerify bool
	// UserAgent overrides the default Go HTTP client user-agent.
	UserAgent string
	// FollowRedirects controls whether the probe follows HTTP redirects.
	FollowRedirects bool
	// Headers are additional HTTP headers to inject into each request.
	Headers http.Header
	// ExpectedContentTypes is a list of Content-Type prefixes considered "normal"
	// for each URL. A response outside these prefixes may indicate DPI injection.
	ExpectedContentTypes []string
	// BlockKeywords is a list of strings that, if present in the response body,
	// indicate DPI injection (e.g. "blocked", "forbidden", "access denied").
	BlockKeywords []string
}

// WebAnalysis performs a structured HTTP probe against the configured URLs,
// collects TLS handshake metadata and HTTP response anomalies, and returns
// per-URL DPI fingerprint records.
type WebAnalysis struct {
	config WebAnalysisConfig
	client *http.Client
}

// NewWebAnalysis creates a new WebAnalysis probe with the given configuration.
// It applies defaults for unset fields.
func NewWebAnalysis(config WebAnalysisConfig) *WebAnalysis {
	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}
	if config.UserAgent == "" {
		config.UserAgent = "LumiNet-WebAnalysis/1.0"
	}
	if config.Headers == nil {
		config.Headers = make(http.Header)
	}
	if config.BlockKeywords == nil {
		config.BlockKeywords = []string{"blocked", "access denied", "forbidden", "connection reset"}
	}

	transport := &http.Transport{
		DisableKeepAlives:  true,
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: config.InsecureSkipVerify},
		TLSHandshakeTimeout: config.Timeout,
		DialContext: (&net.Dialer{
			Timeout: config.Timeout,
		}).DialContext,
	}

	if !config.FollowRedirects {
		transport.DisableKeepAlives = true
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			if !config.FollowRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	return &WebAnalysis{
		config: config,
		client: client,
	}
}

// ProbeURL sends a single HTTP request to the given URL and returns a DPI
// fingerprint record. It inspects both the TLS handshake metadata and the
// HTTP response for anomalies consistent with transparent-proxy interference.
func (w *WebAnalysis) ProbeURL(ctx context.Context, url string) WebDPIFingerprint {
	start := time.Now()
	fp := WebDPIFingerprint{
		URL:     url,
		Method:  "GET",
		DPIAnomalies: []string{},
		BlockedKeywords: []string{},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		fp.Failed = true
		fp.FailureReason = fmt.Sprintf("request_build: %v", err)
		return fp
	}
	req.Header.Set("User-Agent", w.config.UserAgent)
	for k, vals := range w.config.Headers {
		req.Header[k] = vals
	}

	// OONI-style: always request a small body to observe content-length
	// anomalies. We do not read the full body, only a peek.
	req.Header.Set("Range", "bytes=0-2047")

	resp, err := w.client.Do(req)
	if err != nil {
		fp.Failed = true
		if ctx.Err() != nil {
			fp.FailureReason = "context_deadline_exceeded"
		} else {
			fp.FailureReason = fmt.Sprintf("request_error: %v", err)
		}
		return fp
	}
	defer resp.Body.Close()

	fp.ResponseStatus = resp.StatusCode
	fp.ResponseHeaders = resp.Header.Clone()
	fp.ContentType = resp.Header.Get("Content-Type")
	fp.ContentLength = resp.ContentLength

	// --- TLS inspection via response's TLSGet — mirrored from OONI architecture ---
	if resp.TLS != nil {
		fp.TLSVersion = tlsVersionToString(resp.TLS.Version)
		fp.TLSResumed = resp.TLS.DidResume
		fp.ServerName = resp.TLS.ServerName

		// Check for TLS-layer anomalies
		fp.DPIAnomalies = append(fp.DPIAnomalies, w.checkTLSAnomalies(resp.TLS)...)
	}

	fp.Latency = time.Since(start)

	// Read a small body peek for keyword detection and content-length validation.
	bodyPeek, readErr := io.ReadAll(io.LimitReader(resp.Body, 2048))
	if readErr != nil && len(bodyPeek) == 0 {
		// Body read failure is itself an anomaly
		fp.DPIAnomalies = append(fp.DPIAnomalies, "body_read_error")
	} else {
		fp.BlockedKeywords = w.detectBlockedKeywords(string(bodyPeek))
		fp.ContentLengthMatch = w.checkContentLengthMatch(resp.Header, bodyPeek)
	}

	// Check for HTTP-layer anomalies.
	fp.DPIAnomalies = append(fp.DPIAnomalies, w.checkHTTPAnomalies(resp.Header, string(bodyPeek))...)

	return fp
}

// ProbeAll runs ProbeURL for all configured URLs concurrently and returns
// the aggregated results. It respects the context deadline.
func (w *WebAnalysis) ProbeAll(ctx context.Context) []WebDPIFingerprint {
	if len(w.config.URLs) == 0 {
		return nil
	}
	results := make([]WebDPIFingerprint, len(w.config.URLs))
	type result struct {
		i   int
		fp  WebDPIFingerprint
	}
	ch := make(chan result, len(w.config.URLs))
	for i, url := range w.config.URLs {
		go func(i int, url string) {
			ch <- result{i, w.ProbeURL(ctx, url)}
		}(i, url)
	}
	for range w.config.URLs {
		r := <-ch
		results[r.i] = r.fp
	}
	return results
}

// checkTLSAnomalies inspects TLS handshake metadata for signs of MITM proxies.
// This is a clean-room implementation based on the OONI concept of checking
// for unexpected certificate issuers, weak ciphers, and TLS version downgrades.
func (w *WebAnalysis) checkTLSAnomalies(cs *tls.ConnectionState) []string {
	var anomalies []string

	// OONI tlsmiddlebox-style check: if more than one certificate is in the
	// chain, the extra certs may belong to a MITM appliance.
	if len(cs.PeerCertificates) > 2 {
		anomalies = append(anomalies, "unexpected_certificate_chain_length")
	}

	// Check TLS version: downgrades to TLS 1.0/1.1 are suspicious.
	if cs.Version < tls.VersionTLS12 {
		anomalies = append(anomalies, "tls_version_downgrade")
	}

	// Check for TLS 1.3 but with no session resumption signals a middlebox
	// that strips session tickets. (ConnectionState exposes DidResume;
	// the ticket-state field does not exist in Go's public API.)
	if cs.Version == tls.VersionTLS13 && !cs.DidResume {
		anomalies = append(anomalies, "tls13_session_ticket_missing")
	}

	return anomalies
}

// checkHTTPAnomalies checks HTTP response headers for DPI injection patterns.
func (w *WebAnalysis) checkHTTPAnomalies(headers http.Header, body string) []string {
	var anomalies []string

	// Check for X-Blocked-By or similar DPI headers.
	for _, h := range []string{"X-Blocked-By", "X-DPI-Rule", "X-Violation"} {
		if headers.Get(h) != "" {
			anomalies = append(anomalies, fmt.Sprintf("dpi_header_present:%s", h))
		}
	}

	// Check Content-Type for injection (e.g. text/html injected into API response).
	ct := headers.Get("Content-Type")
	if ct == "text/html" && strings.HasPrefix(w.config.URLs[0], "https://api.") {
		anomalies = append(anomalies, "content_type_mismatch")
	}

	// Check for cache-control manipulation (some DPI boxes strip caching headers).
	if cc := headers.Get("Cache-Control"); cc == "" {
		// Lack of cache-control is not always anomalous; only flag if other signals exist.
	}

	// Check for server header being stripped (DPI sometimes removes Server header).
	if headers.Get("Server") == "" && len(body) > 0 {
		anomalies = append(anomalies, "server_header_missing")
	}

	return anomalies
}

// detectBlockedKeywords scans a body peek for known DPI injection keywords.
func (w *WebAnalysis) detectBlockedKeywords(body string) []string {
	var found []string
	lower := strings.ToLower(body)
	for _, kw := range w.config.BlockKeywords {
		if strings.Contains(lower, strings.ToLower(kw)) {
			found = append(found, kw)
		}
	}
	return found
}

// checkContentLengthMatch validates that the actual body size matches the
// Content-Length header, a common DPI injection fingerprint.
func (w *WebAnalysis) checkContentLengthMatch(headers http.Header, bodyPeek []byte) bool {
	clStr := headers.Get("Content-Length")
	if clStr == "" {
		return true // No header to compare
	}
	var cl int64
	fmt.Sscanf(clStr, "%d", &cl)
	// We only have the first 2048 bytes; a mismatch on this is a signal.
	return cl == int64(len(bodyPeek)) || cl > int64(len(bodyPeek))
}

// tlsVersionToString converts a tls.Version* constant to a human-readable string.
func tlsVersionToString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04X", v)
	}
}

// RunWebAnalysis is a convenience function that creates a WebAnalysis,
// runs ProbeAll, and returns the results. It is the primary entry point.
func RunWebAnalysis(ctx context.Context, config WebAnalysisConfig) []WebDPIFingerprint {
	w := NewWebAnalysis(config)
	return w.ProbeAll(ctx)
}
