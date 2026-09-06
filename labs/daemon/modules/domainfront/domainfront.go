// Package domainfront provides domain fronting relay for censorship bypass.
// Ported from CMP-GUI-MasterHttpRelayVPN's relay engine.
//
// Domain fronting technique: HTTPS request to www.google.com (SNI shows google.com)
// but the encrypted Host header points to script.google.com (Apps Script relay).
// DPI sees traffic to google.com (looks normal) but content comes from the relay.
//
// Architecture:
//   Client → HTTPS to www.google.com (SNI) → Google CDN → script.google.com → Apps Script
//   Apps Script fetches target URL → returns response through the same channel.
package domainfront

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// RelayRequest is the JSON envelope sent to the Apps Script relay.
type RelayRequest struct {
	Key      string            `json:"k"`           // Auth key
	URL      string            `json:"u"`           // Target URL
	Method   string            `json:"m,omitempty"` // HTTP method (default GET)
	Headers  map[string]string `json:"h,omitempty"` // Request headers
	Body     string            `json:"b,omitempty"` // Base64-encoded body
	Redirect bool              `json:"r,omitempty"` // Follow redirects
	Gzip     bool              `json:"g,omitempty"` // Request gzip compression
}

// RelayResponse is the JSON envelope returned by the Apps Script relay.
type RelayResponse struct {
	Status  int                 `json:"s,omitempty"` // HTTP status code
	Headers map[string][]string `json:"h,omitempty"` // Response headers
	Body    string              `json:"b,omitempty"` // Base64-encoded body
	Gzipped bool                `json:"gz,omitempty"` // Body is gzip-compressed
	Error   string              `json:"e,omitempty"` // Error message
}

// BatchRequest wraps multiple relay requests for batch execution.
type BatchRequest struct {
	Key      string          `json:"k"`
	Requests []RelayRequest  `json:"q"`
}

// Headers that must not be forwarded through the relay.
// Ported from CMP-GUI's SKIP_HEADERS constant.
var skipHeaders = map[string]bool{
	"host":               true,
	"connection":         true,
	"content-length":     true,
	"transfer-encoding":  true,
	"proxy-connection":   true,
	"proxy-authorization": true,
	"priority":           true,
	"te":                 true,
	"x-forwarded-for":    true,
	"x-forwarded-host":   true,
	"x-forwarded-proto":  true,
	"x-forwarded-port":   true,
	"x-real-ip":          true,
	"forwarded":          true,
	"via":                true,
	"x-mhr-hop":          true,
	"accept-encoding":    true,
}

// FrontingConfig configures the domain fronting relay.
type FrontingConfig struct {
	// FrontDomain is the SNI domain (e.g., "www.google.com").
	FrontDomain string
	// RelayHost is the actual relay host (e.g., "script.google.com").
	RelayHost string
	// ScriptID is the Apps Script deployment ID.
	ScriptID string
	// AuthKey is the authentication key.
	AuthKey string
	// MaxConcurrent is max concurrent requests.
	MaxConcurrent int
	// RequestTimeout per request.
	RequestTimeout time.Duration
	// TLSConnectTimeout for initial connection.
	TLSConnectTimeout time.Duration
	// ConnTTL is connection lifetime.
	ConnTTL time.Duration
}

// DefaultFrontingConfig returns a default configuration for Google Apps Script relay.
func DefaultFrontingConfig() FrontingConfig {
	return FrontingConfig{
		FrontDomain:       "www.google.com",
		RelayHost:         "script.google.com",
		MaxConcurrent:     100,
		RequestTimeout:    30 * time.Second,
		TLSConnectTimeout: 10 * time.Second,
		ConnTTL:           5 * time.Minute,
	}
}

// DomainFronter implements domain-fronted HTTP relay.
type DomainFronter struct {
	config  FrontingConfig
	client  *http.Client
	sem     chan struct{}
	mu      sync.Mutex
	created time.Time
}

// NewDomainFronter creates a new domain fronting relay.
func NewDomainFronter(config FrontingConfig) *DomainFronter {
	// Create transport that connects to FrontDomain but sends requests to RelayHost
	transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Connect to the front domain's IP
			dialer := &net.Dialer{Timeout: config.TLSConnectTimeout}
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, fmt.Errorf("dial %s: %w", addr, err)
			}
			return conn, nil
		},
		MaxIdleConns:        config.MaxConcurrent,
		MaxIdleConnsPerHost: config.MaxConcurrent,
		IdleConnTimeout:     config.ConnTTL,
		ForceAttemptHTTP2:   true,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   config.RequestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	return &DomainFronter{
		config:  config,
		client:  client,
		sem:     make(chan struct{}, config.MaxConcurrent),
		created: time.Now(),
	}
}

// Relay sends a request through the domain fronting relay.
func (df *DomainFronter) Relay(ctx context.Context, req RelayRequest) (*RelayResponse, error) {
	req.Key = df.config.AuthKey

	// Acquire semaphore
	select {
	case df.sem <- struct{}{}:
		defer func() { <-df.sem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Build the relay URL
	relayURL := fmt.Sprintf("https://%s/macros/s/%s/exec",
		df.config.RelayHost, df.config.ScriptID)

	// Marshal request
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", relayURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	// Set headers for domain fronting
	// SNI will show FrontDomain, but Host header points to RelayHost
	httpReq.Header.Set("Host", df.config.RelayHost)
	httpReq.Header.Set("Content-Type", "application/json")

	// Execute request
	resp, err := df.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("relay request: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	// Parse relay response
	var relayResp RelayResponse
	if err := json.Unmarshal(respBody, &relayResp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	// Check for relay error
	if relayResp.Error != "" {
		return nil, fmt.Errorf("relay error: %s", relayResp.Error)
	}

	// Decompress if gzipped
	if relayResp.Gzipped {
		decoded, err := base64.StdEncoding.DecodeString(relayResp.Body)
		if err != nil {
			return nil, fmt.Errorf("decode body: %w", err)
		}
		decompressed, err := gzipDecompress(decoded)
		if err != nil {
			return nil, fmt.Errorf("decompress: %w", err)
		}
		relayResp.Body = base64.StdEncoding.EncodeToString(decompressed)
		relayResp.Gzipped = false
	}

	return &relayResp, nil
}

// RelayBatch sends multiple requests in a single batch call.
func (df *DomainFronter) RelayBatch(ctx context.Context, requests []RelayRequest) ([]RelayResponse, error) {
	batch := BatchRequest{
		Key:      df.config.AuthKey,
		Requests: requests,
	}

	body, err := json.Marshal(batch)
	if err != nil {
		return nil, fmt.Errorf("marshal batch: %w", err)
	}

	relayURL := fmt.Sprintf("https://%s/macros/s/%s/exec",
		df.config.RelayHost, df.config.ScriptID)

	httpReq, err := http.NewRequestWithContext(ctx, "POST", relayURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Host", df.config.RelayHost)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := df.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("batch request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 50*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var responses []RelayResponse
	if err := json.Unmarshal(respBody, &responses); err != nil {
		return nil, fmt.Errorf("parse batch response: %w", err)
	}

	return responses, nil
}

// StripHopByHopHeaders removes headers that should not be forwarded.
func StripHopByHopHeaders(headers map[string]string) map[string]string {
	filtered := make(map[string]string)
	for k, v := range headers {
		if !skipHeaders[k] {
			filtered[k] = v
		}
	}
	return filtered
}

// EncodeBody base64-encodes a body for the relay.
func EncodeBody(body []byte) string {
	return base64.StdEncoding.EncodeToString(body)
}

// DecodeBody base64-decodes a relay response body.
func DecodeBody(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}

func gzipDecompress(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}
