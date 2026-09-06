// Package relay provides an HTTP relay proxy for traffic forwarding.
// Ported from aio-downloader's exit node implementations.
package relay

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// RelayRequest represents a JSON relay request.
// Wire format: {u: url, m: method, h: headers, b: body(base64), r: redirect}
type RelayRequest struct {
	URL      string            `json:"u"`
	Method   string            `json:"m"`
	Headers  map[string]string `json:"h"`
	Body     string            `json:"b"` // base64-encoded
	Redirect bool              `json:"r"`
}

// RelayResponse represents a JSON relay response.
// Wire format: {s: status, h: headers, b: body(base64), e: error}
type RelayResponse struct {
	Status  int                 `json:"s,omitempty"`
	Headers map[string][]string `json:"h,omitempty"`
	Body    string              `json:"b,omitempty"` // base64-encoded
	Error   string              `json:"e,omitempty"`
}

// Hop-by-hop headers that must not be forwarded.
// Ported from aio-downloader's python-exit-node.py.
var stripHeaders = map[string]bool{
	"host":               true,
	"connection":         true,
	"content-length":     true,
	"transfer-encoding":  true,
	"keep-alive":         true,
	"te":                 true,
	"trailer":            true,
	"upgrade":            true,
	"proxy-connection":   true,
	"proxy-authorization": true,
	"proxy-authenticate": true,
	"x-forwarded-for":    true,
	"x-forwarded-host":   true,
	"x-forwarded-proto":  true,
	"x-forwarded-port":   true,
	"x-real-ip":          true,
	"forwarded":          true,
	"via":                true,
	"accept-encoding":    true,
}

// RelayHandler creates an http.Handler that processes relay requests.
func RelayHandler(apiKey string, maxBody int64) http.Handler {
	client := &http.Client{
		Timeout: 45 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        256,
			MaxIdleConnsPerHost: 64,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Health check
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Authenticate
		if apiKey != "" {
			if r.Header.Get("X-Relay-Key") != apiKey {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}

		// Parse request
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Limit body size
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}

		var req RelayRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		// Execute relay
		resp := executeRelay(r.Context(), client, &req)

		// Send response
		w.Header().Set("Content-Type", "application/json")
		if resp.Error != "" {
			w.WriteHeader(http.StatusBadGateway)
		}
		json.NewEncoder(w).Encode(resp)
	})
}

func executeRelay(ctx context.Context, client *http.Client, req *RelayRequest) RelayResponse {
	// Decode body
	var bodyReader io.Reader
	if req.Body != "" {
		decoded, err := base64.StdEncoding.DecodeString(req.Body)
		if err != nil {
			return RelayResponse{Error: fmt.Sprintf("invalid base64 body: %v", err)}
		}
		bodyReader = strings.NewReader(string(decoded))
	}

	// Create request
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, bodyReader)
	if err != nil {
		return RelayResponse{Error: fmt.Sprintf("failed to create request: %v", err)}
	}

	// Set headers (skip hop-by-hop)
	for k, v := range req.Headers {
		if !stripHeaders[strings.ToLower(k)] {
			httpReq.Header.Set(k, v)
		}
	}

	// Configure redirect policy
	if !req.Redirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	// Execute
	resp, err := client.Do(httpReq)
	if err != nil {
		return RelayResponse{Error: fmt.Sprintf("request failed: %v", err)}
	}
	defer resp.Body.Close()

	// Read response body (limit to 64 MiB)
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024*1024))
	if err != nil {
		return RelayResponse{Error: fmt.Sprintf("failed to read response: %v", err)}
	}

	// Build response headers
	headers := make(map[string][]string)
	for k, v := range resp.Header {
		if !stripHeaders[strings.ToLower(k)] {
			headers[k] = v
		}
	}

	return RelayResponse{
		Status:  resp.StatusCode,
		Headers: headers,
		Body:    base64.StdEncoding.EncodeToString(respBody),
	}
}

// HealthCheckHandler returns a simple health check handler.
func HealthCheckHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}
}
