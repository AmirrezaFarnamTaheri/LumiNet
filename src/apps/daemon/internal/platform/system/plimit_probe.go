// Package system provides platform integration and diagnostic helpers.

package system

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/maybeknott/luminet/internal/foundation/remoteaction"
)

// PLimit manages concurrent operations budget waiting (similar to JS p-limit).
type PLimit struct {
	concurrencyLimit int
	activeSem        chan struct{}
}

// NewPLimit instantiates a PLimit manager.
func NewPLimit(limit int) *PLimit {
	return &PLimit{
		concurrencyLimit: limit,
		activeSem:        make(chan struct{}, limit),
	}
}

// Run executes a task within the concurrency limit.
func (p *PLimit) Run(ctx context.Context, task func() error) error {
	select {
	case p.activeSem <- struct{}{}:
		defer func() { <-p.activeSem }()
		return task()
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ProbeResult represents UptimeFlare probe results from Globalping or local workers.
type ProbeResult struct {
	ProbeLocation string  `json:"location"`   // Format: country + '/' + city
	AvgPing       float64 `json:"avg_ping"`   // stats.avg
	TotalTime     float64 `json:"total_time"` // timings.total
	StatusCode    int     `json:"status_code"`
	RawBody       string  `json:"raw_body"`
	TLSAuthorized bool    `json:"tls_authorized"`
	TLSError      string  `json:"tls_error,omitempty"`
}

// HTTPResponseCheck checks response status code against expected codes ranges
// and validates response body contents, limiting body reading to 64 chars.
func HTTPResponseCheck(statusCode int, body string, expectedRanges [][2]int, forbiddenKeyword string) error {
	validCode := false
	for _, rng := range expectedRanges {
		if statusCode >= rng[0] && statusCode <= rng[1] {
			validCode = true
			break
		}
	}
	if !validCode {
		// Truncate raw body output to avoid huge error logs (64 chars)
		truncated := body
		if len(truncated) > 64 {
			truncated = truncated[:64]
		}
		return fmt.Errorf("unexpected status code %d: body content: %s", statusCode, truncated)
	}

	if forbiddenKeyword != "" && strings.Contains(body, forbiddenKeyword) {
		return fmt.Errorf("forbidden keyword found in response")
	}
	return nil
}

// FormatStatusChangeNotification formats incident markdown notifications.
func FormatStatusChangeNotification(monitorName, oldStatus, newStatus string) string {
	return fmt.Sprintf("### Incident Alert: %s\nStatus changed from **%s** to **%s**.", monitorName, oldStatus, newStatus)
}

// WebhookNotify sends Webhook alert payloads to target endpoints.
func WebhookNotify(ctx context.Context, endpoint string, payloadType string, msg string) error {
	var body []byte
	var contentType string

	switch strings.ToLower(payloadType) {
	case "json":
		contentType = "application/json"
		m := map[string]string{"msg": msg}
		body, _ = json.Marshal(m)
	case "x-www-form-urlencoded":
		contentType = "application/x-www-form-urlencoded"
		v := url.Values{}
		v.Set("msg", msg)
		body = []byte(v.Encode())
	default:
		contentType = "text/plain"
		body = []byte(msg)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	policy := remoteaction.DefaultPolicy("system.webhook.notify", remoteaction.SingleAttempt)
	outcome, err := remoteaction.Do(ctx, client, policy, func(ctx context.Context, _ int) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", contentType)
		return req, nil
	}, nil)
	if err != nil {
		return err
	}
	resp := outcome.Response
	if resp == nil {
		return fmt.Errorf("webhook notification completed without response")
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook responded with non-2xx status: %d", resp.StatusCode)
	}
	return nil
}
