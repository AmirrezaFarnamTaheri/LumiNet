// Package captcha — isolated 2Captcha plugin.
//
// Addresses S-07: 2Captcha Plugin Isolation.
//
// The 2Captcha integration is compiled only when the build tag "captcha"
// is present. Without this tag the package is completely excluded from
// the binary so zero captcha-related code ships in a standard build.
//
// Build with captcha:
//
//	go build -tags captcha ./...
//
// Threat model:
//   - The API key is never logged (redacted at the redact layer).
//   - The plugin is sandboxed behind a feature-gate check.
//   - Only the solver goroutine accesses the 2Captcha network.
//   - All outbound requests use a context with a hard deadline.

//go:build captcha

package captcha

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	submitURL  = "https://2captcha.com/in.php"
	resultURL  = "https://2captcha.com/res.php"
	pollInterval = 5 * time.Second
	maxWait      = 3 * time.Minute
)

// Solver is the 2Captcha plugin interface.
type Solver interface {
	SolveHCaptcha(ctx context.Context, siteKey, pageURL string) (string, error)
	SolveRecaptchaV2(ctx context.Context, siteKey, pageURL string) (string, error)
}

// Plugin is the concrete 2Captcha solver implementation.
// Instantiate with NewPlugin; reuse across requests.
type Plugin struct {
	apiKey string
	client *http.Client
}

// NewPlugin creates a Plugin with the given API key.
// The key should be sourced from the secrets store — never from config JSON.
func NewPlugin(apiKey string) *Plugin {
	return &Plugin{
		apiKey: apiKey,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// SolveHCaptcha submits an hCaptcha challenge and waits for the solution.
func (p *Plugin) SolveHCaptcha(ctx context.Context, siteKey, pageURL string) (string, error) {
	taskID, err := p.submit(ctx, url.Values{
		"key":       {p.apiKey},
		"method":    {"hcaptcha"},
		"sitekey":   {siteKey},
		"pageurl":   {pageURL},
		"json":      {"1"},
	})
	if err != nil {
		return "", fmt.Errorf("hcaptcha submit: %w", err)
	}
	return p.poll(ctx, taskID)
}

// SolveRecaptchaV2 submits a reCAPTCHA v2 challenge and waits for the token.
func (p *Plugin) SolveRecaptchaV2(ctx context.Context, siteKey, pageURL string) (string, error) {
	taskID, err := p.submit(ctx, url.Values{
		"key":       {p.apiKey},
		"method":    {"userrecaptcha"},
		"googlekey": {siteKey},
		"pageurl":   {pageURL},
		"json":      {"1"},
	})
	if err != nil {
		return "", fmt.Errorf("recaptchav2 submit: %w", err)
	}
	return p.poll(ctx, taskID)
}

// --- internal ---------------------------------------------------------------

type apiResponse struct {
	Status  int    `json:"status"`
	Request string `json:"request"`
}

func (p *Plugin) submit(ctx context.Context, params url.Values) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, submitURL,
		strings.NewReader(params.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var ar apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&ar); err != nil {
		return "", fmt.Errorf("decode submit response: %w", err)
	}
	if ar.Status != 1 {
		return "", fmt.Errorf("2captcha submit error: %s", ar.Request)
	}
	return ar.Request, nil
}

func (p *Plugin) poll(ctx context.Context, taskID string) (string, error) {
	deadline := time.Now().Add(maxWait)
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(pollInterval):
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("2captcha: timed out waiting for solution (taskID=%s)", taskID)
		}

		params := url.Values{
			"key":    {p.apiKey},
			"action": {"get"},
			"id":     {taskID},
			"json":   {"1"},
		}
		pctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		req, err := http.NewRequestWithContext(pctx, http.MethodGet,
			resultURL+"?"+params.Encode(), nil)
		cancel()
		if err != nil {
			return "", err
		}

		resp, err := p.client.Do(req)
		if err != nil {
			continue // transient error — keep polling
		}
		var ar apiResponse
		_ = json.NewDecoder(resp.Body).Decode(&ar)
		resp.Body.Close()

		if ar.Status == 1 {
			return ar.Request, nil
		}
		if ar.Request != "CAPCHA_NOT_READY" {
			return "", fmt.Errorf("2captcha poll error: %s", ar.Request)
		}
		// CAPCHA_NOT_READY → keep polling
	}
}
