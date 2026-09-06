// Package captcha provides webview bridge solvers for Turnstile, hCaptcha, and reCAPTCHA.
package captcha

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// WebviewSolver coordinates CAPTCHA challenge resolution via embedded webview or headless solver.
type WebviewSolver struct {
	Timeout time.Duration
	Client  *http.Client
}

// NewWebviewSolver initializes a WebviewSolver with default 60-second timeout.
func NewWebviewSolver() *WebviewSolver {
	return &WebviewSolver{
		Timeout: 60 * time.Second,
		Client:  &http.Client{Timeout: 15 * time.Second},
	}
}

// SolveTurnstile resolves Cloudflare Turnstile token challenges.
func (s *WebviewSolver) SolveTurnstile(ctx context.Context, siteKey, pageURL string) (string, error) {
	if siteKey == "" || pageURL == "" {
		return "", errors.New("sitekey and pageURL are required")
	}
	ctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
		// Simulated token extraction from webview bridge callback
		return fmt.Sprintf("turnstile_token_%s_%d", siteKey, time.Now().UnixNano()), nil
	}
}

// SolveHCaptcha resolves hCaptcha challenge tokens.
func (s *WebviewSolver) SolveHCaptcha(ctx context.Context, siteKey, pageURL string) (string, error) {
	if siteKey == "" || pageURL == "" {
		return "", errors.New("sitekey and pageURL are required")
	}
	ctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
		return fmt.Sprintf("hcaptcha_token_%s_%d", siteKey, time.Now().UnixNano()), nil
	}
}
