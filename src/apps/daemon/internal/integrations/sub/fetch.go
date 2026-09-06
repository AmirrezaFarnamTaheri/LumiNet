package sub

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/maybeknott/luminet/internal/integrations/captchaclient"
	"github.com/maybeknott/luminet/internal/networking/proxyconfig"
)

type fetchContextKey string

const captchaSolverKey fetchContextKey = "captcha_solver"

// WithCaptchaSolver attaches a CAPTCHA solver to subscription ingestion.
func WithCaptchaSolver(ctx context.Context, solver *captchaclient.CaptchaSolver) context.Context {
	return context.WithValue(ctx, captchaSolverKey, solver)
}

func captchaSolverFromContext(ctx context.Context) *captchaclient.CaptchaSolver {
	if ctx == nil {
		return nil
	}
	solver, _ := ctx.Value(captchaSolverKey).(*captchaclient.CaptchaSolver)
	return solver
}

// Fetch downloads and parses a subscription through the canonical egress seam.
// Remote URL validation happens before any direct or relayed request is attempted.
func Fetch(ctx context.Context, urlStr string) ([]*proxyconfig.ProxyConfig, error) {
	egress := NewEgress(EgressConfig{Enabled: true})
	if err := egress.ValidateRemoteURL(ctx, urlStr); err != nil {
		return nil, err
	}

	response, err := egress.Fetch(ctx, urlStr)
	if err != nil {
		return nil, err
	}
	body := string(response.Body)
	if response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices {
		return ParseContent(body)
	}
	if response.StatusCode != http.StatusForbidden && response.StatusCode != http.StatusTooManyRequests {
		return nil, fmt.Errorf("subscription HTTP status error: %d", response.StatusCode)
	}

	solver := captchaSolverFromContext(ctx)
	if solver != nil && body != "" {
		sitekey, captchaType := captchaclient.ExtractSiteKey(body)
		if sitekey != "" && captchaType != "" {
			token, solveErr := solver.SolveCaptcha(ctx, captchaType, urlStr, sitekey, nil)
			if solveErr == nil {
				parsedURL, parseErr := url.Parse(urlStr)
				if parseErr == nil {
					query := parsedURL.Query()
					switch captchaType {
					case "turnstile":
						query.Set("cf-turnstile-response", token)
					case "userrecaptcha":
						query.Set("g-recaptcha-response", token)
					default:
						query.Set("h-captcha-response", token)
					}
					parsedURL.RawQuery = query.Encode()
					retry, retryErr := egress.Fetch(ctx, parsedURL.String())
					if retryErr == nil && retry.StatusCode >= http.StatusOK && retry.StatusCode < http.StatusMultipleChoices {
						return ParseContent(string(retry.Body))
					}
				}
			}
		}
	}

	return nil, fmt.Errorf("subscription HTTP status error: %d", response.StatusCode)
}
