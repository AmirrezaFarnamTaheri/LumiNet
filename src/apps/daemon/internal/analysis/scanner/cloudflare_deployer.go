package scanner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/maybeknott/luminet/internal/foundation/remoteaction"
)

// CloudflareDeployer handles API deployment of scripts to Cloudflare Workers.
type CloudflareDeployer struct {
	client *http.Client
}

// NewCloudflareDeployer initializes the deployer.
func NewCloudflareDeployer() *CloudflareDeployer {
	return &CloudflareDeployer{
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// DeployWorkerScript uploads a javascript script to a Cloudflare Worker route.
func (d *CloudflareDeployer) DeployWorkerScript(ctx context.Context, email, apiToken, accountID, scriptName, scriptBody string) error {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/accounts/%s/workers/scripts/%s", accountID, scriptName)

	policy := remoteaction.DefaultPolicy("cloudflare.scanner-worker.upload", remoteaction.Idempotent)
	policy.RateLimitScope = "provider.cloudflare"
	outcome, err := remoteaction.Do(ctx, d.client, policy, func(ctx context.Context, _ int) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewBufferString(scriptBody))
		if err != nil {
			return nil, fmt.Errorf("failed to create worker request: %w", err)
		}
		req.Header.Set("X-Auth-Email", email)
		req.Header.Set("Authorization", "Bearer "+apiToken)
		req.Header.Set("Content-Type", "application/javascript")
		return req, nil
	}, nil)
	if err != nil {
		return fmt.Errorf("failed to execute worker request: %w", err)
	}
	resp := outcome.Response
	if resp == nil {
		return fmt.Errorf("Cloudflare worker upload completed without response")
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		return fmt.Errorf("Cloudflare API error (status %d): %s", resp.StatusCode, string(body))
	}

	return nil
}
