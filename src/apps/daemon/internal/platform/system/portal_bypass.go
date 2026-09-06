// Package system handles low-level OS operations and bindings.

package system

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/maybeknott/luminet/internal/foundation/remoteaction"
)

// PortalConfig holds the login bypass configurations.
type PortalConfig struct {
	PortalURL     string
	Username      string
	Password      string
	CheckURL      string
	CheckInterval time.Duration
}

// PortalBypass handles portal login bypass.
type PortalBypass struct{}

func NewPortalBypass() *PortalBypass {
	return &PortalBypass{}
}

// Bypass ports Go portal login bypass scripting engine and session keep-alive loop.
func (p *PortalBypass) Bypass() {
	slog.Info("PortalBypass: portal login bypass engine initialized")
}

// PortalBypassClient handles client connection checks and logins.
type PortalBypassClient struct {
	cfg PortalConfig
}

func NewPortalBypassClient(cfg PortalConfig) *PortalBypassClient {
	return &PortalBypassClient{cfg: cfg}
}

// CheckConnectivity returns true if check URL returns 204 or is online.
func (p *PortalBypassClient) CheckConnectivity() bool {
	client := &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(p.cfg.CheckURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusNoContent
}

// Login performs the POST request login action.
func (p *PortalBypassClient) Login() error {
	data := url.Values{}
	data.Set("username", p.cfg.Username)
	data.Set("password", p.cfg.Password)

	client := &http.Client{Timeout: 10 * time.Second}
	policy := remoteaction.DefaultPolicy("portal.login.submit", remoteaction.SingleAttempt)
	outcome, err := remoteaction.Do(context.Background(), client, policy, func(ctx context.Context, _ int) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.PortalURL, strings.NewReader(data.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req, nil
	}, nil)
	if err != nil {
		return err
	}
	resp := outcome.Response
	if resp == nil {
		return fmt.Errorf("portal login completed without response")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("login failed with status: %d", resp.StatusCode)
	}
	return nil
}

// StartKeepAlive periodically checks connectivity and logs in if disconnected.
func (p *PortalBypassClient) StartKeepAlive(ctx context.Context) {
	ticker := time.NewTicker(p.cfg.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !p.CheckConnectivity() {
				_ = p.Login()
			}
		}
	}
}
