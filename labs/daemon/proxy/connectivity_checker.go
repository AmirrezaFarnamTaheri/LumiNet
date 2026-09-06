// Package proxy provides connectivity and configuration checks.
// Ported from: IPScanner-main (PS1 NCSI check + ifconfig.me fallback)
// Target path: server/internal/proxy/connectivity_checker.go

package proxy

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"
)

// ConnectivityResult details internet and captive-portal status.
type ConnectivityResult struct {
	Connected  bool   `json:"connected"`
	Captive    bool   `json:"captive_portal"`
	ExternalIP string `json:"external_ip,omitempty"`
}

// ConnectivityChecker validates internet connectivity using Microsoft NCSI.
type ConnectivityChecker struct {
	httpClient *http.Client
}

// NewConnectivityChecker creates a new checker.
func NewConnectivityChecker() *ConnectivityChecker {
	return &ConnectivityChecker{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// CheckConnectivity queries NCSI and resolves the external IP if online.
func (c *ConnectivityChecker) CheckConnectivity(ctx context.Context) (ConnectivityResult, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://www.msftncsi.com/ncsi.txt", nil)
	if err != nil {
		return ConnectivityResult{}, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return ConnectivityResult{Connected: false, Captive: false}, nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ConnectivityResult{}, err
	}

	text := string(body)
	if resp.StatusCode != http.StatusOK || text != "Microsoft NCSI" {
		// Response hijacked or changed: captive portal detected!
		return ConnectivityResult{Connected: true, Captive: true}, nil
	}

	// NCSI passed! Try to resolve external IP.
	ipReq, err := http.NewRequestWithContext(ctx, "GET", "https://ifconfig.me/ip", nil)
	if err != nil {
		return ConnectivityResult{Connected: true, Captive: false}, nil
	}
	// Add user-agent to return clean text IP
	ipReq.Header.Set("User-Agent", "curl/7.79.1")

	ipResp, err := c.httpClient.Do(ipReq)
	if err != nil {
		return ConnectivityResult{Connected: true, Captive: false}, nil
	}
	defer ipResp.Body.Close()

	ipBody, err := io.ReadAll(ipResp.Body)
	var extIP string
	if err == nil {
		extIP = strings.TrimSpace(string(ipBody))
	}

	return ConnectivityResult{
		Connected:  true,
		Captive:    false,
		ExternalIP: extIP,
	}, nil
}
