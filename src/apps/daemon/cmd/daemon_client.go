package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	controlsession "github.com/maybeknott/luminet/contracts/session"
)

// loadDaemonSession reads the versioned local control descriptor. A missing
// file means no daemon was discovered; an invalid descriptor is an error and
// must not be treated as permission to create a competing in-process manager.
func loadDaemonSession(dd string) (*controlsession.Descriptor, error) {
	d, err := controlsession.ReadFile(filepath.Join(dd, "session.json"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("load daemon session: %w", err)
	}
	return &d, nil
}

const maxDaemonResponseBytes = 4 << 20

// forwardToDaemon forwards to a discovered daemon. Network failures and HTTP
// 4xx/5xx responses are errors so callers cannot silently fall back to a
// second in-process authority.
func forwardToDaemon(d controlsession.Descriptor, endpoint, method string, body []byte) ([]byte, int, error) {
	return forwardDaemonRequest(context.Background(), d, endpoint, method, body)
}

func forwardDaemonRequest(ctx context.Context, d controlsession.Descriptor, endpoint, method string, body []byte) ([]byte, int, error) {
	base, err := normalizeLoopbackDaemonURL(d.APIURL)
	if err != nil {
		return nil, 0, err
	}
	relative, err := url.Parse(endpoint)
	if err != nil || relative.IsAbs() || relative.Host != "" || !strings.HasPrefix(relative.Path, "/") {
		return nil, 0, errors.New("forward endpoint must be an absolute-path reference")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, method, base+relative.RequestURI(), bytes.NewReader(body))
	if err != nil {
		return nil, 0, fmt.Errorf("build daemon request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if d.APIKey != "" {
		req.Header.Set("X-API-Key", d.APIKey)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("discovered daemon unreachable: %w", err)
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, maxDaemonResponseBytes+1))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read daemon response: %w", err)
	}
	if len(responseBody) > maxDaemonResponseBytes {
		return nil, resp.StatusCode, errors.New("daemon response exceeds size limit")
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return responseBody, resp.StatusCode, fmt.Errorf("discovered daemon returned HTTP %d", resp.StatusCode)
	}
	return responseBody, resp.StatusCode, nil
}

func waitDaemonReady(ctx context.Context, apiURL string, interval time.Duration) error {
	base, err := normalizeLoopbackDaemonURL(apiURL)
	if err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if interval <= 0 {
		interval = 25 * time.Millisecond
	}
	client := &http.Client{Timeout: time.Second}
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/health", nil)
		if err != nil {
			return fmt.Errorf("build health request: %w", err)
		}
		resp, requestErr := client.Do(req)
		if requestErr == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			if requestErr != nil {
				return fmt.Errorf("daemon did not become ready: %w", requestErr)
			}
			return fmt.Errorf("daemon did not become ready: %w", ctx.Err())
		case <-timer.C:
		}
	}
}

func normalizeLoopbackDaemonURL(raw string) (string, error) {
	base, err := controlsession.NormalizeAPIURL(raw)
	if err != nil {
		return "", err
	}
	parsed, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("parse daemon URL: %w", err)
	}
	host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	if host == "localhost" {
		return base, nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", errors.New("session discovery endpoint must be loopback")
	}
	return base, nil
}

// jsonMarshal is a convenience wrapper around encoding/json.Marshal used by
// CLI commands that need to serialize payloads for daemon forwarding.
func jsonMarshal(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}
