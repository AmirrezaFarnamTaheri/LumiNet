// Package stats provides analytics, machine learning, and uptime telemetry logic.
// Ported from: UptimeFlare

package stats

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// UptimeMonitor coordinates serverless HTTP health check schedulers and
// dispatches alert notifications via Apprise webhooks.
type UptimeMonitor struct {
	appriseURL string
}

// NewUptimeMonitor initializes the checker with an Apprise webhook URL.
func NewUptimeMonitor(appriseURL string) *UptimeMonitor {
	return &UptimeMonitor{appriseURL: appriseURL}
}

// CheckScheduler runs a single HTTP ping check and dispatches a DOWN
// notification if the target returns an error or a 4xx/5xx response.
func (u *UptimeMonitor) CheckScheduler(ctx context.Context, target string) {
	slog.Info("uptime_monitor: checking target", "target", target)

	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		_ = u.DispatchNotification(ctx, target, "DOWN: Request Init Error")
		return
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		_ = u.DispatchNotification(ctx, target, "DOWN: Connection Timeout")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		_ = u.DispatchNotification(ctx, target, fmt.Sprintf("DOWN: HTTP %d", resp.StatusCode))
	} else {
		slog.Info("uptime_monitor: target healthy", "target", target, "status", resp.StatusCode)
	}
}

// DispatchNotification sends an alert payload to the Apprise webhook endpoint.
func (u *UptimeMonitor) DispatchNotification(ctx context.Context, target, state string) error {
	slog.Info("uptime_monitor: dispatching notification", "target", target, "state", state)

	if u.appriseURL == "" {
		return fmt.Errorf("uptime_monitor: apprise URL is not configured")
	}

	payload := map[string]string{
		"title": "Uptime Alert",
		"body":  fmt.Sprintf("Target: %s is in state %s at %s", target, state, time.Now().Format(time.RFC3339)),
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", u.appriseURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("uptime_monitor: apprise returned status %d: %s", resp.StatusCode, string(respBytes))
	}

	return nil
}
