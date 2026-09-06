package diagnostics

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestStealthBrowserAuditScoresConfiguredPosture(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	opts := StealthBrowserAudit{
		UserAgent:        "Mozilla/5.0 StealthBrowser/1.0",
		AntiFingerprint:  true,
		CanvasObfuscated: true,
		AudioObfuscated:  true,
	}

	details, score, err := RunStealthAudit(ctx, opts)
	if err != nil {
		t.Fatalf("RunStealthAudit: %v", err)
	}
	if score != 100.0 {
		t.Fatalf("score = %f, want 100", score)
	}
	if !strings.Contains(details, "StealthBrowser/1.0") {
		t.Fatalf("details missing configured user-agent: %q", details)
	}
	if strings.Contains(strings.ToLower(details), "headless session") {
		t.Fatalf("audit must not claim a browser runtime session: %q", details)
	}
}

func TestStealthBrowserAuditHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := RunStealthAudit(ctx, StealthBrowserAudit{}); err == nil {
		t.Fatal("cancelled audit returned success")
	}
}
