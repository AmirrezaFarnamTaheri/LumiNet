package system

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPLimit(t *testing.T) {
	limiter := NewPLimit(2)
	ctx := context.Background()

	taskRun := false
	err := limiter.Run(ctx, func() error {
		taskRun = true
		return nil
	})

	if err != nil || !taskRun {
		t.Errorf("concurrency limiter task failed: err=%v, run=%t", err, taskRun)
	}
}

func TestHTTPResponseCheck(t *testing.T) {
	ranges := [][2]int{{200, 299}}

	// Good case
	err := HTTPResponseCheck(204, "Body content", ranges, "")
	if err != nil {
		t.Errorf("unexpected error on valid status code: %v", err)
	}

	// Mismatched status code
	err = HTTPResponseCheck(400, "Bad Request detail very long text here to verify truncation", ranges, "")
	if err == nil {
		t.Error("expected error on invalid status code, got nil")
	}

	// Forbidden keyword
	err = HTTPResponseCheck(200, "This contains forbidden content", ranges, "forbidden")
	if err == nil {
		t.Error("expected error on forbidden content, got nil")
	}
}

func TestFormatStatusChangeNotification(t *testing.T) {
	res := FormatStatusChangeNotification("TestServer", "DOWN", "UP")
	if !contains(res, "DOWN") || !contains(res, "UP") {
		t.Errorf("FormatStatusChangeNotification output mismatch: %s", res)
	}
}

func TestWebhookNotify(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := WebhookNotify(ctx, srv.URL, "json", "Status Check Passed")
	if err != nil {
		t.Errorf("WebhookNotify JSON type failed: %v", err)
	}

	err = WebhookNotify(ctx, srv.URL, "x-www-form-urlencoded", "Status Check Passed")
	if err != nil {
		t.Errorf("WebhookNotify Form type failed: %v", err)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || stringsContains(s, substr))
}

func stringsContains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
