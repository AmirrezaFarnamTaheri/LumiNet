package system

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTelemetryServer_RateLimit(t *testing.T) {
	s := NewTelemetryServer(2, 1)

	// Direct call without full Upgrade should hit Upgrade failure, but let's test rate limit rejection directly
	s.clientIPs["127.0.0.1"] = 1 // simulate active connection from IP

	req2 := httptest.NewRequest("GET", "/ws", nil)
	req2.RemoteAddr = "127.0.0.1:5678"
	w2 := httptest.NewRecorder()

	s.ServeHTTP(w2, req2)

	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 Too Many Requests, got %d", w2.Code)
	}
	if !strings.Contains(w2.Body.String(), "Connection limit exceeded") {
		t.Errorf("unexpected error message: %s", w2.Body.String())
	}
}
