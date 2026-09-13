package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestGetTelegramMTProtoProxiesRejectsUnsafeChannelURL(t *testing.T) {
	// The subscription fetcher intentionally rejects non-public/non-HTTPS
	// destinations before any request is sent. Keep the API-level regression
	// test aligned with that SSRF boundary instead of bypassing it with a local
	// httptest server.
	unsafeChannel := "http://127.0.0.1:8080/channel"

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)

	server := &Server{}
	r.GET("/api/telegram/mtproto", server.GetTelegramMTProtoProxies)

	req, err := http.NewRequest(http.MethodGet, "/api/telegram/mtproto?channel="+url.QueryEscape(unsafeChannel), nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected unsafe channel rejection, got status %d. Body: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "non-public address") && !strings.Contains(body, "HTTPS on port 443") {
		t.Fatalf("unsafe channel rejection did not expose the SSRF-policy reason: %s", body)
	}
}
