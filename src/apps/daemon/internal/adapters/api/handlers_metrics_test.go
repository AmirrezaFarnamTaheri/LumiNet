package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestMetricsRouteFailsClosedWithoutProductionMetricsPipeline(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := &Server{}
	router := gin.New()
	router.GET("/api/metrics", server.getMetrics)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/metrics", nil))

	if response.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotImplemented)
	}
	if contentType := response.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/plain") {
		t.Fatalf("content type = %q", contentType)
	}
	body := response.Body.String()
	if !strings.Contains(body, "metrics unavailable") {
		t.Fatalf("metrics route must fail closed with explicit capability truth, got:\n%s", body)
	}
}
