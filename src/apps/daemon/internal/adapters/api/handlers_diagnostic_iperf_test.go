package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRunIperfProbeRequiresPerOperationAuthorization(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	server := &Server{}
	router.POST("/iperf", server.RunIperfProbe)

	request := httptest.NewRequest(http.MethodPost, "/iperf", strings.NewReader(`{"address":"198.51.100.10:5201","protocol":"tcp"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status=%d, want %d", response.Code, http.StatusForbidden)
	}
	if !strings.Contains(response.Body.String(), "IPERF_AUTHORIZATION_REQUIRED") {
		t.Fatalf("response=%s, want authorization error", response.Body.String())
	}
}

func TestIsIperfBadRequest(t *testing.T) {
	tests := []struct {
		err  string
		want bool
	}{
		{"unsupported protocol udp", true},
		{"target address must be host:port", true},
		{"connection refused by peer", true},
		{"parallel and reverse are mutually exclusive", true},
		{"address parameter required", true},
		{"invalid duration value", true},
		{"unknown network failure", false},
		{"executable unavailable on system path", false},
	}
	for _, tc := range tests {
		if got := isIperfBadRequest(tc.err); got != tc.want {
			t.Errorf("isIperfBadRequest(%q) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

