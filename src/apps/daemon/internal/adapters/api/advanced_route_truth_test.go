package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestAdvancedSystemRouteTruthCoversRegisteredCluster(t *testing.T) {
	if got := len(advancedSystemRouteTruth); got != 20 {
		t.Fatalf("advanced route truth entries = %d, want 20", got)
	}
	for key, truth := range advancedSystemRouteTruth {
		if truth.Mode == "" {
			t.Fatalf("%s has no mode", key)
		}
		if truth.Reason == "" {
			t.Fatalf("%s has no reason", key)
		}
	}
}

func TestDisconnectedAdvancedRoutesFailClosed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := &Server{}
	tests := []struct {
		method  string
		path    string
		body    string
		handler gin.HandlerFunc
	}{
		{http.MethodPost, "/sni-spoofing", `{}`, server.HandleSNISpoofing},
		{http.MethodPost, "/dpi-desync", `{}`, server.HandleDPIDesync},
		{http.MethodPost, "/gdrive-tunnel", `{}`, server.HandleGDriveTunnel},
		{http.MethodGet, "/master-telemetry", "", server.HandleMasterTelemetry},
		{http.MethodGet, "/vpn-state", "", server.HandleVPNState},
		{http.MethodGet, "/device-profile", "", server.HandleGetDeviceProfile},
		{http.MethodPost, "/device-profile", `{}`, server.HandleSetDeviceProfile},
	}
	for _, test := range tests {
		t.Run(test.method+" "+test.path, func(t *testing.T) {
			router := gin.New()
			router.Handle(test.method, test.path, test.handler)
			writer := httptest.NewRecorder()
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			if test.body != "" {
				request.Header.Set("Content-Type", "application/json")
			}
			router.ServeHTTP(writer, request)
			if writer.Code != http.StatusNotImplemented {
				t.Fatalf("status=%d body=%s", writer.Code, writer.Body.String())
			}
			if !strings.Contains(writer.Body.String(), `"status":"unavailable"`) {
				t.Fatalf("body does not report unavailable capability: %s", writer.Body.String())
			}
		})
	}
}
