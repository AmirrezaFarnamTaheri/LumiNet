package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/foundation/capabilities"
)

func TestCapabilitiesReflectRegistryAvailability(t *testing.T) {
	gin.SetMode(gin.TestMode)
	registry := capabilities.NewRegistry()
	if err := registry.SetMaturity(capabilities.CapDiagnostics, capabilities.MaturityUnavailable); err != nil {
		t.Fatal(err)
	}
	server := &Server{capabilities: registry}
	router := gin.New()
	router.GET("/capabilities", server.GetCapabilities)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/capabilities", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("expected capabilities response, got %d", response.Code)
	}

	var payload struct {
		Capabilities []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	for _, capability := range payload.Capabilities {
		if capability.ID == string(capabilities.CapDiagnostics) && capability.Status != "unavailable" {
			t.Fatalf("diagnostics must reflect registry failure, got %q", capability.Status)
		}
	}
}
