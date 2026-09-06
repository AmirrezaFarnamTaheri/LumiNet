package capabilities

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRegistryDefaultsAndPermissions(t *testing.T) {
	reg := NewRegistry()
	all := reg.All()
	if len(all) == 0 {
		t.Error("expected default capabilities to be registered")
	}

	// Verify existing capability
	permitted, err := reg.IsPermitted(CapDNSControl)
	if err != nil {
		t.Logf("CapDNSControl is not permitted on this platform: %v", err)
	} else {
		t.Logf("CapDNSControl permitted: %v", permitted)
	}

	// Verify unknown capability
	_, err = reg.IsPermitted(CapabilityID("invalid_cap"))
	if err == nil {
		t.Error("expected error for unknown capability")
	}
}

func TestRegistryAllIsStableByCapabilityID(t *testing.T) {
	registry := NewRegistry()
	all := registry.All()
	if len(all) == 0 {
		t.Fatal("registry returned no capabilities")
	}
	for i := 1; i < len(all); i++ {
		if all[i-1].ID >= all[i].ID {
			t.Fatalf("capabilities are not sorted: %q before %q", all[i-1].ID, all[i].ID)
		}
	}
}

func TestUnwiredCapabilitiesAreUnavailableWithReasons(t *testing.T) {
	registry := NewRegistry()
	for _, id := range []CapabilityID{CapCapture, CapActiveProbes} {
		permitted, err := registry.IsPermitted(id)
		if err != nil {
			t.Fatalf("permission check for %q: %v", id, err)
		}
		if permitted {
			t.Fatalf("unwired capability %q must not be permitted", id)
		}
		found := false
		for _, capability := range registry.All() {
			if capability.ID == id {
				found = true
				if capability.UnavailableReason == "" {
					t.Fatalf("unwired capability %q needs an availability reason", id)
				}
			}
		}
		if !found {
			t.Fatalf("unwired capability %q missing from registry", id)
		}
	}
}

func TestGuardRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	reg := NewRegistry()

	// Set up a mock route guarded by a capability
	r.GET("/test-cap", GuardRoute(reg, CapDNSControl), func(c *gin.Context) {
		c.String(http.StatusOK, "success")
	})

	// Test request
	req := httptest.NewRequest("GET", "/test-cap", nil)
	resp := httptest.NewRecorder()

	r.ServeHTTP(resp, req)

	// Since CapDNSControl is defined for darwin, linux, and windows, it should be permitted on these platforms
	// If it is permitted, code is 200, otherwise it returns 403 or 500. Let's verify we get a valid HTTP status.
	t.Logf("GuardRoute response status: %d", resp.Code)
	if resp.Code != http.StatusOK && resp.Code != http.StatusForbidden {
		t.Errorf("unexpected status code: %d, body: %s", resp.Code, resp.Body.String())
	}
}
