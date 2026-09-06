package system

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestPortalBypass(t *testing.T) {
	var loginCount int32

	// Setup mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/portal":
			if r.Method == "POST" {
				username := r.FormValue("username")
				password := r.FormValue("password")
				if username == "testuser" && password == "testpass" {
					atomic.AddInt32(&loginCount, 1)
					w.WriteHeader(http.StatusOK)
				} else {
					w.WriteHeader(http.StatusUnauthorized)
				}
			}
		case "/check":
			// First request: offline (returns 302 portal redirect or 500)
			// Subsequent requests: online (returns 204)
			if atomic.LoadInt32(&loginCount) == 0 {
				w.WriteHeader(http.StatusFound) // redirect to portal
			} else {
				w.WriteHeader(http.StatusNoContent)
			}
		}
	}))
	defer server.Close()

	cfg := PortalConfig{
		PortalURL:     server.URL + "/portal",
		Username:      "testuser",
		Password:      "testpass",
		CheckURL:      server.URL + "/check",
		CheckInterval: 50 * time.Millisecond,
	}

	client := NewPortalBypassClient(cfg)

	// Check connectivity initially (should be false since login count is 0)
	if client.CheckConnectivity() {
		t.Error("expected connectivity to be offline initially")
	}

	// Login manually
	err := client.Login()
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	if atomic.LoadInt32(&loginCount) != 1 {
		t.Errorf("expected login count to be 1, got %d", loginCount)
	}

	// Check connectivity after login (should be true)
	if !client.CheckConnectivity() {
		t.Error("expected connectivity to be online after login")
	}

	// Reset login count and test background keepalive loop
	atomic.StoreInt32(&loginCount, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go client.StartKeepAlive(ctx)

	// Wait for background check & automatic re-login
	time.Sleep(150 * time.Millisecond)

	if atomic.LoadInt32(&loginCount) == 0 {
		t.Error("expected automatic login to have run in the background keep-alive loop")
	}
}
