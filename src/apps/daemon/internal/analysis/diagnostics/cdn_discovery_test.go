package diagnostics

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestCDNDiscoveryEngine_DiscoverCleanIPs(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "example.com" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><head><title>My Clean Origin</title></head></html>"))
	}))
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("failed to parse test server url: %v", err)
	}

	host, port, _ := strings.Cut(u.Host, ":")
	if host == "" {
		host = "127.0.0.1"
	}

	engine := NewCDNDiscoveryEngine()
	// Overwrite timeout for fast local testing
	engine.Timeout = 1 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Verify discovery with correct port/IP and expected title
	cleanIPs, err := engine.DiscoverCleanIPs(ctx, "example.com", []string{net.JoinHostPort(host, port)}, "Clean Origin")
	if err != nil {
		t.Fatalf("DiscoverCleanIPs failed: %v", err)
	}

	if len(cleanIPs) != 1 {
		t.Errorf("expected 1 clean IP, got %v", cleanIPs)
	}

	// Verify discovery fails with wrong expected title
	cleanIPsWrongTitle, err := engine.DiscoverCleanIPs(ctx, "example.com", []string{net.JoinHostPort(host, port)}, "Wrong Title")
	if err != nil {
		t.Fatalf("DiscoverCleanIPs failed: %v", err)
	}

	if len(cleanIPsWrongTitle) != 0 {
		t.Errorf("expected 0 clean IPs for wrong title, got %v", cleanIPsWrongTitle)
	}
}
