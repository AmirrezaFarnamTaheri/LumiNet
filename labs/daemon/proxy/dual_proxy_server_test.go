package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestDualProxyServer_HTTPProxy(t *testing.T) {
	// 1. Setup a target HTTP server
	targetMux := http.NewServeMux()
	targetMux.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Target Server Content"))
	})
	targetServer := httptest.NewServer(targetMux)
	defer targetServer.Close()

	// 2. Start DualProxyServer on dynamic local ports
	socksPort := 11080
	httpPort := 18080

	server := NewDualProxyServer()
	err := server.Start(socksPort, httpPort)
	if err != nil {
		t.Fatalf("failed to start dual proxy server: %v", err)
	}
	defer server.Stop()

	// Wait for listeners to be ready
	time.Sleep(100 * time.Millisecond)

	// 3. Test HTTP proxy routing
	proxyURL := fmt.Sprintf("http://127.0.0.1:%d", httpPort)
	parsedProxyURL, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatalf("failed to parse proxy URL: %v", err)
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(parsedProxyURL),
	}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}

	resp, err := client.Get(targetServer.URL + "/test")
	if err != nil {
		t.Fatalf("failed to request via HTTP proxy: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected HTTP 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	if string(body) != "Target Server Content" {
		t.Errorf("expected 'Target Server Content', got %q", string(body))
	}
}

func TestDualProxyServer_DoubleStartReturnsError(t *testing.T) {
	server := NewDualProxyServer()
	if err := server.Start(11081, 18081); err != nil {
		t.Fatalf("first Start failed: %v", err)
	}
	defer server.Stop()

	time.Sleep(50 * time.Millisecond)

	if err := server.Start(11082, 18082); err == nil {
		t.Error("second Start should return error: server already running")
	}
}

func TestDualProxyServer_StopIdempotent(t *testing.T) {
	server := NewDualProxyServer()
	if err := server.Start(11083, 18083); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	server.Stop()
	// Calling Stop again must not panic or deadlock
	done := make(chan struct{})
	go func() {
		server.Stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("second Stop blocked (deadlock?)")
	}
}
