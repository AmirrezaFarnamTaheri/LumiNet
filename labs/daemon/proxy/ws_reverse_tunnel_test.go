package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWSReverseTunnelIntegration(t *testing.T) {
	token := "supersecret"
	manager := NewWSReverseTunnelManager(token)

	// Create test server for WS and reverse HTTP requests
	mux := http.NewServeMux()
	mux.HandleFunc("/___wsrt___/ws", manager.ServeHTTPWS)
	mux.HandleFunc("/", manager.ServeHTTPReverse)

	server := httptest.NewServer(mux)
	defer server.Close()

	// Client handler to respond to requests
	clientHandler := func(req WSReverseTunnelHTTPRequestMessage) WSReverseTunnelHTTPResponseMessage {
		return WSReverseTunnelHTTPResponseMessage{
			StatusCode: http.StatusOK,
			Headers:    map[string]string{"Content-Type": "text/plain"},
			Body:       []byte("Hello from tunneled client: path=" + req.URL),
		}
	}

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/___wsrt___/ws"

	// 1. Connect Client with valid token
	clientConn, err := DialTunnelClient(wsURL, token, "my-app", clientHandler)
	if err != nil {
		t.Fatalf("failed to connect tunnel client: %v", err)
	}
	defer clientConn.Close()

	// Wait for registration
	time.Sleep(100 * time.Millisecond)

	// 2. Perform reverse request via the server
	reqURL := server.URL + "/my-app/some/endpoint?param=1"
	resp, err := http.Get(reqURL)
	if err != nil {
		t.Fatalf("reverse HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	bodyBytes, err := ioReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	expectedBody := "Hello from tunneled client: path=/some/endpoint?param=1"
	if string(bodyBytes) != expectedBody {
		t.Errorf("expected body %q, got %q", expectedBody, string(bodyBytes))
	}
}

func TestWSReverseTunnelAuthFailure(t *testing.T) {
	token := "supersecret"
	manager := NewWSReverseTunnelManager(token)

	mux := http.NewServeMux()
	mux.HandleFunc("/___wsrt___/ws", manager.ServeHTTPWS)

	server := httptest.NewServer(mux)
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/___wsrt___/ws"

	// Connect with invalid token
	_, err := DialTunnelClient(wsURL, "wrongtoken", "my-app", func(req WSReverseTunnelHTTPRequestMessage) WSReverseTunnelHTTPResponseMessage {
		return WSReverseTunnelHTTPResponseMessage{}
	})
	if err == nil {
		t.Fatal("expected authentication failure for wrong token, got nil error")
	}
}

func ioReadAll(r ioReader) ([]byte, error) {
	var buf []byte
	b := make([]byte, 512)
	for {
		n, err := r.Read(b)
		if n > 0 {
			buf = append(buf, b[:n]...)
		}
		if err != nil {
			break
		}
	}
	return buf, nil
}

type ioReader interface {
	Read(p []byte) (n int, err error)
}
