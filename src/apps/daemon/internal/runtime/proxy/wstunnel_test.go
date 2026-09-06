package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestWebSocketTunneling(t *testing.T) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify custom and randomized headers
		ua := r.Header.Get("User-Agent")
		if ua == "" {
			t.Error("Missing User-Agent header")
		}
		cust := r.Header.Get("X-Custom-Header")
		if cust != "LumiTest" {
			t.Errorf("Unexpected X-Custom-Header: %s", cust)
		}

		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Logf("Failed to upgrade: %v", err)
			return
		}
		defer ws.Close()

		for {
			mt, message, err := ws.ReadMessage()
			if err != nil {
				break
			}
			err = ws.WriteMessage(mt, message)
			if err != nil {
				break
			}
		}
	}))
	defer server.Close()

	wsURL := strings.Replace(server.URL, "http://", "ws://", 1)

	client := NewWsTunnelClient(wsURL)
	client.Headers["X-Custom-Header"] = "LumiTest"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := client.EstablishTunnel(ctx)
	if err != nil {
		t.Fatalf("EstablishTunnel failed: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello websocket tunnel")
	_, err = conn.Write(payload)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if string(buf[:n]) != string(payload) {
		t.Errorf("Got message %q, want %q", buf[:n], payload)
	}
}

func TestStunnelTunneling(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello stunnel"))
	}))
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("failed to parse url: %v", err)
	}

	client := NewWsTunnelClient(server.URL)
	client.TunnelType = 2 // Stunnel
	client.UseUTLS = true
	client.Fingerprint = "chrome"
	h := sha256.Sum256(server.Certificate().Raw)
	client.PinnedFingerprint = hex.EncodeToString(h[:])

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := client.EstablishTunnel(ctx)
	if err != nil {
		t.Fatalf("EstablishTunnel failed: %v", err)
	}
	defer conn.Close()

	reqStr := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", u.Host)
	_, err = conn.Write([]byte(reqStr))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	respStr := string(buf[:n])
	if !strings.Contains(respStr, "hello stunnel") {
		t.Errorf("Expected response to contain 'hello stunnel', got: %s", respStr)
	}
}

func TestStunnelRejectsUntrustedCertificateWithoutPin(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	client := NewWsTunnelClient(server.URL)
	client.TunnelType = 2
	client.UseUTLS = true
	client.Fingerprint = "chrome"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if conn, err := client.EstablishTunnel(ctx); err == nil {
		_ = conn.Close()
		t.Fatal("EstablishTunnel accepted an untrusted certificate without a pin")
	}
}

func TestWsTunnelSocketProtect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	wsURL := strings.Replace(server.URL, "http://", "ws://", 1)
	client := NewWsTunnelClient(wsURL)
	client.TunnelType = 1 // WSTunnel

	var protectedFd int
	client.SocketProtect = func(fd int) {
		protectedFd = fd
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, _ = client.EstablishTunnel(ctx)

	if protectedFd == 0 {
		t.Error("Expected SocketProtect callback to be called with a non-zero file descriptor")
	}
}

func TestStunnelCertPinning(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	// Get actual server certificate fingerprint
	certs := server.Certificate()
	h := sha256.Sum256(certs.Raw)
	actualFingerprint := hex.EncodeToString(h[:])

	client := NewWsTunnelClient(server.URL)
	client.TunnelType = 2 // Stunnel
	client.UseUTLS = true
	client.Fingerprint = "chrome"
	client.PinnedFingerprint = actualFingerprint

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := client.EstablishTunnel(ctx)
	if err != nil {
		t.Fatalf("EstablishTunnel with correct pinned fingerprint failed: %v", err)
	}
	conn.Close()

	// Test with incorrect fingerprint
	clientBad := NewWsTunnelClient(server.URL)
	clientBad.TunnelType = 2
	clientBad.UseUTLS = true
	clientBad.Fingerprint = "chrome"
	clientBad.PinnedFingerprint = "badfingerprint1234567890abcdef1234567890abcdef1234567890abcdef"

	_, err = clientBad.EstablishTunnel(ctx)
	if err == nil {
		t.Errorf("expected error for mismatching fingerprint, got nil")
	}
}
