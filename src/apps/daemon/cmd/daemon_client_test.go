package cmd

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	controlsession "github.com/maybeknott/luminet/contracts/session"
)

func TestForwardDaemonRequestRejectsHTTPFailure(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "test-key" {
			t.Errorf("X-API-Key = %q", r.Header.Get("X-API-Key"))
		}
		http.Error(w, "already running", http.StatusConflict)
	}))
	defer server.Close()
	d := controlsession.Descriptor{APIURL: server.URL, APIKey: "test-key"}
	_, status, err := forwardDaemonRequest(context.Background(), d, "/api/system/evasion-tunnel", http.MethodPost, []byte(`{}`))
	if status != http.StatusConflict || err == nil {
		t.Fatalf("forwardDaemonRequest() status=%d err=%v, want 409 error", status, err)
	}
}

func TestForwardDaemonRequestRejectsUnreachableDaemon(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, _, err = forwardDaemonRequest(ctx, controlsession.Descriptor{APIURL: "http://" + addr}, "/health", http.MethodGet, nil)
	if err == nil {
		t.Fatal("forwardDaemonRequest() accepted unreachable discovered daemon")
	}
}

func TestWaitDaemonReadyRetriesUntilHealthSucceeds(t *testing.T) {
	t.Parallel()
	var attempts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			http.NotFound(w, r)
			return
		}
		attempts++
		if attempts < 3 {
			http.Error(w, "starting", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := waitDaemonReady(ctx, server.URL, 5*time.Millisecond); err != nil {
		t.Fatalf("waitDaemonReady() error = %v", err)
	}
	if attempts < 3 {
		t.Fatalf("waitDaemonReady() attempts = %d, want retry", attempts)
	}
}
