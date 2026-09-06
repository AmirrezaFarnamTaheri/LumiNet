package relayclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGsaTunnelConn(t *testing.T) {
	var lastReceivedData []byte
	var lastAuthKey string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastAuthKey = r.Header.Get("X-GSA-Auth-Key")

		var payload TunnelPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if len(payload.Data) > 0 {
			lastReceivedData = payload.Data
		}

		resp := TunnelResponse{}
		resp.Seq = payload.Seq
		if len(payload.Data) > 0 {
			// Echo the data back
			resp.Data = payload.Data
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	authKey := "test-gsa-key"
	target := "example.com:80"
	conn := NewGsaTunnelConn(server.URL, authKey, target)
	defer conn.Close()

	// Test writing
	payload := []byte("hello gsa")
	n, err := conn.Write(payload)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(payload) {
		t.Errorf("Expected to write %d bytes, wrote %d", len(payload), n)
	}

	// Wait a brief moment for HTTP polling to catch up and echo
	time.Sleep(300 * time.Millisecond)

	// Test reading
	buf := make([]byte, 64)
	n, err = conn.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if string(buf[:n]) != "hello gsa" {
		t.Errorf("Expected 'hello gsa', got '%s'", string(buf[:n]))
	}

	if string(lastReceivedData) != "hello gsa" {
		t.Errorf("Expected server to receive 'hello gsa', got '%s'", string(lastReceivedData))
	}

	if lastAuthKey != authKey {
		t.Errorf("Expected auth key '%s', got '%s'", authKey, lastAuthKey)
	}
}

func newDirectTestGSAConn(serverURL string) *GsaTunnelConn {
	ctx, cancel := context.WithCancel(context.Background())
	return &GsaTunnelConn{
		scriptURL:  serverURL,
		realDst:    "example.com:443",
		sessionID:  "test-session",
		client:     &http.Client{Timeout: time.Second},
		state:      newRelayConnState(),
		pollCtx:    ctx,
		pollCancel: cancel,
	}
}

func TestPostRefactor229GSARejectsMismatchedResponseSequence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload TunnelPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload.Seq == nil {
			t.Fatal("GSA request omitted sequence")
		}
		wrong := *payload.Seq + 1
		_ = json.NewEncoder(w).Encode(TunnelResponse{Seq: &wrong})
	}))
	defer server.Close()

	conn := newDirectTestGSAConn(server.URL)
	defer conn.pollCancel()
	if _, err := conn.sendRequest(nil); err == nil || !strings.Contains(err.Error(), "sequence mismatch") {
		t.Fatalf("mismatch error=%v", err)
	}
}

func TestPostRefactor229GSAAcceptsLegacyOmittedSequence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(TunnelResponse{})
	}))
	defer server.Close()

	conn := newDirectTestGSAConn(server.URL)
	defer conn.pollCancel()
	if _, err := conn.sendRequest(nil); err != nil {
		t.Fatalf("legacy response rejected: %v", err)
	}
}

func TestPostRefactor229GSAWriteSequenceRollsBackOnFailedTransmission(t *testing.T) {
	requests := 0
	var seen []uint64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		var payload TunnelPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload.Wseq == nil || payload.Seq == nil {
			t.Fatal("sequenced write omitted wseq/seq")
		}
		seen = append(seen, *payload.Wseq)
		if requests == 1 {
			http.Error(w, "transient", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(TunnelResponse{Seq: payload.Seq})
	}))
	defer server.Close()

	conn := newDirectTestGSAConn(server.URL)
	defer conn.pollCancel()
	if _, err := conn.sendRequest([]byte("hello")); err == nil {
		t.Fatal("expected first transmission failure")
	}
	if _, err := conn.sendRequest([]byte("hello")); err != nil {
		t.Fatalf("retry failed: %v", err)
	}
	if len(seen) != 2 || seen[0] != 0 || seen[1] != 0 {
		t.Fatalf("write sequence was not reused after failed transmission: %v", seen)
	}
}
