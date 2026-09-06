package relayclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestDispersalDialer_StripingAndReassembly(t *testing.T) {
	var receivedFrames []MicroFrame
	var mu sync.Mutex

	// Mock edge relay server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var frame MicroFrame
		if err := json.NewDecoder(r.Body).Decode(&frame); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		receivedFrames = append(receivedFrames, frame)
		mu.Unlock()

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	endpoints := []EdgeEndpoint{
		{Type: EdgeRunnerCloudflare, URL: server.URL, Healthy: true},
		{Type: EdgeRunnerVercel, URL: server.URL, Healthy: true},
		{Type: EdgeRunnerAWSLambda, URL: server.URL, Healthy: true},
		{Type: EdgeRunnerAppsScript, URL: server.URL, Healthy: true},
	}

	dialer := NewDispersalDialer(endpoints, 10) // 10-byte micro chunks
	conn, err := dialer.DialContext(context.Background(), "target.org:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	// Write 35 bytes (should divide into 4 frames: 10, 10, 10, 5)
	payload := []byte("0123456789ABCDEFGHIJ0123456789KLMNO")
	n, err := conn.Write(payload)
	if err != nil {
		t.Fatalf("conn.Write: %v", err)
	}
	if n != len(payload) {
		t.Errorf("wrote %d bytes, want %d", n, len(payload))
	}

	mu.Lock()
	frameCount := len(receivedFrames)
	mu.Unlock()

	if frameCount != 4 {
		t.Errorf("received %d frames, want 4", frameCount)
	}

	// Test inbound out-of-order reassembly
	// Feed frame seq 2, then seq 1, then seq 3
	conn.deliverInbound(MicroFrame{Seq: 2, Data: []byte("WORLD")})
	conn.deliverInbound(MicroFrame{Seq: 1, Data: []byte("HELLO ")})
	conn.deliverInbound(MicroFrame{Seq: 3, Data: []byte("!")})

	readBuf := make([]byte, 12)
	rn, rerr := conn.Read(readBuf)
	if rerr != nil {
		t.Fatalf("conn.Read: %v", rerr)
	}

	expectedStr := "HELLO WORLD!"
	if string(readBuf[:rn]) != expectedStr {
		t.Errorf("Read = %q, want %q", string(readBuf[:rn]), expectedStr)
	}
}
