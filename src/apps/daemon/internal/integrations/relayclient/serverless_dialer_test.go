package relayclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestServerlessDialer(t *testing.T) {
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()

		// Read metadata first
		_, msg, err := ws.ReadMessage()
		if err != nil {
			return
		}

		var meta map[string]interface{}
		if err := json.Unmarshal(msg, &meta); err != nil {
			return
		}

		// Use float64 check as JSON unmarshaling maps numbers to float64
		portVal, _ := meta["port"].(float64)
		if meta["host"] != "example.com" || int(portVal) != 80 {
			_ = ws.WriteMessage(websocket.TextMessage, []byte(`{"status":"error"}`))
			return
		}

		// Send success confirmation
		_ = ws.WriteMessage(websocket.TextMessage, []byte(`{"status":"connected"}`))

		// Echo back binary data
		_, data, err := ws.ReadMessage()
		if err == nil {
			_ = ws.WriteMessage(websocket.BinaryMessage, data)
		}
	}))
	defer server.Close()

	relayURL := strings.Replace(server.URL, "http://", "ws://", 1)
	dialer := NewServerlessDialer(relayURL)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := dialer.DialTarget(ctx, "example.com", 80)
	if err != nil {
		t.Fatalf("DialTarget failed: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello serverless")
	_, err = conn.Write(payload)
	if err != nil {
		t.Fatalf("failed to write payload: %v", err)
	}

	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	if string(buf[:n]) != "hello serverless" {
		t.Errorf("expected 'hello serverless', got '%s'", string(buf[:n]))
	}
}

func TestServerlessDialerRejectsUntrustedTLS(t *testing.T) {
	upgrader := websocket.Upgrader{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = upgrader.Upgrade(w, r, nil)
	}))
	defer server.Close()

	relayURL := strings.Replace(server.URL, "https://", "wss://", 1)
	dialer := NewServerlessDialer(relayURL)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if conn, err := dialer.DialTarget(ctx, "example.com", 80); err == nil {
		_ = conn.Close()
		t.Fatal("DialTarget accepted an untrusted relay certificate")
	}
}

func TestHTTPServerlessConnCloseIsIdempotent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(TunnelResponse{})
	}))
	defer server.Close()

	conn := NewHttpServerlessConn(server.URL, "example.com:80")
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("second Close() = %v", err)
	}
	if _, err := conn.Write([]byte("after-close")); err == nil {
		t.Fatal("Write after Close unexpectedly succeeded")
	}
}

func TestServerlessDialer_HTTP(t *testing.T) {
	// Create mock HTTP POST relay server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		var payload TunnelPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if payload.SessionID == "" || payload.Target != "example.com:80" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		var respData []byte
		if len(payload.Data) > 0 {
			// Echo data back in the response
			respData = payload.Data
		}
		_ = json.NewEncoder(w).Encode(TunnelResponse{
			Data: respData,
		})
	}))
	defer server.Close()

	dialer := NewServerlessDialer(server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := dialer.DialTarget(ctx, "example.com", 80)
	if err != nil {
		t.Fatalf("DialTarget HTTP failed: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello serverless HTTP")
	_, err = conn.Write(payload)
	if err != nil {
		t.Fatalf("failed to write payload to HTTP conn: %v", err)
	}

	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read response from HTTP conn: %v", err)
	}

	if string(buf[:n]) != "hello serverless HTTP" {
		t.Errorf("expected 'hello serverless HTTP', got '%s'", string(buf[:n]))
	}
}

func TestHTTPServerlessConnRejectsMismatchedResponseSequence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload TunnelPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		if payload.Seq == nil {
			t.Fatal("request omitted sequence")
		}
		wrong := *payload.Seq + 1
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(TunnelResponse{Seq: &wrong})
	}))
	defer server.Close()

	conn := &httpServerlessConn{
		relayURL:  server.URL,
		realDst:   "example.com:80",
		sessionID: "seq-test",
		client:    server.Client(),
		state:     newRelayConnState(),
		pollCtx:   context.Background(),
	}
	if _, err := conn.sendRequest(nil); err == nil || !strings.Contains(err.Error(), "sequence mismatch") {
		t.Fatalf("sendRequest mismatch error = %v, want sequence mismatch", err)
	}
}

func TestHTTPServerlessConnAcceptsMatchingOrLegacyResponseSequence(t *testing.T) {
	for _, omitSeq := range []bool{false, true} {
		t.Run(map[bool]string{false: "matching", true: "legacy-omitted"}[omitSeq], func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var payload TunnelPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Fatalf("decode payload: %v", err)
				}
				resp := TunnelResponse{}
				if !omitSeq {
					resp.Seq = payload.Seq
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(resp)
			}))
			defer server.Close()

			conn := &httpServerlessConn{
				relayURL:  server.URL,
				realDst:   "example.com:80",
				sessionID: "seq-test",
				client:    server.Client(),
				state:     newRelayConnState(),
				pollCtx:   context.Background(),
			}
			if _, err := conn.sendRequest(nil); err != nil {
				t.Fatalf("sendRequest = %v", err)
			}
		})
	}
}
