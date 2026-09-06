package relayclient

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestWebSocketConnNetConnContract(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		mt, msg, err := c.ReadMessage()
		if err == nil {
			_ = c.WriteMessage(mt, msg)
		}
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	raw, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c := NewWebSocketConn(raw)
	defer c.Close()

	if c.LocalAddr() == nil || c.RemoteAddr() == nil {
		t.Fatal("net.Conn addresses must be non-nil")
	}
	deadline := time.Now().Add(2 * time.Second)
	if err := c.SetDeadline(deadline); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 8)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := string(buf[:n]); got != "ping" {
		t.Fatalf("payload=%q want ping", got)
	}
}

func TestWebSocketConnEnforcesReadLimit(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.WriteMessage(websocket.BinaryMessage, make([]byte, relayWebSocketReadLimit+1))
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	raw, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c := NewWebSocketConn(raw)
	defer c.Close()

	buf := make([]byte, 32)
	if _, err := c.Read(buf); err == nil {
		t.Fatal("expected oversized websocket message to fail")
	}
}
