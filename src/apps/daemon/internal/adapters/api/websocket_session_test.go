package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestWebsocketSessionIssuerIssuesSingleUseExpiringTokens(t *testing.T) {
	issuer := newWebsocketSessionIssuer()
	now := time.Now()
	token, expiresAt, err := issuer.issue(now)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if token == "" || !expiresAt.After(now) {
		t.Fatalf("issue = token %q expires %s", token, expiresAt)
	}
	if !issuer.consume(token, now) {
		t.Fatal("first token consume failed")
	}
	if issuer.consume(token, now) {
		t.Fatal("token was accepted twice")
	}

	expired, _, err := issuer.issue(now.Add(-2 * websocketSessionTTL))
	if err != nil {
		t.Fatalf("issue expired: %v", err)
	}
	if issuer.consume(expired, now) {
		t.Fatal("expired token was accepted")
	}
}

func TestHubRegistersOnlyAuthenticatedWebSocketClients(t *testing.T) {
	issuer := newWebsocketSessionIssuer()
	hub := NewHub(nil)
	go hub.Run(context.Background())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hub.ServeWs(w, r, nil, func(token string) bool { return issuer.consume(token, time.Now()) })
	}))
	defer server.Close()
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	invalid, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial invalid session: %v", err)
	}
	if err := invalid.WriteJSON(WSCommand{Action: "authenticate", Token: "invalid"}); err != nil {
		t.Fatalf("write invalid handshake: %v", err)
	}
	_ = invalid.Close()
	assertHubClientCount(t, hub, 0)

	token, _, err := issuer.issue(time.Now())
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	valid, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial valid session: %v", err)
	}
	defer valid.Close()
	if err := valid.WriteJSON(WSCommand{Action: "authenticate", Token: token}); err != nil {
		t.Fatalf("write valid handshake: %v", err)
	}
	assertHubClientCount(t, hub, 1)

}

func assertHubClientCount(t *testing.T, hub *Hub, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		hub.mu.RLock()
		count := len(hub.clients)
		hub.mu.RUnlock()
		if count == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	hub.mu.RLock()
	count := len(hub.clients)
	hub.mu.RUnlock()
	t.Fatalf("hub client count = %d, want %d", count, want)
}
