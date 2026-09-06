// Package proxy provides a WebSocket-based reverse tunneling implementation.
// This allows local clients behind NATs or firewalls to expose local HTTP
// services securely via an external public-facing LumiNet server.
//
// Ported from: gtunnel (G-Tunnel)
// LumiNet target: server/internal/proxy/ws_reverse_tunnel.go
package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// WSReverseTunnelMessageType represents the WebSocket reverse tunnel message categories.
type WSReverseTunnelMessageType int

const (
	WSReverseTunnelHTTPRequest  WSReverseTunnelMessageType = 1
	WSReverseTunnelHTTPResponse WSReverseTunnelMessageType = 2
	WSReverseTunnelAuthRequest  WSReverseTunnelMessageType = 3
	WSReverseTunnelAuthResponse WSReverseTunnelMessageType = 4
	WSReverseTunnelError        WSReverseTunnelMessageType = 7
)

// WSReverseTunnelSocketMessage is the top-level packet format exchanged over the WebSocket connection.
type WSReverseTunnelSocketMessage struct {
	Type    WSReverseTunnelMessageType `json:"type"`
	Payload json.RawMessage            `json:"payload"`
}

// WSReverseTunnelHTTPRequestMessage defines the structure of a forwarded HTTP query.
type WSReverseTunnelHTTPRequestMessage struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    []byte            `json:"body"`
}

// WSReverseTunnelHTTPResponseMessage defines the structure of the returned HTTP response.
type WSReverseTunnelHTTPResponseMessage struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       []byte            `json:"body"`
}

// WSReverseTunnelAuthRequestMessage represents the authentication payload.
type WSReverseTunnelAuthRequestMessage struct {
	AccessToken string `json:"access_token"`
	BaseURL     string `json:"base_url"`
}

// WSReverseTunnelAuthResponseMessage represents the authentication response payload.
type WSReverseTunnelAuthResponseMessage struct {
	ID      string `json:"id,omitempty"`
	Success bool   `json:"success"`
	Message string `json:"error,omitempty"`
	BaseURL string `json:"base_url"`
}

// WSReverseTunnelConn represents an active client tunnel connection.
type WSReverseTunnelConn struct {
	ID         string
	Conn       *websocket.Conn
	BaseURL    string
	ResponseCh chan []byte
	mu         sync.Mutex
}

// WSReverseTunnelManager orchestrates multiple reverse WebSocket tunnels.
type WSReverseTunnelManager struct {
	mu             sync.RWMutex
	connections    map[string]*WSReverseTunnelConn
	authenticating map[string]*WSReverseTunnelConn
	accessToken    string
	upgrader       websocket.Upgrader
}

// NewWSReverseTunnelManager instantiates a WSReverseTunnelManager.
func NewWSReverseTunnelManager(accessToken string) *WSReverseTunnelManager {
	return &WSReverseTunnelManager{
		connections:    make(map[string]*WSReverseTunnelConn),
		authenticating: make(map[string]*WSReverseTunnelConn),
		accessToken:    accessToken,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
}

// ServeHTTPWS handles the client WebSocket upgrade, authentication and message loops.
func (m *WSReverseTunnelManager) ServeHTTPWS(w http.ResponseWriter, r *http.Request) {
	conn, err := m.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	id := uuid.New().String()
	t := &WSReverseTunnelConn{
		ID:         id,
		Conn:       conn,
		ResponseCh: make(chan []byte, 10),
	}

	m.mu.Lock()
	m.authenticating[id] = t
	m.mu.Unlock()

	// Authenticate within 10 seconds
	success := m.handleAuth(t)
	if !success {
		t.Conn.Close()
		m.mu.Lock()
		delete(m.authenticating, id)
		m.mu.Unlock()
		return
	}

	m.mu.Lock()
	delete(m.authenticating, id)
	m.connections[t.BaseURL] = t
	m.mu.Unlock()

	defer func() {
		t.Conn.Close()
		m.mu.Lock()
		delete(m.connections, t.BaseURL)
		m.mu.Unlock()
	}()

	m.readLoop(t)
}

func (m *WSReverseTunnelManager) handleAuth(t *WSReverseTunnelConn) bool {
	done := make(chan struct{})
	var authMsg []byte
	var readErr error

	go func() {
		defer close(done)
		_, message, err := t.Conn.ReadMessage()
		if err != nil {
			readErr = err
			return
		}
		authMsg = message
	}()

	select {
	case <-done:
		if readErr != nil {
			return false
		}

		var socketMsg WSReverseTunnelSocketMessage
		if err := json.Unmarshal(authMsg, &socketMsg); err != nil {
			return false
		}

		if socketMsg.Type != WSReverseTunnelAuthRequest {
			return false
		}

		var authReq WSReverseTunnelAuthRequestMessage
		if err := json.Unmarshal(socketMsg.Payload, &authReq); err != nil {
			return false
		}

		if authReq.AccessToken != m.accessToken {
			m.sendAuthResponse(t, false, "Invalid access token", "")
			return false
		}

		baseURL := authReq.BaseURL
		if baseURL == "" {
			baseURL = "app-" + strings.Split(t.ID, "-")[0]
		}

		m.mu.RLock()
		_, exists := m.connections[baseURL]
		m.mu.RUnlock()

		if exists {
			m.sendAuthResponse(t, false, "Base URL already in use", "")
			return false
		}

		t.BaseURL = baseURL
		m.sendAuthResponse(t, true, "Authentication successful", baseURL)
		return true

	case <-time.After(10 * time.Second):
		return false
	}
}

func (m *WSReverseTunnelManager) sendAuthResponse(t *WSReverseTunnelConn, success bool, errMsg string, baseURL string) {
	resp := WSReverseTunnelAuthResponseMessage{
		ID:      t.ID,
		Success: success,
		Message: errMsg,
		BaseURL: baseURL,
	}
	payload, _ := json.Marshal(resp)
	msg := WSReverseTunnelSocketMessage{
		Type:    WSReverseTunnelAuthResponse,
		Payload: payload,
	}
	_ = t.Conn.WriteJSON(msg)
}

func (m *WSReverseTunnelManager) readLoop(t *WSReverseTunnelConn) {
	for {
		_, message, err := t.Conn.ReadMessage()
		if err != nil {
			break
		}

		select {
		case t.ResponseCh <- message:
		default:
			// Drain if full to prevent blocking
		}
	}
}

// ServeHTTPReverse routes incoming proxy HTTP requests to the matching active tunnel connection.
func (m *WSReverseTunnelManager) ServeHTTPReverse(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "Invalid path: missing appID", http.StatusBadRequest)
		return
	}

	appID := parts[0]
	endpoint := "/"
	if len(parts) > 1 {
		endpoint = "/" + parts[1]
	}

	m.mu.RLock()
	tunnel, ok := m.connections[appID]
	m.mu.RUnlock()

	if !ok {
		http.Error(w, "No active tunnel for: "+appID, http.StatusServiceUnavailable)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Read error", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	reqMsg := WSReverseTunnelHTTPRequestMessage{
		Method:  r.Method,
		URL:     endpoint + "?" + r.URL.RawQuery,
		Headers: make(map[string]string),
		Body:    body,
	}

	for name, values := range r.Header {
		if len(values) > 0 {
			reqMsg.Headers[name] = values[0]
		}
	}

	payload, err := json.Marshal(reqMsg)
	if err != nil {
		http.Error(w, "Serialization error", http.StatusInternalServerError)
		return
	}

	fullMsg := WSReverseTunnelSocketMessage{
		Type:    WSReverseTunnelHTTPRequest,
		Payload: payload,
	}

	encoded, err := json.Marshal(fullMsg)
	if err != nil {
		http.Error(w, "Message encoding failed", http.StatusInternalServerError)
		return
	}

	tunnel.mu.Lock()
	err = tunnel.Conn.WriteMessage(websocket.TextMessage, encoded)
	tunnel.mu.Unlock()

	if err != nil {
		http.Error(w, "Tunnel write failed", http.StatusBadGateway)
		return
	}

	select {
	case responseData := <-tunnel.ResponseCh:
		var responseMsg WSReverseTunnelSocketMessage
		if err := json.Unmarshal(responseData, &responseMsg); err != nil {
			http.Error(w, "Invalid tunnel response", http.StatusInternalServerError)
			return
		}

		if responseMsg.Type != WSReverseTunnelHTTPResponse {
			http.Error(w, "Unexpected message type", http.StatusInternalServerError)
			return
		}

		var httpResp WSReverseTunnelHTTPResponseMessage
		if err := json.Unmarshal(responseMsg.Payload, &httpResp); err != nil {
			http.Error(w, "Invalid response payload", http.StatusInternalServerError)
			return
		}

		for name, value := range httpResp.Headers {
			w.Header().Set(name, value)
		}
		w.WriteHeader(httpResp.StatusCode)
		w.Write(httpResp.Body)

	case <-time.After(10 * time.Second):
		http.Error(w, "Tunnel response timeout", http.StatusGatewayTimeout)
	}
}

// DialTunnelClient is a helper mock/client function to connect to the reverse WebSocket server.
func DialTunnelClient(serverURL string, accessToken string, baseURL string, handler func(req WSReverseTunnelHTTPRequestMessage) WSReverseTunnelHTTPResponseMessage) (*websocket.Conn, error) {
	dialer := websocket.Dialer{}
	conn, _, err := dialer.Dial(serverURL, nil)
	if err != nil {
		return nil, err
	}

	// Send auth request
	authReq := WSReverseTunnelAuthRequestMessage{
		AccessToken: accessToken,
		BaseURL:     baseURL,
	}
	payload, _ := json.Marshal(authReq)
	socketMsg := WSReverseTunnelSocketMessage{
		Type:    WSReverseTunnelAuthRequest,
		Payload: payload,
	}

	if err := conn.WriteJSON(socketMsg); err != nil {
		conn.Close()
		return nil, err
	}

	// Read auth response
	var responseMsg WSReverseTunnelSocketMessage
	if err := conn.ReadJSON(&responseMsg); err != nil {
		conn.Close()
		return nil, err
	}

	if responseMsg.Type != WSReverseTunnelAuthResponse {
		conn.Close()
		return nil, errors.New("expected auth response")
	}

	var authResp WSReverseTunnelAuthResponseMessage
	if err := json.Unmarshal(responseMsg.Payload, &authResp); err != nil {
		conn.Close()
		return nil, err
	}

	if !authResp.Success {
		conn.Close()
		return nil, fmt.Errorf("auth failed: %s", authResp.Message)
	}

	// Start message processing loop
	go func() {
		for {
			var msg WSReverseTunnelSocketMessage
			if err := conn.ReadJSON(&msg); err != nil {
				break
			}

			if msg.Type == WSReverseTunnelHTTPRequest {
				var req WSReverseTunnelHTTPRequestMessage
				_ = json.Unmarshal(msg.Payload, &req)

				resp := handler(req)
				respPayload, _ := json.Marshal(resp)
				responseSocketMsg := WSReverseTunnelSocketMessage{
					Type:    WSReverseTunnelHTTPResponse,
					Payload: respPayload,
				}

				_ = conn.WriteJSON(responseSocketMsg)
			}
		}
	}()

	return conn, nil
}
