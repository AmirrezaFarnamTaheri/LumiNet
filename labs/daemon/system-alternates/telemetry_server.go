package system

import (
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// TelemetryServer manages websocket logs/metrics streaming with rate limits.
type TelemetryServer struct {
	upgrader   websocket.Upgrader
	clients    map[*websocket.Conn]string
	clientIPs  map[string]int
	maxClients int
	maxPerIP   int
	mu         sync.Mutex
	writeMu    sync.Mutex
}

// NewTelemetryServer returns a new TelemetryServer instance.
func NewTelemetryServer(maxClients, maxPerIP int) *TelemetryServer {
	if maxClients <= 0 {
		maxClients = 100
	}
	if maxPerIP <= 0 {
		maxPerIP = 5
	}
	return &TelemetryServer{
		upgrader:   websocket.Upgrader{ReadBufferSize: 1024, WriteBufferSize: 1024},
		clients:    make(map[*websocket.Conn]string),
		clientIPs:  make(map[string]int),
		maxClients: maxClients,
		maxPerIP:   maxPerIP,
	}
}

func (s *TelemetryServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}

	s.mu.Lock()
	if len(s.clients) >= s.maxClients || s.clientIPs[ip] >= s.maxPerIP {
		s.mu.Unlock()
		http.Error(w, "Connection limit exceeded", http.StatusTooManyRequests)
		return
	}
	s.clientIPs[ip]++
	s.mu.Unlock()

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.mu.Lock()
		s.clientIPs[ip]--
		s.mu.Unlock()
		return
	}

	s.mu.Lock()
	s.clients[conn] = ip
	s.mu.Unlock()

	defer func() {
		s.removeClient(conn)
		conn.Close()
	}()

	// Loop to read and keep connection alive
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}
}

// BroadcastMetric streams a metric JSON byte payload to all active websocket clients.
func (s *TelemetryServer) BroadcastMetric(metricJson []byte) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	s.mu.Lock()
	clients := make([]*websocket.Conn, 0, len(s.clients))
	for conn := range s.clients {
		clients = append(clients, conn)
	}
	s.mu.Unlock()

	for _, conn := range clients {
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := conn.WriteMessage(websocket.TextMessage, metricJson); err != nil {
			s.removeClient(conn)
			_ = conn.Close()
		}
	}
}

func (s *TelemetryServer) removeClient(conn *websocket.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ip, ok := s.clients[conn]
	if !ok {
		return
	}
	delete(s.clients, conn)
	s.clientIPs[ip]--
	if s.clientIPs[ip] <= 0 {
		delete(s.clientIPs, ip)
	}
}
