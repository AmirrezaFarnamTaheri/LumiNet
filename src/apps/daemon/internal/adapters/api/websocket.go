package api

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/maybeknott/luminet/internal/foundation/trafficstats"
	"github.com/maybeknott/luminet/internal/workflows/jobs"
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer.
	maxMessageSize = 512
)

type wsBroadcast struct {
	jobID     string
	eventType string
	data      interface{}
}

type wsMetrics struct {
	RX      float64  `json:"rx"`
	TX      float64  `json:"tx"`
	Latency *float64 `json:"latency"`
}

// WebSocketStats exposes monotonic counters for transient fan-out pressure.
// Authoritative job state remains persisted by JobManager; these counters only
// describe messages that could not be delivered through bounded live channels.
type WebSocketStats struct {
	BroadcastDrops        uint64 `json:"broadcast_drops"`
	SlowClientDisconnects uint64 `json:"slow_client_disconnects"`
}

// Client represents a single WebSocket client connection.
type Client struct {
	hub           *Hub
	conn          *websocket.Conn
	send          chan []byte
	subscriptions map[string]bool
	mu            sync.RWMutex
}

// Hub manages all active WebSocket clients and message broadcasting.
type Hub struct {
	clients               map[*Client]bool
	broadcast             chan *wsBroadcast
	register              chan *Client
	unregister            chan *Client
	mu                    sync.RWMutex
	broadcaster           *jobs.Broadcaster
	jobEvents             <-chan jobs.JobEvent
	metricsSampler        *trafficstats.RateSampler
	done                  chan struct{}
	broadcastDrops        atomic.Uint64
	slowClientDisconnects atomic.Uint64
}

// NewHub creates a WebSocket hub. When a job manager is supplied, the hub
// owns the broadcaster subscription for the exact lifetime of Run.
func NewHub(jobMgr *jobs.JobManager) *Hub {
	h := &Hub{
		clients:        make(map[*Client]bool),
		broadcast:      make(chan *wsBroadcast, 256),
		register:       make(chan *Client),
		unregister:     make(chan *Client),
		metricsSampler: trafficstats.NewRateSampler(),
		done:           make(chan struct{}),
	}
	if jobMgr != nil {
		h.broadcaster = jobMgr.GetBroadcaster()
		if h.broadcaster != nil {
			h.jobEvents = h.broadcaster.SubscribeAll()
		}
	}
	return h
}

// Done closes after Run has released its job subscription and clients.
func (h *Hub) Done() <-chan struct{} { return h.done }

// Stats returns a concurrency-safe snapshot of transient WebSocket fan-out loss.
func (h *Hub) Stats() WebSocketStats {
	if h == nil {
		return WebSocketStats{}
	}
	return WebSocketStats{
		BroadcastDrops:        h.broadcastDrops.Load(),
		SlowClientDisconnects: h.slowClientDisconnects.Load(),
	}
}

// Run owns all hub work under ctx, including forwarding job events.
func (h *Hub) Run(ctx context.Context) {
	defer close(h.done)
	if h.broadcaster != nil && h.jobEvents != nil {
		defer h.broadcaster.UnsubscribeAll(h.jobEvents)
	}
	defer func() {
		h.mu.Lock()
		for client := range h.clients {
			delete(h.clients, client)
			close(client.send)
			_ = client.conn.Close()
		}
		h.mu.Unlock()
	}()

	metricsTicker := time.NewTicker(time.Second)
	defer metricsTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-metricsTicker.C:
			h.publishMetrics(now)
		case event, ok := <-h.jobEvents:
			if !ok {
				h.jobEvents = nil
				continue
			}
			h.enqueueBroadcast(&wsBroadcast{jobID: event.JobID, eventType: event.Type, data: event.Data})
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()
		case client := <-h.unregister:
			h.removeClient(client)
		case broadcast := <-h.broadcast:
			h.deliverBroadcast(broadcast)
		}
	}
}

func (h *Hub) publishMetrics(now time.Time) {
	uploadBytes, downloadBytes := trafficstats.GetEvasionTrafficStats()
	rates, ok := h.metricsSampler.Sample(now, uploadBytes, downloadBytes)
	if !ok {
		return
	}
	h.enqueueBroadcast(&wsBroadcast{
		eventType: "METRICS_UPDATE",
		data: wsMetrics{
			RX: rates.RXBytesPerSecond,
			TX: rates.TXBytesPerSecond,
			// No authoritative tunnel latency source exists yet. Null is
			// intentionally distinct from a measured zero-millisecond latency.
			Latency: nil,
		},
	})
}

func (h *Hub) enqueueBroadcast(b *wsBroadcast) {
	select {
	case h.broadcast <- b:
	default:
		h.broadcastDrops.Add(1)
	}
}

func (h *Hub) removeClient(client *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.clients[client]; ok {
		delete(h.clients, client)
		close(client.send)
	}
}

func (h *Hub) deliverBroadcast(broadcast *wsBroadcast) {
	msg := WSMessage{Type: broadcast.eventType, JobID: broadcast.jobID, Data: broadcast.data, Timestamp: time.Now()}
	payload, err := json.Marshal(msg)
	if err != nil {
		return
	}

	h.mu.RLock()
	var stalled []*Client
	for client := range h.clients {
		client.mu.RLock()
		isSubscribed := broadcast.jobID == "" || client.subscriptions[broadcast.jobID] || client.subscriptions["*"]
		client.mu.RUnlock()
		if !isSubscribed {
			continue
		}
		select {
		case client.send <- payload:
		default:
			stalled = append(stalled, client)
		}
	}
	h.mu.RUnlock()
	for _, client := range stalled {
		h.slowClientDisconnects.Add(1)
		h.removeClient(client)
	}
}

// ServeWs upgrades an HTTP request to a WebSocket connection and registers the client.
func (h *Hub) ServeWs(w http.ResponseWriter, r *http.Request, allowedOrigins []string, authenticate func(string) bool) {
	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			if origin == "" {
				return true
			}
			u, err := url.Parse(origin)
			if err != nil {
				return false
			}
			host := u.Hostname()
			if host == "localhost" || host == "127.0.0.1" || host == "::1" {
				return true
			}
			for _, allowed := range allowedOrigins {
				if allowed == "*" || allowed == origin {
					return true
				}
				if au, err := url.Parse(allowed); err == nil && au.Hostname() == host {
					return true
				}
			}
			return false
		},
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade websocket: %v", err)
		return
	}
	if authenticate == nil {
		_ = conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var handshake WSCommand
	if err := conn.ReadJSON(&handshake); err != nil || handshake.Action != "authenticate" || !authenticate(handshake.Token) {
		_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "authentication required"), time.Now().Add(writeWait))
		_ = conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	client := &Client{
		hub:           h,
		conn:          conn,
		send:          make(chan []byte, 256),
		subscriptions: make(map[string]bool),
	}

	select {
	case h.register <- client:
	case <-h.done:
		_ = conn.Close()
		return
	}

	// Start reader and writer pumps
	go client.writePump()
	go client.readPump()
}

// BroadcastJobEvent sends a job-related event to all connected clients
// that are subscribed to the given job ID, or to all clients if jobID is empty.
func (h *Hub) BroadcastJobEvent(jobID string, eventType string, data interface{}) {
	h.enqueueBroadcast(&wsBroadcast{jobID: jobID, eventType: eventType, data: data})
}

// BroadcastSystemEvent sends a system-level event to all connected clients.
func (h *Hub) BroadcastSystemEvent(eventType string, data interface{}) {
	h.enqueueBroadcast(&wsBroadcast{jobID: "", eventType: eventType, data: data})
}

// readPump pumps messages from the WebSocket connection to the hub.
// It handles client commands like subscribe/unsubscribe.
func (c *Client) readPump() {
	defer func() {
		select {
		case c.hub.unregister <- c:
		case <-c.hub.done:
		}
		c.conn.Close()
	}()

	c.conn.SetReadLimit(maxMessageSize)
	_ = c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		_ = c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			break
		}

		var cmd WSCommand
		if err := json.Unmarshal(message, &cmd); err != nil {
			continue
		}

		c.mu.Lock()
		switch cmd.Action {
		case "subscribe":
			c.subscriptions[cmd.JobID] = true
		case "unsubscribe":
			delete(c.subscriptions, cmd.JobID)
		}
		c.mu.Unlock()
	}
}

// writePump pumps messages from the hub to the WebSocket connection.
func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				_ = c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			_, _ = w.Write(message)

			if err := w.Close(); err != nil {
				return
			}

		case <-ticker.C:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
