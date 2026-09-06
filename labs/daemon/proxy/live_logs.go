package proxy

// Ported from: sidecar_metrics_output.go streaming logs
// Target: server/internal/proxy/live_logs.go

import (
	"io"
	"log/slog"
	"net/http"
	"sync"
)

// LiveLogs streams relay event logs to connected clients.
type LiveLogs struct {
	clients map[chan string]struct{}
	mu      sync.RWMutex
}

// NewLiveLogs creates a live log broadcaster.
func NewLiveLogs() *LiveLogs {
	return &LiveLogs{clients: make(map[chan string]struct{})}
}

// Broadcast sends a log line to all connected clients.
func (l *LiveLogs) Broadcast(line string) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	for ch := range l.clients {
		select {
		case ch <- line:
		default:
		}
	}
}

// Stream returns an SSE stream of relay logs.
func (l *LiveLogs) Stream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")

	ch := make(chan string, 64)
	l.mu.Lock()
	l.clients[ch] = struct{}{}
	l.mu.Unlock()

	defer func() {
		l.mu.Lock()
		delete(l.clients, ch)
		close(ch)
		l.mu.Unlock()
	}()

	for {
		select {
		case <-r.Context().Done():
			return
		case line := <-ch:
			_, _ = io.WriteString(w, "data: "+line+"\n\n")
			flusher.Flush()
		}
	}
}

// Log logs a relay event internally.
func (l *LiveLogs) Log(msg string) {
	slog.Info("live log", "msg", msg)
	l.Broadcast(msg)
}
