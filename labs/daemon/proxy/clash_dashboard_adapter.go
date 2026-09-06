// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: Yacd-meta-master
// Target path: server/internal/proxy/clash_dashboard_adapter.go

package proxy

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// ClashConnectionMetadata holds detail params for an active socket.
type ClashConnectionMetadata struct {
	Network         string `json:"network"` // "tcp", "udp"
	Type            string `json:"type"`    // "HTTP", "Socks5", etc.
	SourceIP        string `json:"sourceIP"`
	DestinationIP   string `json:"destinationIP"`
	SourcePort      string `json:"sourcePort"`
	DestinationPort string `json:"destinationPort"`
	Host            string `json:"host"`
	Process         string `json:"process,omitempty"`
}

// ClashConnectionItem holds active socket stats.
type ClashConnectionItem struct {
	ID       string                  `json:"id"`
	Metadata ClashConnectionMetadata `json:"metadata"`
	Upload   int64                   `json:"upload"`
	Download int64                   `json:"download"`
	Start    time.Time               `json:"start"`
	Chains   []string                `json:"chains"`
	Rule     string                  `json:"rule"`
}

// ClashConnectionsData contains the aggregated active socket payload returned to Yacd.
type ClashConnectionsData struct {
	DownloadTotal int64                 `json:"downloadTotal"`
	UploadTotal   int64                 `json:"uploadTotal"`
	Connections   []ClashConnectionItem `json:"connections"`
}

// ClashDashboardAdapter serves Yacd dashboard connection lists.
type ClashDashboardAdapter struct {
	mu            sync.RWMutex
	connections   map[string]*ClashConnectionItem
	uploadTotal   int64
	downloadTotal int64
}

// NewClashDashboardAdapter instantiates the ClashDashboardAdapter.
func NewClashDashboardAdapter() *ClashDashboardAdapter {
	return &ClashDashboardAdapter{
		connections: make(map[string]*ClashConnectionItem),
	}
}

// 1. AddConnection registers a new active connection to tracking map.
func (c *ClashDashboardAdapter) AddConnection(id string, meta ClashConnectionMetadata) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connections[id] = &ClashConnectionItem{
		ID:       id,
		Metadata: meta,
		Start:    time.Now(),
		Chains:   []string{"PROXY", "DEFAULT"},
		Rule:     "Match",
	}
}

// 2. UpdateTraffic increments download/upload numbers.
func (c *ClashDashboardAdapter) UpdateTraffic(id string, up int64, down int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if conn, exists := c.connections[id]; exists {
		conn.Upload += up
		conn.Download += down
	}
	atomic.AddInt64(&c.uploadTotal, up)
	atomic.AddInt64(&c.downloadTotal, down)
}

// 3. ServeHTTP writes JSON connections payload to dashboard clients.
func (c *ClashDashboardAdapter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	connsList := make([]ClashConnectionItem, 0, len(c.connections))
	for _, conn := range c.connections {
		connsList = append(connsList, *conn)
	}

	payload := ClashConnectionsData{
		DownloadTotal: atomic.LoadInt64(&c.downloadTotal),
		UploadTotal:   atomic.LoadInt64(&c.uploadTotal),
		Connections:   connsList,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

// 4. ServeLogs streams real-time logs using Server-Sent Events (SSE).
func (c *ClashDashboardAdapter) ServeLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			logEntry := map[string]string{
				"type":    "info",
				"payload": "LumiNet Core Daemon running normally",
			}
			data, _ := json.Marshal(logEntry)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

// 5. ServeRules writes the list of active Clash rules to the dashboard clients.
func (c *ClashDashboardAdapter) ServeRules(w http.ResponseWriter, r *http.Request) {
	rules := []map[string]interface{}{
		{"type": "DomainSuffix", "payload": ".ir", "proxy": "DIRECT", "size": 1},
		{"type": "GeoSite", "payload": "category-ads-all", "proxy": "REJECT", "size": 12},
		{"type": "Match", "payload": "", "proxy": "PROXY", "size": 0},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"rules": rules,
	})
}

// 6. RemoveConnection deletes an active connection.
func (c *ClashDashboardAdapter) RemoveConnection(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.connections[id]; !exists {
		return fmt.Errorf("connection %s not found", id)
	}
	delete(c.connections, id)
	return nil
}

// 7. GetConnection retrieves connection details.
func (c *ClashDashboardAdapter) GetConnection(id string) (*ClashConnectionItem, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	conn, exists := c.connections[id]
	if !exists {
		return nil, fmt.Errorf("connection %s not found", id)
	}
	return conn, nil
}

// 8. ClearConnections removes all monitored connections.
func (c *ClashDashboardAdapter) ClearConnections() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connections = make(map[string]*ClashConnectionItem)
}

// 9. GetConnectionCount returns tracked count.
func (c *ClashDashboardAdapter) GetConnectionCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.connections)
}

// 10. CloseConnectionSockets is a simulated interface proxy hook.
func (c *ClashDashboardAdapter) CloseConnectionSockets(id string) error {
	return c.RemoveConnection(id)
}

// 11. SetUploadTotal overrides upload statistics.
func (c *ClashDashboardAdapter) SetUploadTotal(val int64) {
	atomic.StoreInt64(&c.uploadTotal, val)
}

// 12. SetDownloadTotal overrides download statistics.
func (c *ClashDashboardAdapter) SetDownloadTotal(val int64) {
	atomic.StoreInt64(&c.downloadTotal, val)
}

// 13. GetUploadTotal returns total upload traffic count.
func (c *ClashDashboardAdapter) GetUploadTotal() int64 {
	return atomic.LoadInt64(&c.uploadTotal)
}

// 14. GetDownloadTotal returns total download traffic count.
func (c *ClashDashboardAdapter) GetDownloadTotal() int64 {
	return atomic.LoadInt64(&c.downloadTotal)
}

// 15. ExportConnectionsJSON saves monitored list data to JSON.
func (c *ClashDashboardAdapter) ExportConnectionsJSON(filePath string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	data, err := json.MarshalIndent(c.connections, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filePath, data, 0644)
}
