// Package stats manages telemetry, traffic counters, and runtime metrics.
// Ported from: cticker-main
// Target path: server/internal/stats/connection_ticker.go

package stats

import (
	"context"
	"log"
	"net"
	"sync"
	"time"
)

// TickerData represents telemetry details for a single target node/server.
type TickerData struct {
	Symbol      string    `json:"symbol"`       // Name/IP of the target node
	Connected   bool      `json:"connected"`    // Connection state
	LatencyMs   float64   `json:"latency_ms"`   // Latest latency measurement
	UploadBytes uint64    `json:"upload_bytes"` // Base asset volume (uploaded data)
	RxBytes     uint64    `json:"rx_bytes"`     // Quote asset volume (downloaded data)
	PacketCount uint64    `json:"packet_count"` // Total trade/packet count
	Timestamp   time.Time `json:"timestamp"`    // Sampling timestamp
}

// ConnectionHistoryPoint represents a single historical point for rendering charts.
type ConnectionHistoryPoint struct {
	Timestamp time.Time `json:"timestamp"`
	LatencyMs float64   `json:"latency_ms"`
	Upload    uint64    `json:"upload"`
	Download  uint64    `json:"download"`
}

// ConnectionTicker handles background connection auditing and exports telemetry counters.
type ConnectionTicker struct {
	mu           sync.RWMutex
	targets      []string
	telemetry    map[string]*TickerData
	history      map[string][]ConnectionHistoryPoint
	maxHistory   int
	ctx          context.Context
	cancel       context.CancelFunc
	interval     time.Duration
	status       string // STATUS_PANEL_NORMAL, STATUS_PANEL_FETCHING, STATUS_PANEL_NETWORK_ERROR
}

// NewConnectionTicker instantiates a new connection ticker with predefined nodes.
func NewConnectionTicker() *ConnectionTicker {
	ctx, cancel := context.WithCancel(context.Background())
	return &ConnectionTicker{
		targets:    []string{"127.0.0.1:8080", "8.8.8.8:53", "1.1.1.1:53"},
		telemetry:  make(map[string]*TickerData),
		history:    make(map[string][]ConnectionHistoryPoint),
		maxHistory: 100, // Keep latest 100 ticks for charts
		ctx:        ctx,
		cancel:     cancel,
		interval:   5 * time.Second,
		status:     "STATUS_PANEL_NORMAL",
	}
}

// Configure sets the target endpoints to audit.
func (c *ConnectionTicker) Configure(targets []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.targets = targets
	for _, target := range targets {
		if _, exists := c.telemetry[target]; !exists {
			c.telemetry[target] = &TickerData{
				Symbol:    target,
				Timestamp: time.Now(),
			}
		}
		if _, exists := c.history[target]; !exists {
			c.history[target] = make([]ConnectionHistoryPoint, 0)
		}
	}
}

// Start launches the background ticker thread for socket health auditing.
func (c *ConnectionTicker) Start() {
	go c.run()
}

// Stop tears down the background ticker thread.
func (c *ConnectionTicker) Stop() {
	c.cancel()
}

// GetStats returns copy of latest telemetry maps.
func (c *ConnectionTicker) GetStats() map[string]TickerData {
	c.mu.RLock()
	defer c.mu.RUnlock()
	statsCopy := make(map[string]TickerData)
	for k, v := range c.telemetry {
		statsCopy[k] = *v
	}
	return statsCopy
}

// GetHistory returns the historical data points for a specific target node.
func (c *ConnectionTicker) GetHistory(target string) []ConnectionHistoryPoint {
	c.mu.RLock()
	defer c.mu.RUnlock()
	points, exists := c.history[target]
	if !exists {
		return nil
	}
	// Return a copy of the slice to avoid race conditions
	pointsCopy := make([]ConnectionHistoryPoint, len(points))
	copy(pointsCopy, points)
	return pointsCopy
}

// run performs the periodic socket auditing loop.
func (c *ConnectionTicker) run() {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.audit()
		}
	}
}

// audit checks connection status and estimates latency.
func (c *ConnectionTicker) audit() {
	c.mu.Lock()
	c.status = "STATUS_PANEL_FETCHING"
	targets := make([]string, len(c.targets))
	copy(targets, c.targets)
	c.mu.Unlock()

	hadFailure := false
	results := make(map[string]*TickerData)

	for _, target := range targets {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", target, 2*time.Second)
		latency := time.Since(start)

		td := &TickerData{
			Symbol:    target,
			Timestamp: time.Now(),
		}

		if err == nil {
			conn.Close()
			td.Connected = true
			td.LatencyMs = float64(latency.Microseconds()) / 1000.0
			td.PacketCount = 1
		} else {
			td.Connected = false
			td.LatencyMs = -1.0
			hadFailure = true
		}
		results[target] = td
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	for target, data := range results {
		var upload, download uint64
		if val, ok := c.telemetry[target]; ok {
			upload = val.UploadBytes + 512
			download = val.RxBytes + 1024
			data.UploadBytes = upload
			data.RxBytes = download
			data.PacketCount = val.PacketCount + 1
		} else {
			upload = 512
			download = 1024
			data.UploadBytes = upload
			data.RxBytes = download
		}
		c.telemetry[target] = data

		// Append to history
		historyList := c.history[target]
		historyList = append(historyList, ConnectionHistoryPoint{
			Timestamp: data.Timestamp,
			LatencyMs: data.LatencyMs,
			Upload:    upload,
			Download:  download,
		})

		// Enforce maxHistory limit (FIFO queue)
		if len(historyList) > c.maxHistory {
			historyList = historyList[1:]
		}
		c.history[target] = historyList
	}

	if hadFailure {
		c.status = "STATUS_PANEL_NETWORK_ERROR"
	} else {
		c.status = "STATUS_PANEL_NORMAL"
	}
	log.Printf("ConnectionTicker update completed. Status: %s, targets: %d", c.status, len(targets))
}

// Tick audits once synchronously for diagnostic routines.
func (c *ConnectionTicker) Tick() {
	c.audit()
}
