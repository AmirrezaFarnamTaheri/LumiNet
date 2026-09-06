// Package qos manages packet classification and traffic shaping.
// Ported from: l7-snake-main (pt3status/status.pb.go)
// Target path: server/internal/qos/l7_snake_client.go

package qos

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// L7SnakeStatus represents pt3status status message.
type L7SnakeStatus struct {
	DeviceID      string    `json:"device_id"`
	UptimeSecs    int64     `json:"uptime_secs"`
	RxBytes       int64     `json:"rx_bytes"`
	TxBytes       int64     `json:"tx_bytes"`
	ActiveStreams int32     `json:"active_streams"`
	Timestamp     time.Time `json:"timestamp"`
}

// Getters & Setters for L7SnakeStatus
func (s *L7SnakeStatus) GetDeviceID() string { return s.DeviceID }
func (s *L7SnakeStatus) SetDeviceID(v string) { s.DeviceID = v }
func (s *L7SnakeStatus) GetRxBytes() int64 { return s.RxBytes }
func (s *L7SnakeStatus) SetRxBytes(v int64) { s.RxBytes = v }

// L7SnakeClient tracks traffic statistics and streams dynamically.
type L7SnakeClient struct {
	mu           sync.RWMutex
	deviceID     string
	uptimeStart  time.Time
	rxBytes      int64
	txBytes      int64
	activeStream int32
}

// NewL7SnakeClient creates a client.
func NewL7SnakeClient(deviceID string) *L7SnakeClient {
	return &L7SnakeClient{
		deviceID:    deviceID,
		uptimeStart: time.Now(),
	}
}

// RecordTraffic increments byte counters.
func (c *L7SnakeClient) RecordTraffic(rx, tx int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rxBytes += rx
	c.txBytes += tx
}

// SetStreams updates concurrent streams.
func (c *L7SnakeClient) SetStreams(count int32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.activeStream = count
}

// GetStatus returns the current status envelope snapshot.
func (c *L7SnakeClient) GetStatus(ctx context.Context) L7SnakeStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return L7SnakeStatus{
		DeviceID:      c.deviceID,
		UptimeSecs:    int64(time.Since(c.uptimeStart).Seconds()),
		RxBytes:       c.rxBytes,
		TxBytes:       c.txBytes,
		ActiveStreams: c.activeStream,
		Timestamp:     time.Now(),
	}
}

// L7SnakeConfig represents the configuration structures for l7-snake.
type L7SnakeConfig struct {
	Data struct {
		Communication struct {
			ID         string   `yaml:"id" json:"id"`
			ListenPort string   `yaml:"listenport" json:"listenport"`
			Targets    []string `yaml:"targets" json:"targets"`
		} `yaml:"communication" json:"communication"`
		Routing struct {
			Routes     []string `yaml:"routes" json:"routes"`
			Terminator bool     `yaml:"terminator" json:"terminator"`
		} `yaml:"routing" json:"routing"`
		Settings struct {
			Interval string `yaml:"interval" json:"interval"`
		} `yaml:"settings" json:"settings"`
	} `yaml:"data" json:"data"`
}

// WriteDefaultSnakeConfig generates a template configuration file if not exists.
// Maps to upstream ConfigWriter() in configstruct.go.
func WriteDefaultSnakeConfig(path string) error {
	cfg := L7SnakeConfig{}
	cfg.Data.Communication.ID = "none"
	cfg.Data.Communication.ListenPort = "9001"
	cfg.Data.Communication.Targets = []string{"localhost:80", "0.0.0.0:9000"}
	cfg.Data.Routing.Routes = []string{"route-a", "route-b"}
	cfg.Data.Routing.Terminator = true
	cfg.Data.Settings.Interval = "3s"

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	// Output simulated template content since we don't strictly require yaml import overhead here
	content := fmt.Sprintf("data:\n  communication:\n    id: %s\n    listenport: %s\n    targets:\n      - localhost:80\n      - 0.0.0.0:9000\n  routing:\n    routes:\n      - route-a\n      - route-b\n    terminator: %t\n  settings:\n    interval: %s\n",
		cfg.Data.Communication.ID,
		cfg.Data.Communication.ListenPort,
		cfg.Data.Routing.Terminator,
		cfg.Data.Settings.Interval,
	)

	return os.WriteFile(path, []byte(content), 0o644)
}

// StatusChain represents the status chain node from status.proto.
type StatusChain struct {
	ID          string   `json:"id"`
	Terminator  bool     `json:"terminator"`
	LastUpdated string   `json:"last_updated"`
	Health      int32    `json:"health"`
	Targets     int32    `json:"targets"`
	Routes      []string `json:"routes"`
}

// L7SnakeStatusMessage aggregates multiple status chains.
type L7SnakeStatusMessage struct {
	Lst []*StatusChain `json:"lst"`
}

// L7SnakeEcho represents Echo protobuf message.
type L7SnakeEcho struct {
	Echo string `json:"echo"`
}
