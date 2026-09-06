package scanner

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// ProbeState represents the status of an uptime probe check
type ProbeState string

const (
	ProbeStateUp   ProbeState = "up"
	ProbeStateDown ProbeState = "down"
)

// UptimeResult represents the result of a single check probe
type UptimeResult struct {
	Timestamp time.Time     `json:"timestamp"`
	Latency   time.Duration `json:"latency"`
	State     ProbeState    `json:"state"`
	Error     string        `json:"error,omitempty"`
}

// UptimeTarget defines a target connection address or HTTP endpoint to scan
type UptimeTarget struct {
	ID       string        `json:"id"`
	Type     string        `json:"type"`   // "http" or "tcp"
	Target   string        `json:"target"` // URL (http) or host:port (tcp)
	Interval time.Duration `json:"interval"`
	Timeout  time.Duration `json:"timeout"`
}

// UptimeMonitor runs periodic checks on a list of targets and caches results in-memory
type UptimeMonitor struct {
	targets    map[string]UptimeTarget
	history    map[string][]UptimeResult
	cancels    map[string]context.CancelFunc
	maxHistory int
	mu         sync.RWMutex
	runCtx     context.Context
	cancel     context.CancelFunc
	running    bool
	client     *http.Client
}

var (
	globalUptimeMonitor *UptimeMonitor
	globalUptimeOnce    sync.Once
)

// GetUptimeMonitor returns the singleton instance of UptimeMonitor
func GetUptimeMonitor() *UptimeMonitor {
	globalUptimeOnce.Do(func() {
		globalUptimeMonitor = &UptimeMonitor{
			targets:    make(map[string]UptimeTarget),
			history:    make(map[string][]UptimeResult),
			cancels:    make(map[string]context.CancelFunc),
			maxHistory: 100,
			client: &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse // don't follow redirects, consider 3xx as up
				},
			},
		}
	})
	return globalUptimeMonitor
}

// Start launches background checking goroutines for all configured targets
func (m *UptimeMonitor) Start(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return
	}

	m.running = true
	runCtx, cancel := context.WithCancel(ctx)
	m.runCtx = runCtx
	m.cancel = cancel

	for _, target := range m.targets {
		targetCtx, targetCancel := context.WithCancel(runCtx)
		m.cancels[target.ID] = targetCancel
		go m.workerLoop(targetCtx, target)
	}
}

// Stop terminates all checking worker routines
func (m *UptimeMonitor) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return
	}

	// Cancel all individual target contexts first
	for id, cancel := range m.cancels {
		cancel()
		delete(m.cancels, id)
	}

	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
	m.runCtx = nil
	m.running = false
}

// AddTarget adds a new check target and launches its checker if running
func (m *UptimeMonitor) AddTarget(target UptimeTarget) {
	m.mu.Lock()
	// Cancel existing worker loop for target with the same ID if it exists
	if oldCancel, exists := m.cancels[target.ID]; exists {
		oldCancel()
		delete(m.cancels, target.ID)
	}
	m.targets[target.ID] = target
	m.history[target.ID] = make([]UptimeResult, 0)
	running := m.running
	m.mu.Unlock()

	if running {
		m.mu.Lock()
		runCtx := m.runCtx
		if runCtx != nil {
			targetCtx, targetCancel := context.WithCancel(runCtx)
			m.cancels[target.ID] = targetCancel
			go m.workerLoop(targetCtx, target)
		}
		m.mu.Unlock()
	}
}

// RemoveTarget deletes a check target and its trace history
func (m *UptimeMonitor) RemoveTarget(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cancel, exists := m.cancels[id]; exists {
		cancel()
		delete(m.cancels, id)
	}
	delete(m.targets, id)
	delete(m.history, id)
}

// GetUptimeStats returns the check results history for all targets
func (m *UptimeMonitor) GetUptimeStats() map[string][]UptimeResult {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make(map[string][]UptimeResult)
	for id, res := range m.history {
		copied := make([]UptimeResult, len(res))
		copy(copied, res)
		stats[id] = copied
	}
	return stats
}

func (m *UptimeMonitor) workerLoop(ctx context.Context, target UptimeTarget) {
	ticker := time.NewTicker(target.Interval)
	defer ticker.Stop()

	// Initial probe on start
	m.probe(target)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.probe(target)
		}
	}
}

func (m *UptimeMonitor) probe(target UptimeTarget) {
	var res UptimeResult
	res.Timestamp = time.Now()

	start := time.Now()
	var err error

	if target.Type == "http" {
		err = m.probeHTTP(target.Target, target.Timeout)
	} else {
		err = m.probeTCP(target.Target, target.Timeout)
	}

	res.Latency = time.Since(start)
	if err != nil {
		res.State = ProbeStateDown
		res.Error = err.Error()
	} else {
		res.State = ProbeStateUp
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Append to history and enforce max capacity ring buffer limit
	hist := m.history[target.ID]
	hist = append(hist, res)
	if len(hist) > m.maxHistory {
		hist = hist[1:]
	}
	m.history[target.ID] = hist
}

func (m *UptimeMonitor) probeHTTP(url string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Consider any 2xx or 3xx HTTP response code as successful
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP error: status code %d", resp.StatusCode)
	}

	return nil
}

func (m *UptimeMonitor) probeTCP(address string, timeout time.Duration) error {
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}
