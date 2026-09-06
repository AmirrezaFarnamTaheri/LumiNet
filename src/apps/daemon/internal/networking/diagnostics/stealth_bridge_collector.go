package diagnostics

import (
	"errors"
	"sort"
	"strings"
	"sync"
)

// PluggableTransport defines Tor PT type
type PluggableTransport string

const (
	TransportObfs4     PluggableTransport = "obfs4"
	TransportSnowflake PluggableTransport = "snowflake"
	TransportWebTunnel PluggableTransport = "webtunnel"
	TransportMeek      PluggableTransport = "meek"
)

// StealthBridge represents a verified Tor pluggable transport bridge
type StealthBridge struct {
	Transport   PluggableTransport
	Endpoint    string
	Fingerprint string
	Params      map[string]string
	Score       float64
	LatencyMs   uint32
	Verified    bool
}

// StealthBridgeCollector collects, scores, and exports pluggable transport bridges
type StealthBridgeCollector struct {
	mu                 sync.RWMutex
	MinScoreThreshold  float64
	Bridges            map[string]*StealthBridge
}

// NewStealthBridgeCollector creates a bridge collector
func NewStealthBridgeCollector(minScore float64) *StealthBridgeCollector {
	return &StealthBridgeCollector{
		MinScoreThreshold: minScore,
		Bridges:           make(map[string]*StealthBridge),
	}
}

// ParseBridgeLine parses a raw tor bridge line
func (col *StealthBridgeCollector) ParseBridgeLine(line string) (*StealthBridge, error) {
	col.mu.Lock()
	defer col.mu.Unlock()

	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return nil, errors.New("empty or comment line")
	}

	parts := strings.Fields(trimmed)
	if len(parts) < 3 {
		return nil, errors.New("insufficient tokens in bridge line")
	}

	transport := PluggableTransport(strings.ToLower(parts[0]))
	endpoint := parts[1]
	fingerprint := strings.ToUpper(parts[2])

	params := make(map[string]string)
	for _, token := range parts[3:] {
		kv := strings.SplitN(token, "=", 2)
		if len(kv) == 2 {
			params[kv[0]] = kv[1]
		}
	}

	bridge := &StealthBridge{
		Transport:   transport,
		Endpoint:    endpoint,
		Fingerprint: fingerprint,
		Params:      params,
		Score:       1.0,
		LatencyMs:   0,
		Verified:    false,
	}

	col.Bridges[fingerprint] = bridge
	return bridge, nil
}

// RecordHealth updates probe results and latency scores
func (col *StealthBridgeCollector) RecordHealth(fingerprint string, latencyMs uint32, success bool) bool {
	col.mu.Lock()
	defer col.mu.Unlock()

	upper := strings.ToUpper(fingerprint)
	bridge, exists := col.Bridges[upper]
	if !exists {
		return false
	}

	if success {
		bridge.Verified = true
		bridge.LatencyMs = latencyMs
		latencyFactor := 1000.0 / float64(latencyMs+50)
		if latencyFactor > 2.0 {
			latencyFactor = 2.0
		}
		bridge.Score = (bridge.Score * 0.8) + (1.2 * latencyFactor)
	} else {
		bridge.Score *= 0.5
		if bridge.Score < 0.1 {
			bridge.Verified = false
		}
	}
	return true
}

// GetBestBridges returns ranked bridges exceeding the score threshold
func (col *StealthBridgeCollector) GetBestBridges(transport PluggableTransport, limit int) []*StealthBridge {
	col.mu.RLock()
	defer col.mu.RUnlock()

	var matched []*StealthBridge
	for _, b := range col.Bridges {
		if (transport == "" || b.Transport == transport) && b.Score >= col.MinScoreThreshold {
			matched = append(matched, b)
		}
	}

	sort.Slice(matched, func(i, j int) bool {
		return matched[i].Score > matched[j].Score
	})

	if len(matched) > limit {
		matched = matched[:limit]
	}
	return matched
}
