// Package stats provides telemetry, traffic statistics, and L7 metric analysis for LumiNet.
// Ported from: apermon (sFlow v5 parser & Volumetric Attack Mitigation)
// Target path: server/internal/stats/apermon.go
package stats

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// ApermonMonitor parses sFlow v5 packets and flags volumetric traffic threshold violations.
type ApermonMonitor struct {
	mu           sync.Mutex
	socksAddress string
	byteLimit    int64
	packetLimit  int64
	byteCount    int64
	packetCount  int64
	lastReset    time.Time
	isMitigating bool
}

// NewApermonMonitor creates a new monitor instance.
func NewApermonMonitor(byteLimit, packetLimit int64) *ApermonMonitor {
	return &ApermonMonitor{
		byteLimit:   byteLimit,
		packetLimit: packetLimit,
		lastReset:   time.Now(),
	}
}

// ParseSFlowHeader minimal parser checking version (must be 5)
func (m *ApermonMonitor) ParseSFlowHeader(payload []byte) (uint32, error) {
	if len(payload) < 24 {
		return 0, fmt.Errorf("sFlow payload too short")
	}

	version := binary.BigEndian.Uint32(payload[0:4])
	if version != 5 {
		return version, fmt.Errorf("unsupported sFlow version: %d", version)
	}

	return version, nil
}

// StartTelemetryCollector starts a local sFlow collector on UDP port 6343.
func (m *ApermonMonitor) StartTelemetryCollector(ctx context.Context, listenAddr string) error {
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	buf := make([]byte, 1500)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				continue
			}

			// Aggregate packet stats
			m.mu.Lock()
			m.packetCount++
			m.byteCount += int64(n)

			// Simple slide verification window
			now := time.Now()
			if now.Sub(m.lastReset) >= 1*time.Second {
				if m.byteCount > m.byteLimit || m.packetCount > m.packetLimit {
					m.triggerMitigation()
				} else {
					m.isMitigating = false
				}
				m.byteCount = 0
				m.packetCount = 0
				m.lastReset = now
			}
			m.mu.Unlock()
		}
	}
}

func (m *ApermonMonitor) triggerMitigation() {
	if m.isMitigating {
		return
	}
	m.isMitigating = true
	// Mock executing local mitigation script, e.g. iptables drop triggers
	fmt.Printf("[Apermon Alert] Volumetric anomaly detected! ByteCount exceeded limits. Initiating mitigation.\n")
}
