package system

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	smoothPrevWeight   = 0.4
	smoothSampleWeight = 0.6
)

// TrafficSample captures traffic volume and current transfer speed.
type TrafficSample struct {
	ReceivedBytes       uint64 `json:"received_bytes"`
	SentBytes           uint64 `json:"sent_bytes"`
	DownloadBytesPerSec uint64 `json:"download_bytes_per_sec"`
	UploadBytesPerSec   uint64 `json:"upload_bytes_per_sec"`
	Supported           bool   `json:"supported"`
}

// TrafficMeterSmoother calculates exponential moving average of network rates.
type TrafficMeterSmoother struct {
	mu           sync.Mutex
	baseRx       uint64
	baseTx       uint64
	lastRx       uint64
	lastTx       uint64
	smoothedDown float64
	smoothedUp   float64
	initialized  bool
}

func NewTrafficMeterSmoother() *TrafficMeterSmoother {
	return &TrafficMeterSmoother{}
}

func (m *TrafficMeterSmoother) Start(currentRx, currentTx uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.baseRx = currentRx
	m.baseTx = currentTx
	m.lastRx = currentRx
	m.lastTx = currentTx
	m.smoothedDown = 0.0
	m.smoothedUp = 0.0
	m.initialized = true
}

func (m *TrafficMeterSmoother) SampleNow(currentRx, currentTx uint64, elapsed time.Duration) TrafficSample {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.initialized {
		m.baseRx = currentRx
		m.baseTx = currentTx
		m.lastRx = currentRx
		m.lastTx = currentTx
		m.initialized = true
		return TrafficSample{Supported: true}
	}

	deltaRx := uint64(0)
	if currentRx >= m.lastRx {
		deltaRx = currentRx - m.lastRx
	}

	deltaTx := uint64(0)
	if currentTx >= m.lastTx {
		deltaTx = currentTx - m.lastTx
	}

	elapsedNanos := elapsed.Nanoseconds()
	rawDown := 0.0
	rawUp := 0.0
	if elapsedNanos > 0 {
		rawDown = float64(deltaRx*1_000_000_000) / float64(elapsedNanos)
		rawUp = float64(deltaTx*1_000_000_000) / float64(elapsedNanos)
	}

	if m.smoothedDown <= 0.0 {
		m.smoothedDown = rawDown
	} else {
		m.smoothedDown = m.smoothedDown*smoothPrevWeight + rawDown*smoothSampleWeight
	}

	if m.smoothedUp <= 0.0 {
		m.smoothedUp = rawUp
	} else {
		m.smoothedUp = m.smoothedUp*smoothPrevWeight + rawUp*smoothSampleWeight
	}

	m.lastRx = currentRx
	m.lastTx = currentTx

	rxTotal := uint64(0)
	if currentRx >= m.baseRx {
		rxTotal = currentRx - m.baseRx
	}
	txTotal := uint64(0)
	if currentTx >= m.baseTx {
		txTotal = currentTx - m.baseTx
	}

	return TrafficSample{
		ReceivedBytes:       rxTotal,
		SentBytes:           txTotal,
		DownloadBytesPerSec: uint64(m.smoothedDown),
		UploadBytesPerSec:   uint64(m.smoothedUp),
		Supported:           true,
	}
}

func (m *TrafficMeterSmoother) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.smoothedDown = 0.0
	m.smoothedUp = 0.0
}

// FormatBytes formats byte counts into human-friendly strings.
func FormatBytes(bytes uint64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	}
	units := []string{"KB", "MB", "GB", "TB"}
	val := float64(bytes) / 1024.0
	idx := 0
	for val >= 1024.0 && idx < len(units)-1 {
		val /= 1024.0
		idx++
	}
	if val < 10.0 {
		return fmt.Sprintf("%.1f %s", val, units[idx])
	}
	return fmt.Sprintf("%.0f %s", val, units[idx])
}

// FormatRate formats byte throughput rate.
func FormatRate(bytesPerSec uint64) string {
	return fmt.Sprintf("%s/s", FormatBytes(bytesPerSec))
}

// SplitTunnelMode defines application split tunneling routing modes.
type SplitTunnelMode string

const (
	SplitModeAll    SplitTunnelMode = "ALL"
	SplitModeOnly   SplitTunnelMode = "ONLY"
	SplitModeExcept SplitTunnelMode = "EXCEPT"
)

// SplitTunnelPolicy defines application-level routing exclusions.
type SplitTunnelPolicy struct {
	Mode     SplitTunnelMode `json:"mode"`
	Packages []string        `json:"packages"`
}

func (p SplitTunnelPolicy) EffectivePackages(selfID string) []string {
	var out []string
	for _, pkg := range p.Packages {
		if strings.TrimSpace(pkg) != "" && pkg != selfID {
			out = append(out, pkg)
		}
	}
	return out
}

func (p SplitTunnelPolicy) IsEffectivelyAll(selfID string) bool {
	switch p.Mode {
	case SplitModeAll:
		return true
	case SplitModeOnly:
		return false
	case SplitModeExcept:
		return len(p.EffectivePackages(selfID)) == 0
	default:
		return true
	}
}

func (p SplitTunnelPolicy) ValidationError(selfID string) string {
	if p.Mode == SplitModeOnly && len(p.EffectivePackages(selfID)) == 0 {
		return "Choose at least one app, or switch back to All apps"
	}
	return ""
}
