package proxy

// Ported from: billing-monitor-main
// Target: server/internal/proxy/billing_monitor.go

import (
	"fmt"
	"log/slog"
	"sync"
)

// BillingMonitor tracks bandwidth consumption and billing events.
type BillingMonitor struct {
	mu        sync.RWMutex
	bytesUp   int64
	bytesDown int64
	alerts    []string
}

// NewBillingMonitor creates a billing monitor.
func NewBillingMonitor() *BillingMonitor {
	return &BillingMonitor{}
}

// AddUpstream records uploaded bytes.
func (b *BillingMonitor) AddUpstream(n int64) {
	b.mu.Lock()
	b.bytesUp += n
	b.mu.Unlock()
}

// AddDownstream records downloaded bytes.
func (b *BillingMonitor) AddDownstream(n int64) {
	b.mu.Lock()
	b.bytesDown += n
	b.mu.Unlock()
}

// Snapshot returns current usage totals.
func (b *BillingMonitor) Snapshot() (int64, int64) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.bytesUp, b.bytesDown
}

// Alert records a billing threshold alert.
func (b *BillingMonitor) Alert(msg string) {
	b.mu.Lock()
	b.alerts = append(b.alerts, msg)
	b.mu.Unlock()
	slog.Info("BillingMonitor alert", "msg", msg)
}

// Reset clears counters.
func (b *BillingMonitor) Reset() {
	b.mu.Lock()
	b.bytesUp = 0
	b.bytesDown = 0
	b.alerts = nil
	b.mu.Unlock()
}

// Check evaluates bandwidth thresholds and fires alerts if exceeded.
func (b *BillingMonitor) Check(upLimit, downLimit int64) {
	b.mu.RLock()
	up := b.bytesUp
	down := b.bytesDown
	b.mu.RUnlock()

	if upLimit > 0 && up >= upLimit {
		b.Alert(fmt.Sprintf("upstream limit reached: %d/%d", up, upLimit))
	}
	if downLimit > 0 && down >= downLimit {
		b.Alert(fmt.Sprintf("downstream limit reached: %d/%d", down, downLimit))
	}
}
