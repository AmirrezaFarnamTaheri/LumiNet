package diagnostics

import (
	"sync"
)

type ProviderStatus string

const (
	ProviderStatusOperational ProviderStatus = "Operational"
	ProviderStatusUnstable    ProviderStatus = "Unstable"
	ProviderStatusFailed      ProviderStatus = "Failed"
)

type ProviderHealth struct {
	ProviderName         string
	ConsecutiveFailures  uint32
	SuccessfulHeartbeats uint64
	LastLatencyMs        uint32
	Status               ProviderStatus
}

type ProviderFailoverWatcher struct {
	mu                sync.RWMutex
	providers         map[string]*ProviderHealth
	failoverThreshold uint32
	activeProvider    string
}

func NewProviderFailoverWatcher(failoverThreshold uint32) *ProviderFailoverWatcher {
	if failoverThreshold < 1 {
		failoverThreshold = 1
	}
	return &ProviderFailoverWatcher{
		providers:         make(map[string]*ProviderHealth),
		failoverThreshold: failoverThreshold,
		activeProvider:    "",
	}
}

func (w *ProviderFailoverWatcher) RegisterProvider(name string, isActive bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.providers[name] = &ProviderHealth{
		ProviderName:         name,
		ConsecutiveFailures:  0,
		SuccessfulHeartbeats: 0,
		LastLatencyMs:        0,
		Status:               ProviderStatusOperational,
	}
	if isActive {
		w.activeProvider = name
	}
}

func (w *ProviderFailoverWatcher) RecordHeartbeat(name string, latencyMs uint32, success bool) string {
	w.mu.Lock()
	defer w.mu.Unlock()

	p, exists := w.providers[name]
	if !exists {
		return ""
	}

	var needsFailover bool
	if success {
		p.ConsecutiveFailures = 0
		p.SuccessfulHeartbeats++
		p.LastLatencyMs = latencyMs
		p.Status = ProviderStatusOperational
		needsFailover = false
	} else {
		p.ConsecutiveFailures++
		if p.ConsecutiveFailures >= w.failoverThreshold {
			p.Status = ProviderStatusFailed
			needsFailover = true
		} else {
			p.Status = ProviderStatusUnstable
			needsFailover = false
		}
	}

	if needsFailover && w.activeProvider == name {
		return w.internalFailover()
	}
	return ""
}

func (w *ProviderFailoverWatcher) FailoverToNext() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.internalFailover()
}

func (w *ProviderFailoverWatcher) internalFailover() string {
	for name, p := range w.providers {
		if p.Status == ProviderStatusOperational && name != w.activeProvider {
			w.activeProvider = name
			return name
		}
	}
	return ""
}

func (w *ProviderFailoverWatcher) ActiveProvider() string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.activeProvider
}

func (w *ProviderFailoverWatcher) GetHealth(name string) (ProviderHealth, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	p, ok := w.providers[name]
	if !ok {
		return ProviderHealth{}, false
	}
	return *p, true
}
