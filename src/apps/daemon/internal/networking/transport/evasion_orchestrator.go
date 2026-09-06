package transport

import (
	"sync"
	"time"
)

// EvasionMode represents the active evasion technique.
type EvasionMode string

const (
	EvasionStandard  EvasionMode = "STANDARD"
	EvasionSplit     EvasionMode = "SPLIT"
	EvasionFakeTtl   EvasionMode = "FAKE_TTL"
	EvasionDisorder  EvasionMode = "DISORDER"
	EvasionFronting  EvasionMode = "FRONTING"
)

// AutonomousEvasionOrchestrator tracks network anomalies and dynamically shifts evasion modes.
type AutonomousEvasionOrchestrator struct {
	mu           sync.Mutex
	currentMode  EvasionMode
	rstCount     int
	rstThreshold int
	lastShift    time.Time
	cooldown     time.Duration
}

// NewAutonomousEvasionOrchestrator creates an orchestrator instance.
func NewAutonomousEvasionOrchestrator(rstThreshold int, cooldown time.Duration) *AutonomousEvasionOrchestrator {
	if rstThreshold <= 0 {
		rstThreshold = 3
	}
	if cooldown == 0 {
		cooldown = 10 * time.Second
	}
	return &AutonomousEvasionOrchestrator{
		currentMode:  EvasionStandard,
		rstThreshold: rstThreshold,
		cooldown:     cooldown,
	}
}

// RecordTcpReset records a reset event and switches mode if threshold reached.
func (o *AutonomousEvasionOrchestrator) RecordTcpReset() (EvasionMode, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.rstCount++
	if o.rstCount >= o.rstThreshold && time.Since(o.lastShift) > o.cooldown {
		// Escalate mode
		switch o.currentMode {
		case EvasionStandard:
			o.currentMode = EvasionSplit
		case EvasionSplit:
			o.currentMode = EvasionFakeTtl
		case EvasionFakeTtl:
			o.currentMode = EvasionDisorder
		case EvasionDisorder:
			o.currentMode = EvasionFronting
		default:
			o.currentMode = EvasionStandard
		}
		o.rstCount = 0
		o.lastShift = time.Now()
		return o.currentMode, true
	}

	return o.currentMode, false
}

// CurrentMode returns active evasion mode.
func (o *AutonomousEvasionOrchestrator) CurrentMode() EvasionMode {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.currentMode
}
