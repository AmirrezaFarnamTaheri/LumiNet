// Package resourcebudget derives conservative host-capacity ceilings for
// bounded concurrent work. kindness.go implements IPtProxy-style port
// allocation with kindness mode: resource-limited clients (e.g. mobile, NAT)
// receive preferential port ranges and gentler backoff, while generous
// clients get reduced priority.
package resourcebudget

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// PortRange represents a reserved range of TCP/UDP ports.
type PortRange struct {
	Start      uint16
	End        uint16
	Kind       string // "kind" or "normal"
	ReservationID string
	AcquiredAt time.Time
}

// KindnessMode controls how port allocations distribute fairness.
// It mirrors the IPtProxy kindness concept.
type KindnessMode int

const (
	// KindClient optimises for resource-limited clients (mobile, NAT).
	KindClient KindnessMode = iota
	// Balanced distributes ports evenly.
	Balanced
	// Generous optimises for generous/always-on clients.
	Generous
)

// KindnessBudget manages a shared port range with kindness-aware allocation.
// It uses a slot-map: each port is either free or held by one reservation.
// Backoff is applied to repeated failed allocations and to resource-limited
// clients during high contention.
type KindnessBudget struct {
	mu       sync.RWMutex
	freePort uint32 // atomic cursor for hint-based allocation

	// portMap maps port number → reservation ID (empty = free).
	portMap map[uint16]string

	// ranges are the configured port pools.
	ranges []PortRange

	// reservations tracks active reservations by ID.
	reservations map[string]*PortReservation

	// mode governs the kindness policy.
	mode KindnessMode

	// backoff tracks per-client exponential backoff.
	backoff map[string]*backoffState

	// stats for diagnostics.
	allocations  atomic.Uint64
	releases     atomic.Uint64
	contention   atomic.Uint64
	hintsAttempt atomic.Uint64
}

// PortReservation is a live port hold created by KindnessBudget.Reserve.
type PortReservation struct {
	ID       string
	Port     uint16
	Kind     string
	Acquired time.Time
}

// BackoffConfig controls backoff behavior for resource-limited clients.
type BackoffConfig struct {
	// InitialDelay is the first backoff interval.
	InitialDelay time.Duration
	// MaxDelay caps exponential growth.
	MaxDelay time.Duration
	// Multiplier controls exponential growth rate.
	Multiplier float64
	// JitterFraction is the fraction of delay added as jitter (0-1).
	JitterFraction float64
}

// DefaultBackoffConfig is the applied policy.
var DefaultBackoffConfig = BackoffConfig{
	InitialDelay:   100 * time.Millisecond,
	MaxDelay:       30 * time.Second,
	Multiplier:     2.0,
	JitterFraction: 0.15,
}

var (
	ErrNoFreePort    = errors.New("kindness: no free port in any range")
	ErrNotHolder     = errors.New("kindness: not the holder of this port")
	ErrUnknownRange  = errors.New("kindness: port not in any configured range")
	ErrAlreadyHeld   = errors.New("kindness: port already held")
	ErrNoReservation = errors.New("kindness: reservation not found")
)

// NewKindnessBudget creates a budget with the given port ranges and kindness mode.
func NewKindnessBudget(ranges []PortRange, mode KindnessMode) (*KindnessBudget, error) {
	if len(ranges) == 0 {
		return nil, errors.New("kindness: at least one port range is required")
	}
	portMap := make(map[uint16]string)
	for _, r := range ranges {
		if r.Start > r.End {
			return nil, fmt.Errorf("kindness: invalid range [%d, %d]", r.Start, r.End)
		}
		// Mark all ports as free.
		for p := r.Start; p <= r.End; p++ {
			portMap[p] = ""
		}
	}
	return &KindnessBudget{
		portMap:     portMap,
		ranges:      append([]PortRange(nil), ranges...),
		reservations: make(map[string]*PortReservation),
		mode:        mode,
		backoff:     make(map[string]*backoffState),
	}, nil
}

// Reserve acquires one free port from the ranges, respecting kindness mode.
// The returned PortReservation must be released with Release when done.
// ctx is used for the backoff sleep; pass context.Background for non-blocking.
func (b *KindnessBudget) Reserve(ctx context.Context, id string, kind string, cfg BackoffConfig) (*PortReservation, error) {
	if cfg.InitialDelay == 0 {
		cfg = DefaultBackoffConfig
	}
	if id == "" {
		return nil, errors.New("kindness: reservation id required")
	}

	// Apply backoff for repeated failures on the same ID.
	if err := b.maybeBackoff(ctx, id, cfg); err != nil {
		return nil, err
	}

	// Hint-based allocation: start scanning from a cursor to distribute
	// across the range rather than always allocating the same ports first.
	hint := uint16(atomic.LoadUint32(&b.freePort))
	acquired := b.tryAcquire(hint, id, kind)
	if acquired == 0 {
		// Try full scan as fallback.
		acquired = b.tryAcquire(0, id, kind)
	}

	if acquired == 0 {
		// No free port.
		b.contention.Add(1)
		b.setBackoff(id, cfg)
		return nil, fmt.Errorf("%w (all ports in use)", ErrNoFreePort)
	}

	b.clearBackoff(id)

	res := &PortReservation{
		ID:       id,
		Port:     acquired,
		Kind:     kind,
		Acquired: time.Now(),
	}
	b.mu.Lock()
	b.reservations[id] = res
	b.mu.Unlock()

	b.allocations.Add(1)
	return res, nil
}

// tryAcquire attempts to find and atomically claim a free port starting from
// the given hint (cast to uint16). Returns 0 on failure.
func (b *KindnessBudget) tryAcquire(hint uint16, id, kind string) uint16 {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Collect candidate ports based on kindness mode.
	var candidates []uint16

	switch b.mode {
	case KindClient:
		// Resource-limited clients prefer low ports.
		for _, r := range b.ranges {
			if r.Kind == "kind" || r.Kind == "" {
				candidates = append(candidates, r.Start)
				for p := r.Start; p <= r.End; p++ {
					if b.portMap[p] == "" {
						candidates = append(candidates, p)
					}
				}
			}
		}
	case Generous:
		// Generous clients prefer high ports.
		for _, r := range b.ranges {
			if r.Kind == "normal" || r.Kind == "" {
				for p := r.End; p >= r.Start; p-- {
					if b.portMap[p] == "" {
						candidates = append(candidates, p)
					}
				}
			}
		}
	default: // Balanced
		for p := b.ranges[0].Start; p <= b.ranges[len(b.ranges)-1].End; p++ {
			if b.portMap[p] == "" {
				candidates = append(candidates, p)
			}
		}
	}

	if len(candidates) == 0 {
		return 0
	}

	// Start from hint position.
	start := 0
	for i, p := range candidates {
		if p == hint {
			start = i
			break
		}
	}

	// Scan from hint wrapping around.
	for i := 0; i < len(candidates); i++ {
		idx := (start + i) % len(candidates)
		p := candidates[idx]
		if b.portMap[p] == "" {
			b.portMap[p] = id
			atomic.StoreUint32(&b.freePort, uint32(p)+1)
			return p
		}
	}

	return 0
}

// Release returns a previously reserved port to the free pool.
func (b *KindnessBudget) Release(id string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	res, ok := b.reservations[id]
	if !ok {
		return fmt.Errorf("%w: %q", ErrNoReservation, id)
	}

	port := res.Port
	if held := b.portMap[port]; held != id {
		return fmt.Errorf("%w: port %d held by %q, not %q", ErrNotHolder, port, held, id)
	}

	b.portMap[port] = ""
	delete(b.reservations, id)
	b.releases.Add(1)
	return nil
}

// ReleasePort is a lower-level release by port number. It requires presenting
// the correct reservation ID.
func (b *KindnessBudget) ReleasePort(port uint16, id string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if held := b.portMap[port]; held == "" {
		return fmt.Errorf("%w: port %d is already free", ErrUnknownRange, port)
	} else if held != id {
		return fmt.Errorf("%w: port %d held by %q, not %q", ErrNotHolder, port, held, id)
	}

	delete(b.reservations, id)
	b.portMap[port] = ""
	b.releases.Add(1)
	return nil
}

// Stats returns diagnostic counters.
type KindnessStats struct {
	Allocations  uint64
	Releases     uint64
	Active       int
	Contention   uint64
	HintsAttempt uint64
	Backoffs     int
}

// Stats returns a snapshot of budget telemetry.
func (b *KindnessBudget) Stats() KindnessStats {
	b.mu.RLock()
	active := len(b.reservations)
	backoffs := len(b.backoff)
	b.mu.RUnlock()

	return KindnessStats{
		Allocations:  b.allocations.Load(),
		Releases:     b.releases.Load(),
		Active:       active,
		Contention:   b.contention.Load(),
		HintsAttempt: b.hintsAttempt.Load(),
		Backoffs:     backoffs,
	}
}

// GetReservation returns the reservation for id or nil.
func (b *KindnessBudget) GetReservation(id string) *PortReservation {
	b.mu.RLock()
	defer b.mu.RUnlock()
	r, ok := b.reservations[id]
	if !ok {
		return nil
	}
	cp := *r
	return &cp
}

// SetMode changes the kindness mode. Active reservations are not affected.
func (b *KindnessBudget) SetMode(mode KindnessMode) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.mode = mode
}

// backoffState tracks exponential backoff state for a reservation ID.
type backoffState struct {
	delay    time.Duration
	deadline time.Time
}

func (b *KindnessBudget) maybeBackoff(ctx context.Context, id string, cfg BackoffConfig) error {
	b.mu.RLock()
	bo, ok := b.backoff[id]
	b.mu.RUnlock()
	if !ok {
		return nil
	}

	if time.Now().Before(bo.deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Until(bo.deadline)):
		}
	}
	return nil
}

func (b *KindnessBudget) setBackoff(id string, cfg BackoffConfig) {
	b.mu.Lock()
	defer b.mu.Unlock()
	bo, ok := b.backoff[id]
	if !ok {
		bo = &backoffState{delay: cfg.InitialDelay}
		b.backoff[id] = bo
	}
	bo.delay = time.Duration(math.Min(
		float64(bo.delay)*cfg.Multiplier,
		float64(cfg.MaxDelay),
	))
	// Add jitter.
	jitter := time.Duration(float64(bo.delay) * cfg.JitterFraction * math.Max(0.1, mathrandFloat()))
	bo.deadline = time.Now().Add(bo.delay).Add(jitter)
}

func (b *KindnessBudget) clearBackoff(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.backoff, id)
}

// mathrandFloat returns a float in (0,1]. It uses a simple deterministic
// generator so tests are reproducible; callers should replace with
// rand.Float64() when reproducibility is not needed.
var mathrandFloat = func() float64 {
	v := int64(2654435769) // Knuth multiplicative constant
	v = v * 1664525 + 1013904223
	return float64(v&0x7FFFFFFF) / float64(0x7FFFFFFF)
}
