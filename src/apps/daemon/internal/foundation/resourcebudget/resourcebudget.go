// Package resourcebudget derives conservative host-capacity ceilings for
// bounded concurrent work. It is an envelope, not a scheduler: subsystem
// owners keep their own lower limits and may always choose less concurrency.
package resourcebudget

import (
	"os"
	"runtime"
	"strconv"
	"strings"
)

type Tier string

const (
	TierLow    Tier = "low"
	TierMedium Tier = "medium"
	TierHigh   Tier = "high"
)

type Budget struct {
	Tier            Tier   `json:"tier"`
	CPUs            int    `json:"cpus"`
	MemoryMB        uint64 `json:"memory_mb,omitempty"`
	WorkerCap       int    `json:"worker_cap"`
	ChannelCapacity int    `json:"channel_capacity"`
}

// Detect returns a process-local capacity envelope. Memory is intentionally
// optional: if the platform cannot expose total memory cheaply and safely,
// CPU count alone decides the tier rather than inventing a value.
func Detect() Budget {
	cpus := runtime.NumCPU()
	if cpus < 1 {
		cpus = 1
	}
	return For(cpus, detectMemoryMB())
}

// For is the deterministic policy function used by tests and callers that
// already have host-capacity evidence.
func For(cpus int, memoryMB uint64) Budget {
	if cpus < 1 {
		cpus = 1
	}
	tier := TierHigh
	if cpus <= 2 || (memoryMB > 0 && memoryMB <= 384) {
		tier = TierLow
	} else if cpus <= 4 || (memoryMB > 0 && memoryMB <= 1536) {
		tier = TierMedium
	}

	budget := Budget{Tier: tier, CPUs: cpus, MemoryMB: memoryMB}
	switch tier {
	case TierLow:
		budget.WorkerCap = 4
		budget.ChannelCapacity = 128
	case TierMedium:
		budget.WorkerCap = 16
		budget.ChannelCapacity = 512
	default:
		budget.WorkerCap = 64
		budget.ChannelCapacity = 1024
	}
	return budget
}

// CapWorkers intersects a subsystem request, an optional subsystem ceiling,
// and this host envelope. It never returns less than one for positive work.
func (b Budget) CapWorkers(requested, ceiling int) int {
	if requested <= 0 {
		requested = 1
	}
	if ceiling > 0 && requested > ceiling {
		requested = ceiling
	}
	cap := b.WorkerCap
	if cap <= 0 {
		cap = 1
	}
	if requested > cap {
		requested = cap
	}
	if requested < 1 {
		return 1
	}
	return requested
}

func detectMemoryMB() uint64 {
	if runtime.GOOS != "linux" && runtime.GOOS != "android" {
		return 0
	}
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "MemTotal:" {
			continue
		}
		kb, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0
		}
		return kb / 1024
	}
	return 0
}
