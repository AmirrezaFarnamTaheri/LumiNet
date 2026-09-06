package resourcebudget

import "testing"

func TestForClassifiesCapacityConservatively(t *testing.T) {
	tests := []struct {
		name string
		cpus int
		mem  uint64
		tier Tier
		cap  int
	}{
		{"tiny cpu", 2, 8192, TierLow, 4},
		{"tiny memory", 32, 384, TierLow, 4},
		{"medium cpu", 4, 8192, TierMedium, 16},
		{"medium memory", 32, 1536, TierMedium, 16},
		{"high", 8, 8192, TierHigh, 64},
		{"unknown memory", 8, 0, TierHigh, 64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := For(tt.cpus, tt.mem)
			if got.Tier != tt.tier || got.WorkerCap != tt.cap {
				t.Fatalf("For(%d,%d)=%+v, want tier=%s cap=%d", tt.cpus, tt.mem, got, tt.tier, tt.cap)
			}
		})
	}
}

func TestCapWorkersIntersectsAllCeilings(t *testing.T) {
	low := For(2, 8192)
	if got := low.CapWorkers(64, 32); got != 4 {
		t.Fatalf("low cap=%d, want 4", got)
	}
	high := For(16, 8192)
	if got := high.CapWorkers(128, 24); got != 24 {
		t.Fatalf("subsystem ceiling=%d, want 24", got)
	}
	if got := high.CapWorkers(0, 0); got != 1 {
		t.Fatalf("zero request=%d, want 1", got)
	}
}
