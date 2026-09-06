package mitm

import (
	"context"
	"errors"
	"testing"
)

func TestMitmFrontingBandwidthShaperEnforcesBurst(t *testing.T) {
	shaper, err := NewMitmFrontingBandwidthShaper(100, 10)
	if err != nil {
		t.Fatalf("NewMitmFrontingBandwidthShaper: %v", err)
	}
	if !shaper.AcquiredTokens(10) {
		t.Fatal("expected initial burst to be available")
	}
	if shaper.AcquiredTokens(1) {
		t.Fatal("expected exhausted bucket to reject an immediate acquisition")
	}
	if shaper.TotalDelayedPackets != 1 {
		t.Fatalf("delayed packets = %d, want 1", shaper.TotalDelayedPackets)
	}
}

func TestMitmFrontingBandwidthShaperRejectsInvalidConfig(t *testing.T) {
	if _, err := NewMitmFrontingBandwidthShaper(0, 1); err == nil {
		t.Fatal("expected zero rate to be rejected")
	}
}

func TestMitmFrontingBandwidthShaperWaitHonorsCancellation(t *testing.T) {
	shaper, err := NewMitmFrontingBandwidthShaper(1, 1)
	if err != nil {
		t.Fatalf("NewMitmFrontingBandwidthShaper: %v", err)
	}
	if !shaper.AcquiredTokens(1) {
		t.Fatal("expected initial token")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := shaper.Wait(ctx, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait error = %v, want context.Canceled", err)
	}
}
