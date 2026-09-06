package transport

import (
	"bytes"
	"testing"
)

func TestUniversalMeshEvasionPipeline(t *testing.T) {
	pipeline := NewUniversalMeshEvasionPipeline("node-test")

	// Direct tier
	frames := pipeline.ProcessOutboundFrame([]byte("1234567890"))
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame in direct tier, got %d", len(frames))
	}

	// Escalate to HolePunchedMesh (3 errors)
	pipeline.ReportFailure()
	pipeline.ReportFailure()
	tier1 := pipeline.ReportFailure()
	if tier1 != TierHolePunchedMesh {
		t.Fatalf("expected TierHolePunchedMesh, got %v", tier1)
	}

	// Escalate to DpiEvadedMesh (3 more errors)
	pipeline.ReportFailure()
	pipeline.ReportFailure()
	tier2 := pipeline.ReportFailure()
	if tier2 != TierDpiEvadedMesh {
		t.Fatalf("expected TierDpiEvadedMesh, got %v", tier2)
	}

	// Check fragmented frames in DpiEvadedMesh
	frags := pipeline.ProcessOutboundFrame([]byte("1234567890"))
	if len(frags) != 2 {
		t.Fatalf("expected 2 fragmented frames in DPI evaded tier, got %d", len(frags))
	}

	// Escalate to StealthBridgeFallback (3 more errors)
	pipeline.ReportFailure()
	pipeline.ReportFailure()
	tier3 := pipeline.ReportFailure()
	if tier3 != TierStealthBridgeFallback {
		t.Fatalf("expected TierStealthBridgeFallback, got %v", tier3)
	}

	stealth := pipeline.ProcessOutboundFrame([]byte("HELLO"))
	if !bytes.HasPrefix(stealth[0], []byte("STH:")) {
		t.Fatalf("expected stealth prefix, got: %s", string(stealth[0]))
	}

	pipeline.ReportSuccess()
	metrics := pipeline.GetMetrics()
	if metrics.ModeSwitches != 3 || metrics.PacketsProcessed != 3 {
		t.Fatalf("unexpected metrics: %+v", metrics)
	}
}
