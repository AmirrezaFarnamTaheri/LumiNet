package diagnostics

import (
	"encoding/json"
	"testing"
	"time"
)

func measurement(cc, testName, input string, anomaly bool) CensorshipMeasurement {
	return CensorshipMeasurement{
		ProbeCC: cc, TestName: testName, Input: input,
		StartAt: time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC),
		Anomaly: anomaly,
	}
}

func TestDetectorNewBlockedKeyEmitsChange(t *testing.T) {
	d := NewEventDetector()
	change, err := d.Observe(measurement("IR", "web_connectivity", "https://example.com", true))
	if err != nil {
		t.Fatal(err)
	}
	if change == nil || !change.Blocked {
		t.Fatalf("first anomaly on unseen key should emit blocked change, got %+v", change)
	}
	if change.Mean != ScoreAnomaly {
		t.Fatalf("mean = %v, want %v", change.Mean, ScoreAnomaly)
	}
}

func TestDetectorHysteresisRequiresSustainedEvidence(t *testing.T) {
	d := NewEventDetector()
	clean := measurement("US", "web_connectivity", "https://stable.example", false)
	if _, err := d.Observe(clean); err != nil {
		t.Fatal(err)
	}
	// Single anomaly spike must NOT flip state (EMA keeps mean below 0.10).
	if change, _ := d.Observe(measurement("US", "web_connectivity", "https://stable.example", true)); change != nil {
		t.Fatalf("single spike flapped state: %+v", change)
	}
	mean, blocked, _ := d.Status("US", "web_connectivity", "https://stable.example")
	if blocked {
		t.Fatalf("state blocked after one spike, mean=%v", mean)
	}
}

func TestDetectorSustainedAnomaliesBlockThenClear(t *testing.T) {
	d := NewEventDetector()
	anomaly := measurement("IR", "telegram", "https://t.me/example", true)
	blockedSeen := false
	for i := 0; i < 200; i++ {
		change, err := d.Observe(anomaly)
		if err != nil {
			t.Fatal(err)
		}
		if change != nil && change.Blocked {
			blockedSeen = true
			break
		}
	}
	if !blockedSeen {
		t.Fatal("sustained anomalies never crossed upper limit")
	}
	clearedSeen := false
	for i := 0; i < 400; i++ {
		change, err := d.Observe(measurement("IR", "telegram", "https://t.me/example", false))
		if err != nil {
			t.Fatal(err)
		}
		if change != nil && !change.Blocked {
			clearedSeen = true
			break
		}
	}
	if !clearedSeen {
		t.Fatal("sustained clean measurements never cleared block")
	}
}

func TestDetectorConfirmedScoresHigher(t *testing.T) {
	d := NewEventDetector()
	confirmed := measurement("RU", "tor_reachability", "https://rust.example", false)
	confirmed.Confirmed = true
	change, err := d.Observe(confirmed)
	if err != nil {
		t.Fatal(err)
	}
	if change == nil || !change.Blocked {
		t.Fatal("confirmed block (score 2.0) must trip detector immediately")
	}
}

func TestDetectorEmptyInputSkipped(t *testing.T) {
	d := NewEventDetector()
	if _, err := d.Observe(measurement("IR", "web_connectivity", "", true)); err == nil {
		t.Fatal("empty input should be rejected")
	}
}

func TestDetectorStateRoundTrip(t *testing.T) {
	d := NewEventDetector()
	for i := 0; i < 50; i++ {
		_, _ = d.Observe(measurement("IR", "test", "https://persist.example", true))
	}
	state, err := d.MarshalState()
	if err != nil {
		t.Fatal(err)
	}
	restored := NewEventDetector()
	if err := restored.UnmarshalState(state); err != nil {
		t.Fatal(err)
	}
	wantMean, wantBlocked, ok := d.Status("IR", "test", "https://persist.example")
	gotMean, gotBlocked, gotOK := restored.Status("IR", "test", "https://persist.example")
	if !ok || !gotOK || wantBlocked != gotBlocked || wantMean != gotMean {
		t.Fatalf("state round-trip mismatch: want (%v,%v,%v) got (%v,%v,%v)",
			wantMean, wantBlocked, ok, gotMean, gotBlocked, gotOK)
	}
	raw, _ := json.Marshal(map[string]float64{"mean": gotMean})
	if len(raw) == 0 {
		t.Fatal("json sanity failed")
	}
}
