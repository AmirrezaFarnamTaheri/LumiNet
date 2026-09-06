package jobs

import (
	"testing"
	"time"

	"github.com/maybeknott/luminet/internal/native/bridge"
)

func TestStreamScanIntentNormalization(t *testing.T) {
	intent := StreamScanIntent{}
	normalized, err := normalizeIntent(intent)
	if err != nil {
		t.Fatalf("normalizeIntent: %v", err)
	}

	streamIntent, ok := normalized.(StreamScanIntent)
	if !ok {
		t.Fatalf("expected StreamScanIntent, got %T", normalized)
	}

	if streamIntent.Target != "127.0.0.1" {
		t.Errorf("Target = %s, want 127.0.0.1", streamIntent.Target)
	}
	if len(streamIntent.Ports) == 0 {
		t.Errorf("Ports is empty, expected default ports")
	}
	if streamIntent.TimeoutMs != 3000 {
		t.Errorf("TimeoutMs = %d, want 3000", streamIntent.TimeoutMs)
	}
}

func TestBroadcasterStreamEventsFanOut(t *testing.T) {
	b := NewBroadcaster()
	jobID := "job-stream-test-123"

	ch := b.Subscribe(jobID)
	defer b.Unsubscribe(jobID, ch)

	testProbe := bridge.StreamProbeResultData{
		Target:    "127.0.0.1",
		Port:      80,
		Open:      true,
		LatencyMs: 12.5,
	}

	event := JobEvent{
		JobID:     jobID,
		Type:      "probe_result",
		Data:      testProbe,
		Timestamp: time.Now(),
	}

	b.Publish(event)

	select {
	case received := <-ch:
		if received.JobID != jobID {
			t.Errorf("JobID = %s, want %s", received.JobID, jobID)
		}
		if received.Type != "probe_result" {
			t.Errorf("Type = %s, want probe_result", received.Type)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for broadcasted stream event")
	}
}
