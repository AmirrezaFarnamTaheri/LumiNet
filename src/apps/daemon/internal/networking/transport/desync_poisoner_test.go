package transport

import (
	"testing"
)

func TestPlanDesyncAttackSplit(t *testing.T) {
	data := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
	segments, err := PlanDesyncAttack(DesyncSplit, 4, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(segments) != 2 {
		t.Fatalf("expected 2 segments, got %d", len(segments))
	}
	if string(segments[0].Payload) != "GET " {
		t.Errorf("expected 'GET ', got '%s'", string(segments[0].Payload))
	}
}

func TestPlanDesyncAttackFakeTtl(t *testing.T) {
	data := []byte("CLIENT_HELLO_DATA")
	segments, err := PlanDesyncAttack(DesyncFakeTtl, 5, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(segments) != 3 {
		t.Fatalf("expected 3 segments, got %d", len(segments))
	}
	if !segments[0].IsFake || segments[0].TTL != 3 {
		t.Errorf("expected first segment to be fake with TTL 3")
	}
}
