package proxy

import (
	"testing"
)

func TestStreamScheduler(t *testing.T) {
	s := NewStreamScheduler()

	// Push 3 requests for Stream 1 (Priority Class 1)
	s.Push(ScheduledWriteRequest{StreamID: 1, Class: 1, Seq: 1, Data: []byte("s1_p1_r1")})
	s.Push(ScheduledWriteRequest{StreamID: 1, Class: 1, Seq: 2, Data: []byte("s1_p1_r2")})

	// Push 2 requests for Stream 2 (Priority Class 1)
	s.Push(ScheduledWriteRequest{StreamID: 2, Class: 1, Seq: 1, Data: []byte("s2_p1_r1")})

	// Push 1 request for Stream 3 (Priority Class 0 — Higher Priority!)
	s.Push(ScheduledWriteRequest{StreamID: 3, Class: 0, Seq: 1, Data: []byte("s3_p0_r1")})

	if s.Len() != 4 {
		t.Fatalf("expected length 4, got %d", s.Len())
	}

	// 1. High priority (Class 0) must pop first regardless of stream ID
	req, ok := s.Pop()
	if !ok || string(req.Data) != "s3_p0_r1" {
		t.Errorf("expected s3_p0_r1, got %v (ok=%v)", string(req.Data), ok)
	}

	// 2. Class 1 requests should pop in interleaved Round-Robin manner between Stream 1 and Stream 2
	req, ok = s.Pop()
	if !ok {
		t.Fatalf("failed to pop")
	}
	firstStreamID := req.StreamID
	firstData := string(req.Data)

	req, ok = s.Pop()
	if !ok {
		t.Fatalf("failed to pop")
	}
	secondStreamID := req.StreamID
	secondData := string(req.Data)

	// Validate round-robin stream interleaving
	if firstStreamID == secondStreamID {
		t.Errorf("expected round robin interleaving, got back-to-back pops for stream %d", firstStreamID)
	}

	// Make sure the sequence ordering is correct
	if firstStreamID == 1 {
		if firstData != "s1_p1_r1" || secondData != "s2_p1_r1" {
			t.Errorf("pop order mismatch: %s then %s", firstData, secondData)
		}
	} else {
		if firstData != "s2_p1_r1" || secondData != "s1_p1_r1" {
			t.Errorf("pop order mismatch: %s then %s", firstData, secondData)
		}
	}

	// 3. Last remaining packet
	req, ok = s.Pop()
	if !ok || string(req.Data) != "s1_p1_r2" {
		t.Errorf("expected s1_p1_r2, got %v", string(req.Data))
	}

	// 4. Verify scheduler is empty
	if s.Len() != 0 {
		t.Errorf("scheduler not empty, length=%d", s.Len())
	}
	_, ok = s.Pop()
	if ok {
		t.Errorf("expected ok=false on empty pop")
	}
}
