// Package events — unit tests for EventRing and EventBus.
package events

import (
	"fmt"
	"testing"
	"time"
)

func TestEventRing_AppendAndSince(t *testing.T) {
	r := NewEventRing(10)

	// Append 5 events
	for i := 0; i < 5; i++ {
		r.Append(Event{Type: fmt.Sprintf("ev.%d", i)})
	}

	if r.Len() != 5 {
		t.Errorf("Len: got %d, want 5", r.Len())
	}
	if r.MaxSeq() != 5 {
		t.Errorf("MaxSeq: got %d, want 5", r.MaxSeq())
	}

	all := r.Since(0)
	if len(all) != 5 {
		t.Errorf("Since(0): got %d events, want 5", len(all))
	}
	// Sequence numbers should be 1..5
	for i, e := range all {
		if e.Seq != uint64(i+1) {
			t.Errorf("event[%d].Seq = %d, want %d", i, e.Seq, i+1)
		}
	}

	// Since(3) should return events 4 and 5
	after3 := r.Since(3)
	if len(after3) != 2 {
		t.Errorf("Since(3): got %d events, want 2", len(after3))
	}
}

func TestEventRing_Eviction(t *testing.T) {
	r := NewEventRing(3) // capacity 3

	for i := 0; i < 5; i++ {
		r.Append(Event{Type: fmt.Sprintf("ev.%d", i)})
	}
	// Ring holds only the last 3: seq 3, 4, 5
	if r.Len() != 3 {
		t.Errorf("Len after eviction: got %d, want 3", r.Len())
	}
	all := r.Since(0)
	if len(all) != 3 {
		t.Errorf("Since(0) after eviction: got %d, want 3", len(all))
	}
	if all[0].Seq != 3 {
		t.Errorf("oldest after eviction: seq=%d, want 3", all[0].Seq)
	}
}

func TestEventRing_Latest(t *testing.T) {
	r := NewEventRing(20)
	for i := 0; i < 10; i++ {
		r.Append(Event{Type: "t"})
	}
	got := r.Latest(3)
	if len(got) != 3 {
		t.Errorf("Latest(3): got %d events", len(got))
	}
	// Should be seq 8, 9, 10
	if got[0].Seq != 8 {
		t.Errorf("Latest[0].Seq = %d, want 8", got[0].Seq)
	}
}

func TestEventRing_Timestamps(t *testing.T) {
	r := NewEventRing(10)
	before := time.Now().Add(-time.Millisecond)
	e := r.Append(Event{Type: "ts.test"})
	after := time.Now().Add(time.Millisecond)

	if e.Timestamp.Before(before) || e.Timestamp.After(after) {
		t.Errorf("timestamp %v not in expected range [%v, %v]", e.Timestamp, before, after)
	}
}

func TestEventBus_PubSub(t *testing.T) {
	bus := NewEventBus(100)
	ch, _ := bus.Subscribe("test-sub", 32)

	published := bus.Publish(Event{Type: "test.event", Payload: "hello"})

	select {
	case received := <-ch:
		if received.Seq != published.Seq {
			t.Errorf("received seq %d, want %d", received.Seq, published.Seq)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("did not receive event within timeout")
	}

	bus.Unsubscribe("test-sub")
}

func TestEventBus_ReconnectReplay(t *testing.T) {
	bus := NewEventBus(100)

	// Publish 5 events before subscriber connects
	for i := 0; i < 5; i++ {
		bus.Publish(Event{Type: "pre"})
	}

	_, maxSeq := bus.Subscribe("replayer", 32)
	// Replay events since before subscription
	missed := bus.Since(maxSeq - 3) // get last 3 pre-subscription events
	if len(missed) < 3 {
		t.Errorf("replay: got %d events, want at least 3", len(missed))
	}

	bus.Unsubscribe("replayer")
}
