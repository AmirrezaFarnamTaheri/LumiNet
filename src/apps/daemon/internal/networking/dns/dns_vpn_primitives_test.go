package dns

import (
	"testing"
	"time"
)

func TestMultiLevelPriorityQueue(t *testing.T) {
	mlq := NewMultiLevelPriorityQueue[string](16)

	// Push at different priority tiers: 5 (lowest), 3, 1, 0 (highest)
	if !mlq.Push(5, 105, "item-p5") {
		t.Errorf("expected push p5 to succeed")
	}
	if !mlq.Push(3, 103, "item-p3") {
		t.Errorf("expected push p3 to succeed")
	}
	if !mlq.Push(1, 101, "item-p1") {
		t.Errorf("expected push p1 to succeed")
	}
	if !mlq.Push(0, 100, "item-p0") {
		t.Errorf("expected push p0 to succeed")
	}

	// Key deduplication: push existing key must fail
	if mlq.Push(0, 100, "duplicate") {
		t.Errorf("expected duplicate key push to fail")
	}

	if mlq.Size() != 4 {
		t.Fatalf("expected size 4, got %d", mlq.Size())
	}

	// Peek highest priority
	item, prio, ok := mlq.Peek()
	if !ok || item != "item-p0" || prio != 0 {
		t.Fatalf("unexpected peek: item=%s, prio=%d, ok=%v", item, prio, ok)
	}

	// Pops must come in priority order: 0, 1, 3, 5
	it0, pr0, ok0 := mlq.Pop()
	if !ok0 || it0 != "item-p0" || pr0 != 0 {
		t.Errorf("unexpected pop 0: %s, %d", it0, pr0)
	}

	it1, pr1, ok1 := mlq.Pop()
	if !ok1 || it1 != "item-p1" || pr1 != 1 {
		t.Errorf("unexpected pop 1: %s, %d", it1, pr1)
	}

	// Direct removal by key
	remVal, remOk := mlq.RemoveByKey(105)
	if !remOk || remVal != "item-p5" {
		t.Errorf("unexpected removeByKey: %s, %v", remVal, remOk)
	}

	// Remaining: p3
	if mlq.Size() != 1 {
		t.Errorf("expected size 1 after remove, got %d", mlq.Size())
	}

	it3, pr3, ok3 := mlq.Pop()
	if !ok3 || it3 != "item-p3" || pr3 != 3 {
		t.Errorf("unexpected pop 3: %s, %d", it3, pr3)
	}

	// Queue is now empty
	if _, _, okEmpty := mlq.Pop(); okEmpty {
		t.Errorf("expected empty queue to fail pop")
	}
}

func TestDnsFragmentStore(t *testing.T) {
	store := NewDnsFragmentStore[uint64](8)
	retention := 500 * time.Millisecond
	now := time.Now()

	// Single fragment fast path
	singlePayload := []byte("single datagram")
	data, completed, dup := store.Collect(10, singlePayload, 0, 1, now, retention)
	if !completed || dup || string(data) != "single datagram" {
		t.Fatalf("unexpected single fragment collect: completed=%v, dup=%v, data=%s", completed, dup, string(data))
	}

	// Immediate duplicate within retention window
	_, completedDup, isDup := store.Collect(10, singlePayload, 0, 1, now.Add(10*time.Millisecond), retention)
	if completedDup || !isDup {
		t.Fatalf("expected duplicate suppression: completed=%v, dup=%v", completedDup, isDup)
	}

	// Multi-fragment reassembly (3 parts) out of order: 2, 0, 1
	key := uint64(999)
	p0 := []byte("hello ")
	p1 := []byte("dns ")
	p2 := []byte("vpn!")

	_, c2, d2 := store.Collect(key, p2, 2, 3, now, retention)
	if c2 || d2 {
		t.Errorf("fragment 2 should be incomplete")
	}

	_, c0, d0 := store.Collect(key, p0, 0, 3, now, retention)
	if c0 || d0 {
		t.Errorf("fragment 0 should be incomplete")
	}

	assembled, c1, d1 := store.Collect(key, p1, 1, 3, now, retention)
	if !c1 || d1 || string(assembled) != "hello dns vpn!" {
		t.Fatalf("expected reassembly: completed=%v, dup=%v, assembled=%s", c1, d1, string(assembled))
	}

	// Duplicate after assembly
	_, cMultiDup, dMultiDup := store.Collect(key, p0, 0, 3, now.Add(20*time.Millisecond), retention)
	if cMultiDup || !dMultiDup {
		t.Fatalf("expected duplicate suppression for multi-fragment")
	}
}

func TestPackedControlBlocks(t *testing.T) {
	b1 := ControlBlock{PacketType: 1, StreamID: 42, SequenceNum: 100, FragmentID: 0, TotalFragments: 1}
	b2 := ControlBlock{PacketType: 2, StreamID: 42, SequenceNum: 101, FragmentID: 0, TotalFragments: 1}
	b3 := ControlBlock{PacketType: 6, StreamID: 88, SequenceNum: 200, FragmentID: 1, TotalFragments: 2}

	packed := PackControlBlocks([]ControlBlock{b1, b2, b3})
	if len(packed) != 3*PackedControlBlockSize {
		t.Fatalf("expected len %d, got %d", 3*PackedControlBlockSize, len(packed))
	}

	unpacked := ParsePackedControlBlocks(packed)
	if len(unpacked) != 3 {
		t.Fatalf("expected 3 unpacked blocks, got %d", len(unpacked))
	}

	if unpacked[0] != b1 || unpacked[1] != b2 || unpacked[2] != b3 {
		t.Errorf("unpacked blocks mismatch: %+v vs expected", unpacked)
	}
}
