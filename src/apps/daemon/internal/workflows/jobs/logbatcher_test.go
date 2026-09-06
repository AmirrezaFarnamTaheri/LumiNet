package jobs

import (
	"testing"
	"time"
)

func collect(ch <-chan BatchedRecords[string], n int, timeout time.Duration) []BatchedRecords[string] {
	out := make([]BatchedRecords[string], 0, n)
	timer := time.After(timeout)
	for len(out) < n {
		select {
		case b := <-ch:
			out = append(out, b)
		case <-timer:
			return out
		}
	}
	return out
}

func TestLogBatcherSizeTrigger(t *testing.T) {
	ch := make(chan BatchedRecords[string], 8)
	b := NewLogBatcher(LogBatcherOptions[string]{MaxRecords: 3, MaxInterval: time.Hour, Out: ch})
	defer b.Close()
	for _, v := range []string{"a", "b", "c"} {
		b.Add(v)
	}
	batches := collect(ch, 1, time.Second)
	if len(batches) != 1 || batches[0].Trigger != "size" {
		t.Fatalf("unexpected batches: %+v", batches)
	}
	if len(batches[0].Records) != 3 || batches[0].Records[0] != "a" {
		t.Fatalf("records wrong: %+v", batches[0].Records)
	}
}

func TestLogBatcherTimeTrigger(t *testing.T) {
	ch := make(chan BatchedRecords[string], 8)
	b := NewLogBatcher(LogBatcherOptions[string]{MaxRecords: 100, MaxInterval: 30 * time.Millisecond, Out: ch})
	defer b.Close()
	b.Add("only")
	batches := collect(ch, 1, time.Second)
	if len(batches) != 1 || batches[0].Trigger != "time" {
		t.Fatalf("unexpected batches: %+v", batches)
	}
	if batches[0].Records[0] != "only" {
		t.Fatalf("record wrong: %+v", batches[0])
	}
}

func TestLogBatcherCloseFlushes(t *testing.T) {
	ch := make(chan BatchedRecords[string], 8)
	b := NewLogBatcher(LogBatcherOptions[string]{MaxRecords: 100, MaxInterval: time.Hour, Out: ch})
	b.Add("tail")
	b.Close()
	batches := collect(ch, 1, time.Second)
	if len(batches) != 1 {
		t.Fatalf("close should flush, got %+v", batches)
	}
	// Post-close adds are ignored.
	b.Add("ignored")
	select {
	case extra := <-ch:
		t.Fatalf("post-close add leaked: %+v", extra)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestLogBatcherCoalescesWhenConsumerSlow(t *testing.T) {
	// Unbuffered channel: the producer path must not block; records coalesce.
	ch := make(chan BatchedRecords[string]) // unbuffered
	b := NewLogBatcher(LogBatcherOptions[string]{MaxRecords: 2, MaxInterval: time.Millisecond, Out: ch})
	go func() {
		for i := 0; i < 20; i++ {
			b.Add("x")
			time.Sleep(time.Millisecond)
		}
	}()
	time.Sleep(80 * time.Millisecond)
	b.Close()
	// No panic and no deadlock is the assertion; drain whatever is pending.
	for {
		select {
		case <-ch:
			continue
		default:
		}
		return
	}
}
