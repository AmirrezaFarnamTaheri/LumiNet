package relayclient

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

func TestRelayConnStateReadDeadline(t *testing.T) {
	s := newRelayConnStateWithLimits(16, 16)
	if err := s.SetReadDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err := s.Read(make([]byte, 1))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read error=%v, want deadline exceeded", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("read deadline did not interrupt blocked read")
	}
}

func TestRelayConnStateDeadlineUpdateInterruptsBlockedRead(t *testing.T) {
	s := newRelayConnStateWithLimits(16, 16)
	done := make(chan error, 1)
	go func() {
		_, err := s.Read(make([]byte, 1))
		done <- err
	}()
	time.Sleep(10 * time.Millisecond)
	_ = s.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Read error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("deadline update did not wake read")
	}
}

func TestRelayConnStateWriteBackpressureAndDeadline(t *testing.T) {
	s := newRelayConnStateWithLimits(4, 16)
	_ = s.SetWriteDeadline(time.Now().Add(30 * time.Millisecond))
	n, err := s.Write([]byte("abcdefgh"))
	if n != 4 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Write=(%d,%v), want (4, deadline exceeded)", n, err)
	}
	batch := s.TakeWriteBatch()
	if string(batch) != "abcd" {
		t.Fatalf("batch=%q", batch)
	}
	s.CommitWrite(len(batch))
	_ = s.SetWriteDeadline(time.Time{})
	n, err = s.Write([]byte("efgh"))
	if n != 4 || err != nil {
		t.Fatalf("Write after capacity release=(%d,%v)", n, err)
	}
}

func TestRelayConnStateCloseWakesBlockedOperations(t *testing.T) {
	s := newRelayConnStateWithLimits(1, 16)
	if n, err := s.Write([]byte("x")); n != 1 || err != nil {
		t.Fatalf("initial write=(%d,%v)", n, err)
	}
	writeDone := make(chan error, 1)
	go func() {
		_, err := s.Write([]byte("y"))
		writeDone <- err
	}()
	readDone := make(chan error, 1)
	go func() {
		_, err := s.Read(make([]byte, 1))
		readDone <- err
	}()
	time.Sleep(10 * time.Millisecond)
	s.Close(nil)
	select {
	case err := <-writeDone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("blocked write error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked write was not woken by close")
	}
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("blocked read returned nil error after close")
		}
	case <-time.After(time.Second):
		t.Fatal("blocked read was not woken by close")
	}
}

func TestRelayConnStateReceiveBoundClosesConnection(t *testing.T) {
	s := newRelayConnStateWithLimits(16, 4)
	if err := s.AppendRead([]byte("12345")); err == nil {
		t.Fatal("expected receive-buffer overflow")
	}
	if _, err := s.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write after receive overflow error=%v", err)
	}
}

func TestRelayPollFailureBackoffIsBoundedAndResets(t *testing.T) {
	s := newRelayConnStateWithLimits(16, 16)
	previous := time.Duration(0)
	for i := 0; i < 20; i++ {
		delay := s.RecordPollFailure()
		if delay < relayRetryBaseDelay || delay > relayRetryMaxDelay {
			t.Fatalf("delay %v outside [%v,%v]", delay, relayRetryBaseDelay, relayRetryMaxDelay)
		}
		if delay < previous {
			t.Fatalf("backoff decreased: previous=%v current=%v", previous, delay)
		}
		previous = delay
	}
	if previous != relayRetryMaxDelay {
		t.Fatalf("backoff never reached cap: %v", previous)
	}
	s.RecordPollSuccess()
	if delay := s.RecordPollFailure(); delay != relayRetryBaseDelay {
		t.Fatalf("backoff did not reset after success: %v", delay)
	}
}

func TestWaitRelayRetryHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if waitRelayRetry(ctx, time.Second) {
		t.Fatal("cancelled retry wait reported success")
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("cancelled wait took too long: %v", elapsed)
	}
}

func TestPostRefactor224IdlePollBackoffIsIndependentBoundedAndResetsOnActivity(t *testing.T) {
	s := newRelayConnStateWithLimits(64, 64)
	want := []time.Duration{200 * time.Millisecond, 400 * time.Millisecond, 800 * time.Millisecond, 1600 * time.Millisecond, 3200 * time.Millisecond, 4 * time.Second, 4 * time.Second}
	for i, expected := range want {
		if got := s.RecordIdlePoll(true); got != expected {
			t.Fatalf("empty poll %d delay=%v want=%v", i, got, expected)
		}
	}
	if got := s.RecordIdlePoll(false); got != relayIdlePollBaseDelay {
		t.Fatalf("activity reset=%v", got)
	}
	if _, err := s.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if got := s.RecordIdlePoll(false); got != relayIdlePollBaseDelay {
		t.Fatalf("local write reset=%v", got)
	}
	if err := s.AppendRead([]byte("y")); err != nil {
		t.Fatal(err)
	}
	if got := s.RecordIdlePoll(false); got != relayIdlePollBaseDelay {
		t.Fatalf("downstream reset=%v", got)
	}

	// Transport failures keep their existing, separate retry budget.
	if got := s.RecordPollFailure(); got != relayRetryBaseDelay {
		t.Fatalf("failure retry=%v", got)
	}
	if got := s.RecordIdlePoll(true); got != 400*time.Millisecond {
		t.Fatalf("failure state leaked into idle state: %v", got)
	}
}
