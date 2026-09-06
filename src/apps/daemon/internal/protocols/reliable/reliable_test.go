package reliable

import (
	"testing"
	"time"
)

func TestStreamProfilesPreserveDispatchAndOrdering(t *testing.T) {
	now := time.Unix(100, 0)
	manual := New(Config{InitialSeq: 0, Window: 8, SendLimit: 6, MinRTO: time.Second, MaxRTO: time.Minute, ManualDispatch: true})
	if got := manual.Step(Command{Op: Send, Payload: []byte("dns"), Now: now}); len(got.Outbound) != 0 || got.Pending != 1 {
		t.Fatalf("manual send = %#v", got)
	}
	if got := manual.Step(Command{Op: Tick, Now: now}); len(got.Outbound) != 1 || got.Outbound[0].Seq != 0 {
		t.Fatalf("manual tick = %#v", got)
	}

	eager := New(Config{InitialSeq: 1, Window: 8, MinRTO: time.Second, MaxRTO: time.Minute})
	if got := eager.Step(Command{Op: Send, Payload: []byte("arq"), Now: now}); len(got.Outbound) != 1 || got.Outbound[0].Seq != 1 {
		t.Fatalf("eager send = %#v", got)
	}
	if got := eager.Step(Command{Op: Receive, Frame: Frame{Kind: Data, Seq: 2, Payload: []byte("world")}, Now: now}); len(got.Delivered) != 0 {
		t.Fatalf("out-of-order delivery = %#v", got)
	}
	got := eager.Step(Command{Op: Receive, Frame: Frame{Kind: Data, Seq: 1, Payload: []byte("hello ")}, Now: now})
	if len(got.Delivered) != 2 || string(got.Delivered[0].Payload) != "hello " || string(got.Delivered[1].Payload) != "world" {
		t.Fatalf("ordered delivery = %#v", got.Delivered)
	}
}

func TestStreamNackPolicyAndCloseOnExhaustion(t *testing.T) {
	now := time.Unix(100, 0)
	s := New(Config{Window: 4, MinRTO: time.Second, MaxRTO: time.Second, MaxRetries: 1, NackInitialDelay: time.Second, NackRepeatInterval: time.Second, CloseOnExhaustion: true})
	s.Step(Command{Op: Send, Payload: []byte("x"), Now: now})
	if got := s.Step(Command{Op: Receive, Frame: Frame{Kind: Nack, Seq: 0}, Now: now}); got.FastRetransmit {
		t.Fatal("first NACK bypassed initial delay")
	}
	if got := s.Step(Command{Op: Receive, Frame: Frame{Kind: Nack, Seq: 0}, Now: now.Add(time.Second)}); !got.FastRetransmit {
		t.Fatal("eligible NACK did not retransmit")
	}
	s.Step(Command{Op: Tick, Now: now.Add(3 * time.Second)})
	s.Step(Command{Op: Tick, Now: now.Add(5 * time.Second)})
	if !s.Stats().Closed {
		t.Fatal("retry exhaustion did not close the configured stream")
	}
}
