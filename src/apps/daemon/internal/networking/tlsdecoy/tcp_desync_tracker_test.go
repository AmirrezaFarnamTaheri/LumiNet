package tlsdecoy

import (
	"testing"
)

func TestTcpDesyncTrackerHandshake(t *testing.T) {
	tracker := NewTcpDesyncTracker("192.168.1.50", "188.114.98.0", 54321, 443)

	// Outbound SYN (seq 20000, ack 0)
	act, err := tracker.ProcessOutbound(20000, 0, true, false, false, false, 0, 100, 517)
	if err != nil {
		t.Fatalf("ProcessOutbound SYN failed: %v", err)
	}
	if act.ScheduleDecoy {
		t.Error("SYN should not schedule decoy")
	}
	if tracker.Phase != PhaseSynSent {
		t.Errorf("Phase = %v; want %v", tracker.Phase, PhaseSynSent)
	}

	// Inbound SYN-ACK (seq 60000, ack 20001)
	inAct, err := tracker.ProcessInbound(60000, 20001, true, true, false, false, 0)
	if err != nil {
		t.Fatalf("ProcessInbound SYN-ACK failed: %v", err)
	}
	if inAct.DecoyAcknowledged {
		t.Error("SYN-ACK should not acknowledge decoy")
	}
	if tracker.Phase != PhaseSynAckReceived {
		t.Errorf("Phase = %v; want %v", tracker.Phase, PhaseSynAckReceived)
	}

	// Outbound ACK (seq 20001, ack 60001)
	act2, err := tracker.ProcessOutbound(20001, 60001, false, true, false, false, 0, 100, 517)
	if err != nil {
		t.Fatalf("ProcessOutbound ACK failed: %v", err)
	}
	if !act2.ScheduleDecoy {
		t.Error("ACK should schedule decoy")
	}
	// (20000 + 1) - 517 = 19484
	if act2.DecoySeq != 19484 {
		t.Errorf("DecoySeq = %d; want 19484", act2.DecoySeq)
	}
	if act2.NewIdent != 101 {
		t.Errorf("NewIdent = %d; want 101", act2.NewIdent)
	}
	if tracker.Phase != PhaseDecoyInjected {
		t.Errorf("Phase = %v; want %v", tracker.Phase, PhaseDecoyInjected)
	}

	// Inbound ACK (seq 60001, ack 20001)
	inAct2, err := tracker.ProcessInbound(60001, 20001, false, true, false, false, 0)
	if err != nil {
		t.Fatalf("ProcessInbound Decoy ACK failed: %v", err)
	}
	if !inAct2.DecoyAcknowledged {
		t.Error("Should acknowledge decoy")
	}
	if tracker.Phase != PhaseDecoyAcknowledged {
		t.Errorf("Phase = %v; want %v", tracker.Phase, PhaseDecoyAcknowledged)
	}
}

func TestTcpDesyncTrackerInvalidSequence(t *testing.T) {
	tracker := NewTcpDesyncTracker("192.168.1.50", "188.114.98.0", 54321, 443)

	// Outbound SYN with ack != 0
	_, err := tracker.ProcessOutbound(20000, 1, true, false, false, false, 0, 100, 517)
	if err == nil {
		t.Error("Expected error for non-zero ack on SYN")
	}
	if tracker.Phase != PhaseTerminated {
		t.Errorf("Phase = %v; want %v", tracker.Phase, PhaseTerminated)
	}
}
