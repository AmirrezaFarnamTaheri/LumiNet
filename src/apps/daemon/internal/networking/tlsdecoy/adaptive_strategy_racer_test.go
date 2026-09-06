package tlsdecoy

import (
	"bytes"
	"testing"
)

func TestSniCharsFragmentation(t *testing.T) {
	clientHello := buildTestClientHello("mci.ir")
	offset, length, found := LocateSNI(clientHello)
	if !found || length != 6 {
		t.Fatalf("failed to locate SNI 'mci.ir'")
	}

	frags := FragmentExtended(clientHello, ExtendedStrategySniChars, 0)
	// prefix + 6 single-char slices (no trailing extensions) = 7 slices total
	if len(frags) != 7 {
		t.Fatalf("expected 7 fragments for sni_chars, got %d", len(frags))
	}
	if len(frags[0]) != offset {
		t.Fatalf("expected first frag to end at offset %d, got %d", offset, len(frags[0]))
	}
	for i := 1; i <= 6; i++ {
		if len(frags[i]) != 1 {
			t.Fatalf("expected 1-byte char fragment at index %d, got %d", i, len(frags[i]))
		}
	}

	reconstructed := bytes.Join(frags, nil)
	if !bytes.Equal(reconstructed, clientHello) {
		t.Fatalf("reconstructed sni_chars does not match original ClientHello")
	}
}

func TestMulti64Fragmentation(t *testing.T) {
	clientHello := buildTestClientHello("speedtest.net")
	frags := FragmentExtended(clientHello, ExtendedStrategyMulti64, 64)
	if len(frags) <= 1 || len(frags[0]) != 64 {
		t.Fatalf("Multi64 chunking failed: len=%d first_len=%d", len(frags), len(frags[0]))
	}

	reconstructed := bytes.Join(frags, nil)
	if !bytes.Equal(reconstructed, clientHello) {
		t.Fatalf("reconstructed Multi64 does not match original ClientHello")
	}
}

func TestValidateStrategyResponse(t *testing.T) {
	// Empty
	if status := ValidateStrategyResponse(nil); status != ResponseStatusEmpty {
		t.Fatalf("expected ResponseStatusEmpty, got %v", status)
	}

	// TLS Alert (0x15)
	alert := []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28}
	if status := ValidateStrategyResponse(alert); status != ResponseStatusAlertRejected {
		t.Fatalf("expected ResponseStatusAlertRejected, got %v", status)
	}

	// Truncated Handshake (< 8 bytes)
	truncated := []byte{0x16, 0x03, 0x03, 0x00}
	if status := ValidateStrategyResponse(truncated); status != ResponseStatusTruncatedMalformed {
		t.Fatalf("expected ResponseStatusTruncatedMalformed, got %v", status)
	}

	// Valid ServerHello
	valid := []byte{0x16, 0x03, 0x03, 0x00, 0x50, 0x02, 0x00, 0x00, 0x4c}
	if status := ValidateStrategyResponse(valid); status != ResponseStatusValid {
		t.Fatalf("expected ResponseStatusValid, got %v", status)
	}
}

func TestBuildDisposableFakeProbe(t *testing.T) {
	probe := BuildDisposableFakeProbe("speedtest.net")
	if len(probe) < 50 || probe[0] != 0x16 || probe[5] != 0x01 {
		t.Fatalf("invalid disposable fake probe structure")
	}
	offset, length, found := LocateSNI(probe)
	if !found || string(probe[offset:offset+length]) != "speedtest.net" {
		t.Fatalf("fake probe SNI mismatch")
	}
}

func TestAdaptiveStrategyRacer(t *testing.T) {
	racer := NewAdaptiveStrategyRacer(CarrierModeMci, "speedtest.net")
	plan := racer.PlanStrategies("104.18.8.83")
	if len(plan) == 0 || plan[0].Strategy != ExtendedStrategyFull20 {
		t.Fatalf("unexpected initial plan: %v", plan)
	}

	racer.RecordSuccess("104.18.8.83", ExtendedStrategySniChars)
	strat, ok := racer.PreferredStrategy("104.18.8.83")
	if !ok || strat != ExtendedStrategySniChars {
		t.Fatalf("preferred strategy not recorded")
	}

	updatedPlan := racer.PlanStrategies("104.18.8.83")
	if updatedPlan[0].Strategy != ExtendedStrategySniChars {
		t.Fatalf("prioritized plan should have SniChars first: %v", updatedPlan)
	}
}
