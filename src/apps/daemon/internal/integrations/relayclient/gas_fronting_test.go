package relayclient

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestNextQuotaResetAdvancesAcrossMidnightPacific(t *testing.T) {
	loc := quotaResetTZ
	// Fixed afternoon time: 2026-05-04 14:00 PT -> next midnight must be 2026-05-05 00:00 PT
	now := time.Date(2026, 5, 4, 14, 0, 0, 0, loc)
	got := NextQuotaReset(now)
	want := time.Date(2026, 5, 5, 0, 0, 0, 0, loc)
	if !got.Equal(want) {
		t.Fatalf("NextQuotaReset(%v) = %v, want %v", now, got, want)
	}
}

func TestSelectFrontedClientIndexesDropsFailedAndSlowHosts(t *testing.T) {
	results := []FrontedProbeResult{
		{Index: 0, Host: "www.google.com", Samples: []time.Duration{90 * time.Millisecond, 100 * time.Millisecond}},
		{Index: 1, Host: "mail.google.com", Samples: []time.Duration{110 * time.Millisecond, 120 * time.Millisecond}},
		{Index: 2, Host: "slow.google.com", Samples: []time.Duration{390 * time.Millisecond, 420 * time.Millisecond}}, // > 2.5x
		{Index: 3, Host: "dead.google.com", Err: context.DeadlineExceeded},
	}

	got := SelectFrontedClientIndexes(results)
	if len(got) != 2 || got[0] != 0 || got[1] != 1 {
		t.Fatalf("SelectFrontedClientIndexes returned %v, want [0, 1]", got)
	}
}

func TestIsLocalNetworkOffline(t *testing.T) {
	if IsLocalNetworkOffline(nil) {
		t.Fatal("nil error should not be classified as offline")
	}

	dnsTimeout := &net.DNSError{IsTimeout: true}
	if !IsLocalNetworkOffline(dnsTimeout) {
		t.Fatal("dns timeout error should be classified as offline")
	}

	genericErr := errors.New("remote TLS connection reset by peer")
	if IsLocalNetworkOffline(genericErr) {
		t.Fatal("remote RST should not be classified as local network offline")
	}
}
