package kcppolicy

import "testing"

func intp(v int) *int           { return &v }
func boolp(v bool) *bool        { return &v }
func floatp(v float64) *float64 { return &v }
func int64p(v int64) *int64     { return &v }

func TestResolveLegacyMatchesHistoricalRuntime(t *testing.T) {
	p, err := Resolve(Input{})
	if err != nil {
		t.Fatal(err)
	}
	if p.Intent != "legacy" || p.DataShards != 10 || p.ParityShards != 3 || p.NoDelay != 1 || p.Interval != 20 || p.Resend != 2 || p.NoCongestion != 1 || p.SendWindow != 128 || p.ReceiveWindow != 128 || p.MTU != 0 {
		t.Fatalf("legacy policy drifted: %+v", p)
	}
}

func TestResolveLossAdviceIsBoundedAndExplicitOverridesWin(t *testing.T) {
	p, err := Resolve(Input{
		Intent: "loss-recovery", ObservedLossPercent: floatp(35),
		Overrides: Overrides{ParityShards: intp(0), DataShards: intp(0), NoDelay: intp(0), ACKNoDelay: boolp(false), WriteDelay: boolp(false), DSCP: intp(0), PacketDuplication: intp(0), RateLimitBPS: int64p(0)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.DataShards != 0 || p.ParityShards != 0 || p.NoDelay != 0 || p.ACKNoDelay || p.WriteDelay || p.DSCP != 0 || p.PacketDuplication != 0 || p.RateLimitBPS != 0 {
		t.Fatalf("explicit zero/false overrides lost: %+v", p)
	}
}

func TestResolveAdaptiveFECNeverExceedsShardCeiling(t *testing.T) {
	p, err := Resolve(Input{Intent: "throughput", ObservedLossPercent: floatp(95)})
	if err != nil {
		t.Fatal(err)
	}
	if p.DataShards+p.ParityShards > MaxFECShards {
		t.Fatalf("FEC total=%d exceeds %d", p.DataShards+p.ParityShards, MaxFECShards)
	}
}

func TestResolveRejectsInvalidPolicy(t *testing.T) {
	_, err := Resolve(Input{Overrides: Overrides{DataShards: intp(63), ParityShards: intp(2)}})
	if err == nil {
		t.Fatal("expected FEC bound error")
	}
	_, err = Resolve(Input{ObservedLossPercent: floatp(100)})
	if err == nil {
		t.Fatal("expected loss bound error")
	}
}
