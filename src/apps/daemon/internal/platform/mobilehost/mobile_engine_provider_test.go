package mobilehost

import (
	"testing"
)

func TestMobileEngineProvider(t *testing.T) {
	cfg := MobileEngineConfig{
		BindAddress: "127.0.0.1",
		Socks5Port:  10808,
		HttpPort:    10809,
		DnsPort:     5353,
		MTU:         1500,
	}

	provider := NewMobileEngineProvider(cfg)
	if provider.GetState() != EngineStopped {
		t.Fatalf("expected initial state stopped")
	}

	err := provider.StartEngine(1000)
	if err != nil {
		t.Fatalf("start engine failed: %v", err)
	}

	if provider.GetState() != EngineRunning {
		t.Fatalf("expected running state")
	}

	provider.RecordTraffic(500, 1000, 1060)
	m := provider.GetMetrics()
	if m.RxBytes != 500 || m.TxBytes != 1000 || m.UptimeSecs != 60 {
		t.Fatalf("metrics mismatch: %+v", m)
	}

	provider.MarkDegraded(true)
	if provider.GetState() != EngineDegraded {
		t.Fatalf("expected degraded state")
	}

	err = provider.StopEngine()
	if err != nil {
		t.Fatalf("stop failed: %v", err)
	}
	if provider.GetState() != EngineStopped {
		t.Fatalf("expected stopped state")
	}
}
