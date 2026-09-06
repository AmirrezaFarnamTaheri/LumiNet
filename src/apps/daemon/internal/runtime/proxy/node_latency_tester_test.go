package proxy

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestNodeLatencyTester_PingTCP(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen TCP: %v", err)
	}
	defer l.Close()

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	tester := NewNodeLatencyTester()
	ctx := context.Background()
	res := tester.PingTCP(ctx, l.Addr().String(), 500*time.Millisecond)
	if !res.Success {
		t.Errorf("expected PingTCP success, got failure")
	}
}

func TestNodeLatencyTester_PingQUIC(t *testing.T) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to resolve UDP address: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}
	defer conn.Close()

	go func() {
		buf := make([]byte, 1500)
		for {
			n, rAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n >= 23 {
				// Construct a dummy Version Negotiation response
				// First byte 0xC0 (Long Header), Version 0 (Version Negotiation)
				resp := make([]byte, 23)
				resp[0] = 0xC0
				// Version (4 bytes of 0s)
				resp[1] = 0x00
				resp[2] = 0x00
				resp[3] = 0x00
				resp[4] = 0x00
				// copy connection IDs
				resp[5] = buf[14] // SCID length
				copy(resp[6:14], buf[15:23])
				resp[14] = buf[5] // DCID length
				copy(resp[15:23], buf[6:14])

				// Add a tiny mock propagation delay so latency measurement registers > 0 on high-speed loopback pings
				time.Sleep(2 * time.Millisecond)
				_, _ = conn.WriteToUDP(resp, rAddr)
			}
		}
	}()

	tester := NewNodeLatencyTester()
	ctx := context.Background()
	res := tester.PingQUIC(ctx, conn.LocalAddr().String(), 500*time.Millisecond)
	if !res.Success {
		t.Errorf("expected PingQUIC success, got failure")
	}
}

func TestNodeLatencyTester_MeasureJitterTCP(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen TCP: %v", err)
	}
	defer l.Close()

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			time.Sleep(1 * time.Millisecond)
			conn.Close()
		}
	}()

	tester := NewNodeLatencyTester()
	ctx := context.Background()
	res := tester.MeasureJitterTCP(ctx, l.Addr().String(), 3, 5*time.Millisecond, 500*time.Millisecond)
	if !res.Success {
		t.Errorf("expected MeasureJitterTCP success, got failure")
	}
}

func TestNodeLatencyTester_MeasureJitterQUIC(t *testing.T) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to resolve UDP address: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}
	defer conn.Close()

	go func() {
		buf := make([]byte, 1500)
		for {
			n, rAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n >= 23 {
				resp := make([]byte, 23)
				resp[0] = 0xC0
				resp[1] = 0x00
				resp[2] = 0x00
				resp[3] = 0x00
				resp[4] = 0x00
				resp[5] = buf[14]
				copy(resp[6:14], buf[15:23])
				resp[14] = buf[5]
				copy(resp[15:23], buf[6:14])

				time.Sleep(2 * time.Millisecond)
				_, _ = conn.WriteToUDP(resp, rAddr)
			}
		}
	}()

	tester := NewNodeLatencyTester()
	ctx := context.Background()
	res := tester.MeasureJitterQUIC(ctx, conn.LocalAddr().String(), 3, 5*time.Millisecond, 500*time.Millisecond)
	if !res.Success {
		t.Errorf("expected MeasureJitterQUIC success, got failure")
	}
	if res.Latency == 0 {
		t.Errorf("expected measured Latency > 0")
	}
}

func TestEndpointQuality_PartialLossMedianAndJitter(t *testing.T) {
	tester := NewNodeLatencyTester()
	sequence := []LatencyResult{
		{Latency: 10 * time.Millisecond, Success: true},
		{Success: false},
		{Latency: 30 * time.Millisecond, Success: true},
		{Latency: 20 * time.Millisecond, Success: true},
	}
	idx := 0
	res := tester.measureQuality(context.Background(), "example", len(sequence), 0, func() LatencyResult {
		v := sequence[idx]
		idx++
		return v
	})
	if !res.Success || res.Successful != 3 || res.Failed != 1 || res.Samples != 4 {
		t.Fatalf("unexpected quality result: %+v", res)
	}
	if res.LossPercent != 25 {
		t.Fatalf("loss=%v want 25", res.LossPercent)
	}
	if res.MedianLatency != 20*time.Millisecond {
		t.Fatalf("median=%v want 20ms", res.MedianLatency)
	}
	// Successful RTT sequence is 10,30,20 => adjacent deltas 20,10 => 15ms.
	if res.Jitter != 15*time.Millisecond {
		t.Fatalf("jitter=%v want 15ms", res.Jitter)
	}
}

func TestEndpointQuality_BoundsAndOrdering(t *testing.T) {
	tester := NewNodeLatencyTester()
	if got := tester.measureQuality(context.Background(), "x", maxEndpointQualitySamples+1, 0, func() LatencyResult { return LatencyResult{Success: true} }); got.Success {
		t.Fatal("oversized sample request accepted")
	}
	a := EndpointQualityResult{Address: "a", Success: true, LossPercent: 0, MedianLatency: 50 * time.Millisecond}
	b := EndpointQualityResult{Address: "b", Success: true, LossPercent: 10, MedianLatency: 5 * time.Millisecond}
	if !BetterEndpointQuality(a, b) {
		t.Fatal("loss-first ordering did not prefer zero-loss endpoint")
	}
}
