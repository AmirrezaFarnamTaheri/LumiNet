package pingcache

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestPingCache_DeduplicationAndTTL(t *testing.T) {
	// Start local TCP listener to measure latency
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer l.Close()

	addr := l.Addr().(*net.TCPAddr)
	host := addr.IP.String()
	port := addr.Port

	// Spin off handler to accept connection so dial succeeds quickly
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	dir := t.TempDir()
	pc := New(filepath.Join(dir, "ping_cache.json"))

	ctx := context.Background()
	r1 := pc.GetDelay(ctx, host, port, true)
	if !r1.Success || r1.LatencyMs < 0 {
		t.Fatalf("expected successful ping, got %+v", r1)
	}

	// Immediate query should hit cache
	r2 := pc.GetDelay(ctx, host, port, true)
	if r2.Method != "cache" {
		t.Errorf("expected cache hit, got method: %s", r2.Method)
	}
	if r2.LatencyMs != r1.LatencyMs {
		t.Errorf("latencies mismatch: %d vs %d", r1.LatencyMs, r2.LatencyMs)
	}

	// Without cache option, should run live probe
	r3 := pc.GetDelay(ctx, host, port, false)
	if r3.Method != "tcp" {
		t.Errorf("expected live tcp probe, got method: %s", r3.Method)
	}
}

func TestPingCache_Continuous(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()

	addr := l.Addr().(*net.TCPAddr)
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	dir := t.TempDir()
	pc := New(filepath.Join(dir, "ping_cache.json"))

	ch, stop := pc.ContinuousPing(addr.IP.String(), addr.Port, 100*time.Millisecond)
	defer stop()

	select {
	case r := <-ch:
		if !r.Success {
			t.Errorf("expected success in continuous ping, got %+v", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for continuous ping result")
	}
}
