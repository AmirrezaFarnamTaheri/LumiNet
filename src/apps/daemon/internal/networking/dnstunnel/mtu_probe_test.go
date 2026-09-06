package dnstunnel

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeUDPResolver answers any datagram with a fixed-size reply.
type fakeUDPResolver struct {
	conn     *net.UDPConn
	mu       sync.Mutex
	received [][]byte
	stop     chan struct{}
}

func startFakeResolver(t *testing.T, replySize int) *fakeUDPResolver {
	t.Helper()
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeUDPResolver{conn: conn, stop: make(chan struct{})}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, clientAddr, readErr := conn.ReadFromUDP(buf)
			if readErr != nil {
				return
			}
			fake.mu.Lock()
			fake.received = append(fake.received, append([]byte(nil), buf[:n]...))
			fake.mu.Unlock()
			reply := make([]byte, replySize)
			copy(reply, buf[:minInt(12, n)])
			if _, wErr := conn.WriteToUDP(reply, clientAddr); wErr != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { close(fake.stop); conn.Close() })
	return fake
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (f *fakeUDPResolver) sizes() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]int, 0, len(f.received))
	for _, r := range f.received {
		out = append(out, len(r))
	}
	return out
}

func TestMTUProbeBinarySearchFindsBudget(t *testing.T) {
	const ceiling = 1500
	resolver := startFakeResolver(t, 64)
	prober := NewMTUProber(resolver.conn.LocalAddr().String(), "probe.example")
	// The fake answers everything; the largest accepted size is bounded by the
	// OS UDP send limit well above our ceiling, so expect ~CeilSize discovery
	// modulo binary-search granularity (±16).
	prober.CeilSize = ceiling
	prober.FloorSize = 512
	prober.Retries = 0
	prober.Timeout = 300 * time.Millisecond

	result, err := prober.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Err != "" {
		t.Fatalf("probe error: %s", result.Err)
	}
	if result.UploadBudget < ceiling-32 || result.UploadBudget > ceiling {
		t.Fatalf("upload budget %d outside [%d,%d]", result.UploadBudget, ceiling-32, ceiling)
	}
	if result.DownloadBudget <= result.UploadBudget {
		t.Fatalf("download budget should exceed upload: %+v", result)
	}
	sizes := resolver.sizes()
	if len(sizes) == 0 {
		t.Fatal("resolver received nothing")
	}
}

func TestBuildPaddedQueryHitsTargetLength(t *testing.T) {
	for _, target := range []int{512, 800, 1232, 2000, 4096} {
		q := buildPaddedQuery("probe.example", target)
		if len(q) < target-24 || len(q) > target+64 {
			t.Errorf("target %d produced %d bytes", target, len(q))
		}
		// QDCOUNT must be 1 and ARCOUNT must be 1 (EDNS padding).
		flagsQD := binary.BigEndian.Uint16(q[4:6])
		flagsAR := binary.BigEndian.Uint16(q[10:12])
		if flagsQD != 1 || flagsAR != 1 {
			t.Errorf("target %d: qd=%d ar=%d", target, flagsQD, flagsAR)
		}
	}
}

func TestMTUProberSilentResolverTimesOut(t *testing.T) {
	// Bind a socket but never answer.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("udp unavailable: %v", err)
	}
	defer conn.Close()

	prober := NewMTUProber(conn.LocalAddr().String(), "silent.example")
	prober.Timeout = 50 * time.Millisecond
	prober.Retries = 0
	prober.CeilSize = 600
	prober.FloorSize = 400

	result, err := prober.Probe(context.Background())
	if err == nil && result.Err == "" {
		t.Fatal("expected failure against silent resolver")
	}
	if result.UploadBudget != 0 {
		t.Fatalf("no size survived silence; budget=%d", result.UploadBudget)
	}
}
