package diagnostics

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maybeknott/luminet/internal/networking/tlsdecoy"
)

func TestBuildFakeClientHello(t *testing.T) {
	sni := "security.vercel.com"
	pkt := buildFakeClientHello(sni)

	if len(pkt) != tlsdecoy.ClientHelloSize {
		t.Fatalf("expected %d-byte padded ClientHello, got %d", tlsdecoy.ClientHelloSize, len(pkt))
	}
	if pkt[0] != 0x16 || pkt[1] != 0x03 || pkt[2] != 0x01 {
		t.Fatalf("unexpected TLS record header: % x", pkt[:3])
	}
	if got := int(binary.BigEndian.Uint16(pkt[3:5])); got != len(pkt)-5 {
		t.Fatalf("record length=%d want=%d", got, len(pkt)-5)
	}
	if pkt[5] != 0x01 {
		t.Fatalf("expected ClientHello handshake type, got 0x%02x", pkt[5])
	}
	handshakeLen := int(pkt[6])<<16 | int(pkt[7])<<8 | int(pkt[8])
	if handshakeLen != len(pkt)-9 {
		t.Fatalf("handshake length=%d want=%d", handshakeLen, len(pkt)-9)
	}
	if got := int(binary.BigEndian.Uint16(pkt[125:127])); got != len(sni) {
		t.Fatalf("SNI length=%d want=%d", got, len(sni))
	}
	if got := string(pkt[127 : 127+len(sni)]); got != sni {
		t.Fatalf("SNI=%q want=%q", got, sni)
	}
	if pkt[len(pkt)-1] != 0x00 {
		t.Fatal("expected padding to keep the decoy ClientHello at fixed size")
	}
}

func TestBuildFakeClientHelloRejectsInvalidSNI(t *testing.T) {
	for _, sni := range []string{"", "bad name", "-bad.example", "bad-.example", strings.Repeat("a", 220)} {
		if got := buildFakeClientHello(sni); got != nil {
			t.Fatalf("expected invalid SNI %q to be rejected", sni)
		}
	}
}

func TestBuildFakeClientHelloSupportsMaximumBoundedSNI(t *testing.T) {
	sni := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 27)
	if len(sni) != maxSniSpoofLength {
		t.Fatalf("test SNI length=%d", len(sni))
	}
	pkt := buildFakeClientHello(sni)
	if len(pkt) != tlsdecoy.ClientHelloSize {
		t.Fatalf("maximum SNI produced %d bytes", len(pkt))
	}
	if got := string(pkt[127 : 127+len(sni)]); got != sni {
		t.Fatalf("maximum SNI round-trip mismatch")
	}
}

func TestRunSniSpoofScan_LocalNetworkFail(t *testing.T) {
	// Use a port that should always fail to connect (closed port)
	cfg := SniSpoofScanConfig{
		Target:      "127.0.0.1:19443",
		Timeout:     500 * time.Millisecond,
		Concurrency: 2,
	}

	snis := []string{"example.com", "cloudflare.com"}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	results := RunSniSpoofScan(ctx, cfg, snis)
	if len(results) != len(snis) {
		t.Fatalf("expected %d results, got %d", len(snis), len(results))
	}

	for _, r := range results {
		// Connect to closed port should give connect_failed
		if r.Outcome != SniSpoofConnectFailed && r.Outcome != SniSpoofConnectTimeout {
			t.Errorf("expected connect_failed or connect_timeout for %s, got %s", r.SNI, r.Outcome)
		}
	}
}

func TestSniSpoofScan_Defaults(t *testing.T) {
	cfg := SniSpoofScanConfig{}
	// Defaults should be set inside RunSniSpoofScan
	if cfg.Concurrency != 0 {
		t.Error("expected zero concurrency before run")
	}
}

func TestRunSniSpoofScanCapsConcurrencyAndCandidateBudget(t *testing.T) {
	var mu sync.Mutex
	active, maxActive := 0, 0
	probe := func(ctx context.Context, target, sni string, timeout time.Duration) SniSpoofResult {
		mu.Lock()
		active++
		if active > maxActive {
			maxActive = active
		}
		mu.Unlock()
		time.Sleep(10 * time.Millisecond)
		mu.Lock()
		active--
		mu.Unlock()
		return SniSpoofResult{SNI: sni, Target: target, Outcome: SniSpoofOK}
	}
	snis := make([]string, 80)
	for i := range snis {
		snis[i] = fmt.Sprintf("x%d.example.com", i)
	}
	got := runSniSpoofScanWithProbe(context.Background(), SniSpoofScanConfig{Target: "x:443", Concurrency: 1000}, snis, probe)
	if len(got) != 80 || maxActive > maxSniSpoofConcurrency {
		t.Fatalf("results=%d maxActive=%d", len(got), maxActive)
	}
	over := make([]string, maxSniSpoofCandidates+1)
	got = runSniSpoofScanWithProbe(context.Background(), SniSpoofScanConfig{Target: "x:443"}, over, probe)
	if len(got) != 1 || got[0].Outcome != SniSpoofBudgetExceeded {
		t.Fatalf("budget not enforced: %#v", got)
	}
}

func TestRunSniSpoofScanCancellationStopsQueueing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := RunSniSpoofScan(ctx, SniSpoofScanConfig{Target: "x:443", Concurrency: 2}, []string{"a.example", "b.example"})
	for _, r := range got {
		if r.Outcome != SniSpoofCancelled {
			t.Fatalf("expected cancelled: %#v", got)
		}
	}
}

func TestProbeFakeSNIReadsExactTLSRecordHeader(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 512)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte{0x16, 0x03})
		time.Sleep(20 * time.Millisecond)
		_, _ = c.Write([]byte{0x03, 0x00, 0x00})
	}()
	r := probeFakeSNI(context.Background(), ln.Addr().String(), "example.com", time.Second)
	<-done
	if r.Outcome != SniSpoofOK {
		t.Fatalf("got %#v", r)
	}
}

func TestProbeFakeSNIRejectsShortTLSRecordHeader(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 512)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte{0x16, 0x03})
	}()
	r := probeFakeSNI(context.Background(), ln.Addr().String(), "example.com", time.Second)
	if r.Outcome != SniSpoofBadResponse {
		t.Fatalf("got %#v", r)
	}
}

func TestProbeFakeSNIRejectsInvalidName(t *testing.T) {
	r := probeFakeSNI(context.Background(), "127.0.0.1:1", "bad name", time.Second)
	if r.Outcome != SniSpoofInvalidSNI {
		t.Fatalf("got %#v", r)
	}
}

func TestRunSniSpoofStabilityScanRanksStableLowLatencyCandidates(t *testing.T) {
	var calls sync.Map
	probe := func(_ context.Context, target, sni string, _ time.Duration) SniSpoofResult {
		value, _ := calls.LoadOrStore(sni, new(atomic.Int32))
		count := value.(*atomic.Int32).Add(1)
		if sni == "flaky.example" && count%2 == 0 {
			return SniSpoofResult{SNI: sni, Target: target, Outcome: SniSpoofReadTimeout, Latency: 80 * time.Millisecond}
		}
		latency := 20 * time.Millisecond
		if sni == "slow.example" {
			latency = 200 * time.Millisecond
		}
		return SniSpoofResult{SNI: sni, Target: target, Outcome: SniSpoofOK, Latency: latency}
	}
	got := runSniSpoofStabilityScanWithProbe(context.Background(), SniSpoofScanConfig{Target: "x:443", Concurrency: 2}, []string{"slow.example", "flaky.example", "fast.example"}, 4, probe)
	if len(got) != 3 {
		t.Fatalf("got %d results", len(got))
	}
	if got[0].SNI != "fast.example" || got[0].StabilityPct != 100 || got[0].AvgLatencyMs != 20 {
		t.Fatalf("unexpected first result: %+v", got[0])
	}
	if got[2].SNI != "flaky.example" || got[2].StabilityPct != 50 {
		t.Fatalf("unexpected flaky result: %+v", got[2])
	}
}
