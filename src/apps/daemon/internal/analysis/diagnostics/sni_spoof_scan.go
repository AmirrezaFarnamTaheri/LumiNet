package diagnostics

import (
	"context"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/maybeknott/luminet/internal/foundation/resourcebudget"
	"github.com/maybeknott/luminet/internal/networking/tlsdecoy"
)

const (
	maxSniSpoofCandidates  = 4096
	maxSniSpoofConcurrency = 64
)

// SniSpoofScanConfig controls a bounded diagnostic scan.
type SniSpoofScanConfig struct {
	Target      string
	FakeSNI     string
	Timeout     time.Duration
	Concurrency int
}

type SniSpoofOutcome string

const (
	SniSpoofOK             SniSpoofOutcome = "ok"
	SniSpoofConnectFailed  SniSpoofOutcome = "connect_failed"
	SniSpoofConnectTimeout SniSpoofOutcome = "connect_timeout"
	SniSpoofReadTimeout    SniSpoofOutcome = "read_timeout"
	SniSpoofBadResponse    SniSpoofOutcome = "bad_response"
	SniSpoofEmptyResponse  SniSpoofOutcome = "empty_response"
	SniSpoofInvalidSNI     SniSpoofOutcome = "invalid_sni"
	SniSpoofCancelled      SniSpoofOutcome = "cancelled"
	SniSpoofBudgetExceeded SniSpoofOutcome = "budget_exceeded"
)

type SniSpoofResult struct {
	SNI     string
	Target  string
	Outcome SniSpoofOutcome
	Detail  string
	Latency time.Duration
}

func RunSniSpoofScan(ctx context.Context, cfg SniSpoofScanConfig, snis []string) []SniSpoofResult {
	return runSniSpoofScanWithProbe(ctx, cfg, snis, probeFakeSNI)
}

type sniSpoofProbeFunc func(context.Context, string, string, time.Duration) SniSpoofResult

type sniSpoofJob struct {
	index int
	sni   string
}

func runSniSpoofScanWithProbe(ctx context.Context, cfg SniSpoofScanConfig, snis []string, probe sniSpoofProbeFunc) []SniSpoofResult {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 10
	}
	cfg.Concurrency = resourcebudget.Detect().CapWorkers(cfg.Concurrency, maxSniSpoofConcurrency)
	if cfg.Timeout <= 0 {
		cfg.Timeout = 6 * time.Second
	}
	if len(snis) > maxSniSpoofCandidates {
		return []SniSpoofResult{{Target: cfg.Target, Outcome: SniSpoofBudgetExceeded, Detail: fmt.Sprintf("candidate budget exceeds %d: got %d", maxSniSpoofCandidates, len(snis))}}
	}
	results := make([]SniSpoofResult, len(snis))
	if len(snis) == 0 {
		return results
	}
	workerCount := cfg.Concurrency
	if workerCount > len(snis) {
		workerCount = len(snis)
	}
	jobs := make(chan sniSpoofJob)
	var wg sync.WaitGroup
	wg.Add(workerCount)
	for w := 0; w < workerCount; w++ {
		go func() {
			defer wg.Done()
			for job := range jobs {
				if err := ctx.Err(); err != nil {
					results[job.index] = SniSpoofResult{SNI: job.sni, Target: cfg.Target, Outcome: SniSpoofCancelled, Detail: err.Error()}
					continue
				}
				results[job.index] = probe(ctx, cfg.Target, job.sni, cfg.Timeout)
			}
		}()
	}
	for i, sni := range snis {
		select {
		case jobs <- sniSpoofJob{index: i, sni: sni}:
		case <-ctx.Done():
			for j := i; j < len(snis); j++ {
				results[j] = SniSpoofResult{SNI: snis[j], Target: cfg.Target, Outcome: SniSpoofCancelled, Detail: ctx.Err().Error()}
			}
			close(jobs)
			wg.Wait()
			return results
		}
	}
	close(jobs)
	wg.Wait()
	return results
}

func probeFakeSNI(ctx context.Context, target, fakeSni string, timeout time.Duration) SniSpoofResult {
	r := SniSpoofResult{SNI: fakeSni, Target: target}
	if err := ctx.Err(); err != nil {
		r.Outcome = SniSpoofCancelled
		r.Detail = err.Error()
		return r
	}
	if !validSNI(fakeSni) {
		r.Outcome = SniSpoofInvalidSNI
		r.Detail = "SNI must be an ASCII DNS name of at most 219 bytes"
		return r
	}
	start := time.Now()
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		r.Latency = time.Since(start)
		if ctx.Err() != nil {
			r.Outcome = SniSpoofCancelled
			r.Detail = ctx.Err().Error()
		} else if isTimeout(err) {
			r.Outcome = SniSpoofConnectTimeout
		} else {
			r.Outcome = SniSpoofConnectFailed
			r.Detail = err.Error()
		}
		return r
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(buildFakeClientHello(fakeSni)); err != nil {
		r.Latency = time.Since(start)
		r.Outcome = SniSpoofConnectFailed
		r.Detail = fmt.Sprintf("write error: %v", err)
		return r
	}
	header := make([]byte, 5)
	n, err := io.ReadFull(conn, header)
	r.Latency = time.Since(start)
	if err != nil {
		if ctx.Err() != nil {
			r.Outcome = SniSpoofCancelled
			r.Detail = ctx.Err().Error()
		} else if isTimeout(err) {
			r.Outcome = SniSpoofReadTimeout
		} else if n == 0 {
			r.Outcome = SniSpoofEmptyResponse
		} else {
			r.Outcome = SniSpoofBadResponse
			r.Detail = fmt.Sprintf("short TLS record header: %d/5 bytes", n)
		}
		return r
	}
	if header[0] != 0x16 {
		r.Outcome = SniSpoofBadResponse
		r.Detail = fmt.Sprintf("first byte: 0x%02x", header[0])
		return r
	}
	r.Outcome = SniSpoofOK
	return r
}

// buildFakeClientHello delegates to the canonical lower-layer TLS decoy owner.
func buildFakeClientHello(sni string) []byte {
	hello, err := tlsdecoy.BuildPaddedClientHello(sni)
	if err != nil {
		return nil
	}
	return hello
}

func isTimeout(err error) bool {
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}

// SniSpoofStabilityResult aggregates repeated probes for one SNI. It is derived
// from the RKh scanner's useful stability/latency ranking primitive while
// retaining LumiNet's bounded TLS-record probe semantics.
type SniSpoofStabilityResult struct {
	SNI          string                  `json:"sni"`
	Target       string                  `json:"target"`
	Attempts     int                     `json:"attempts"`
	Successes    int                     `json:"successes"`
	StabilityPct int                     `json:"stability_pct"`
	AvgLatencyMs int64                   `json:"avg_latency_ms"`
	Score        int64                   `json:"score"`
	Outcomes     map[SniSpoofOutcome]int `json:"outcomes"`
	LastDetail   string                  `json:"last_detail,omitempty"`
}

// RunSniSpoofStabilityScan repeats the bounded SNI scan and aggregates success
// rate plus average latency. Runs are capped to avoid turning diagnostics into
// an unbounded fan-out multiplier.
func RunSniSpoofStabilityScan(ctx context.Context, cfg SniSpoofScanConfig, snis []string, runs int) []SniSpoofStabilityResult {
	return runSniSpoofStabilityScanWithProbe(ctx, cfg, snis, runs, probeFakeSNI)
}

func runSniSpoofStabilityScanWithProbe(ctx context.Context, cfg SniSpoofScanConfig, snis []string, runs int, probe sniSpoofProbeFunc) []SniSpoofStabilityResult {
	if runs <= 0 {
		runs = 3
	}
	if runs > 5 {
		runs = 5
	}
	if len(snis) > maxSniSpoofCandidates {
		return []SniSpoofStabilityResult{{Target: cfg.Target, Attempts: 0, LastDetail: fmt.Sprintf("candidate budget exceeds %d: got %d", maxSniSpoofCandidates, len(snis))}}
	}
	agg := make([]SniSpoofStabilityResult, len(snis))
	for i, sni := range snis {
		agg[i] = SniSpoofStabilityResult{SNI: sni, Target: cfg.Target, Outcomes: make(map[SniSpoofOutcome]int)}
	}
	for run := 0; run < runs; run++ {
		if ctx.Err() != nil {
			break
		}
		batch := runSniSpoofScanWithProbe(ctx, cfg, snis, probe)
		if len(batch) != len(snis) {
			break
		}
		for i, result := range batch {
			a := &agg[i]
			a.Attempts++
			a.Outcomes[result.Outcome]++
			a.LastDetail = result.Detail
			if result.Outcome == SniSpoofOK {
				a.Successes++
				a.AvgLatencyMs += result.Latency.Milliseconds()
			}
		}
	}
	for i := range agg {
		a := &agg[i]
		if a.Attempts > 0 {
			a.StabilityPct = (a.Successes * 100) / a.Attempts
		}
		if a.Successes > 0 {
			a.AvgLatencyMs /= int64(a.Successes)
		} else {
			a.AvgLatencyMs = 9999
		}
		// Preserve the donor's intuitive ordering: stability dominates, latency
		// breaks ties. This is a diagnostic score, not a security decision.
		a.Score = int64(a.StabilityPct*10) - a.AvgLatencyMs
	}
	sort.SliceStable(agg, func(i, j int) bool {
		if agg[i].Score != agg[j].Score {
			return agg[i].Score > agg[j].Score
		}
		return agg[i].SNI < agg[j].SNI
	})
	return agg
}
