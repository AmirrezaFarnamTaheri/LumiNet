// Package scanner implements host and dns probing operations.

package scanner

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	mrand "math/rand"
	"net"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ─── DPI Obfuscation Methods ─────────────────────────────────────────────────
// Note: DPIObfuscationOptions struct is declared in sidecar_models.go.
// The following are additional methods on the existing type.

// Getters & Setters for DPIObfuscationOptions
func (d *DPIObfuscationOptions) GetEnablePayloadSplitting() bool { return d.EnablePayloadSplitting }
func (d *DPIObfuscationOptions) SetEnablePayloadSplitting(v bool) { d.EnablePayloadSplitting = v }
func (d *DPIObfuscationOptions) GetSplitByteBoundary() int { return d.SplitByteBoundary }
func (d *DPIObfuscationOptions) SetSplitByteBoundary(v int) { d.SplitByteBoundary = v }
func (d *DPIObfuscationOptions) GetSplitDelayMicroseconds() int { return d.SplitDelayMicroseconds }
func (d *DPIObfuscationOptions) SetSplitDelayMicroseconds(v int) { d.SplitDelayMicroseconds = v }
func (d *DPIObfuscationOptions) GetRandomizeSplitPoint() bool { return d.RandomizeSplitPoint }
func (d *DPIObfuscationOptions) SetRandomizeSplitPoint(v bool) { d.RandomizeSplitPoint = v }
func (d *DPIObfuscationOptions) GetFragmentCount() int { return d.FragmentCount }
func (d *DPIObfuscationOptions) SetFragmentCount(v int) { d.FragmentCount = v }
func (d *DPIObfuscationOptions) GetEnableDesync() bool { return d.EnableDesync }
func (d *DPIObfuscationOptions) SetEnableDesync(v bool) { d.EnableDesync = v }
func (d *DPIObfuscationOptions) GetDesyncMode() string { return d.DesyncMode }
func (d *DPIObfuscationOptions) SetDesyncMode(v string) { d.DesyncMode = v }
func (d *DPIObfuscationOptions) GetDesyncFakeRepeat() int { return d.DesyncFakeRepeat }
func (d *DPIObfuscationOptions) SetDesyncFakeRepeat(v int) { d.DesyncFakeRepeat = v }
func (d *DPIObfuscationOptions) GetDesyncFakeDelayMs() int { return d.DesyncFakeDelayMs }
func (d *DPIObfuscationOptions) SetDesyncFakeDelayMs(v int) { d.DesyncFakeDelayMs = v }
func (d *DPIObfuscationOptions) GetDesyncFakePreset() string { return d.DesyncFakePreset }
func (d *DPIObfuscationOptions) SetDesyncFakePreset(v string) { d.DesyncFakePreset = v }
func (d *DPIObfuscationOptions) GetDesyncSNIChunk() int { return d.DesyncSNIChunk }
func (d *DPIObfuscationOptions) SetDesyncSNIChunk(v int) { d.DesyncSNIChunk = v }
func (d *DPIObfuscationOptions) GetDesyncFragDelayMs() int { return d.DesyncFragDelayMs }
func (d *DPIObfuscationOptions) SetDesyncFragDelayMs(v int) { d.DesyncFragDelayMs = v }

// Builders for DPIObfuscationOptions
func (d *DPIObfuscationOptions) WithPayloadSplitting(boundary int) *DPIObfuscationOptions {
	d.EnablePayloadSplitting = true
	d.SplitByteBoundary = boundary
	return d
}
func (d *DPIObfuscationOptions) WithDesync(mode string) *DPIObfuscationOptions {
	d.EnableDesync = true
	d.DesyncMode = mode
	return d
}
func (d *DPIObfuscationOptions) WithFragmentCount(n int) *DPIObfuscationOptions {
	d.FragmentCount = n
	return d
}
func (d *DPIObfuscationOptions) WithRandomSplitPoint() *DPIObfuscationOptions {
	d.RandomizeSplitPoint = true
	return d
}

// IsNoop returns true if all obfuscation options are disabled.
func (d *DPIObfuscationOptions) IsNoop() bool {
	return !d.EnablePayloadSplitting && !d.EnableDesync
}

// ObfuscatedConn wraps a net.Conn and performs DPI obfuscation on Write.
type ObfuscatedConn struct {
	net.Conn
	Opts DPIObfuscationOptions
}

// Write performs fragment-split or desync-obfuscated TLS record injection.
// Maps to upstream ObfuscatedConn.Write().
func (c *ObfuscatedConn) Write(b []byte) (int, error) {
	if c.Opts.EnableDesync && isClientHelloRecord(b) {
		if c.Opts.DesyncSNIChunk > 0 {
			chunks := FragmentWrites(b, c.Opts.DesyncSNIChunk)
			total := 0
			for i, ch := range chunks {
				n, err := c.Conn.Write(ch)
				total += n
				if err != nil {
					return total, err
				}
				if i+1 < len(chunks) && c.Opts.DesyncFragDelayMs > 0 {
					time.Sleep(time.Duration(c.Opts.DesyncFragDelayMs) * time.Millisecond)
				}
			}
			return total, nil
		}
	}
	if !c.Opts.EnablePayloadSplitting || len(b) <= 1 {
		return c.Conn.Write(b)
	}

	length := len(b)
	fc := c.Opts.FragmentCount
	if fc <= 1 {
		fc = 2
	}
	if fc > length {
		fc = length
	}

	var sorted []int
	if c.Opts.RandomizeSplitPoint {
		var seedBuf [4]byte
		var seed int
		if _, err := crand.Read(seedBuf[:]); err == nil {
			seed = int(binary.BigEndian.Uint32(seedBuf[:]))
		} else {
			seed = time.Now().Nanosecond()
		}
		rng := mrand.New(mrand.NewSource(int64(seed)))
		indices := make(map[int]bool)
		for len(indices) < fc-1 {
			idx := rng.Intn(length-1) + 1
			indices[idx] = true
		}
		sorted = make([]int, 0, len(indices))
		for idx := range indices {
			sorted = append(sorted, idx)
		}
		sort.Ints(sorted)
	} else {
		if fc == 2 {
			boundary := c.Opts.SplitByteBoundary
			if boundary <= 0 || boundary >= length {
				boundary = length / 2
				if boundary == 0 {
					boundary = 1
				}
			}
			sorted = []int{boundary}
		} else {
			sorted = make([]int, 0, fc-1)
			chunkSize := length / fc
			if chunkSize == 0 {
				chunkSize = 1
			}
			for i := 1; i < fc; i++ {
				boundary := i * chunkSize
				if boundary >= length {
					break
				}
				sorted = append(sorted, boundary)
			}
		}
	}

	delay := time.Duration(c.Opts.SplitDelayMicroseconds) * time.Microsecond
	if delay == 0 {
		delay = 50 * time.Microsecond
	}

	total := 0
	last := 0
	for _, idx := range sorted {
		n, err := c.Conn.Write(b[last:idx])
		total += n
		if err != nil {
			return total, err
		}
		last = idx
		time.Sleep(delay)
	}
	n, err := c.Conn.Write(b[last:])
	total += n
	return total, err
}

// DialObfuscatedSocket opens a TCP connection and wraps it in an ObfuscatedConn if needed.
// Maps to upstream DialObfuscatedSocket().
func DialObfuscatedSocket(ctx context.Context, network, addr string, timeout time.Duration, opts DPIObfuscationOptions) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	rawConn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	if opts.EnablePayloadSplitting || opts.EnableDesync {
		return &ObfuscatedConn{Conn: rawConn, Opts: opts}, nil
	}
	return rawConn, nil
}

// FragmentWrites splits a byte slice into chunks of size chunkSize.
// Maps to upstream FragmentWrites() in sidecar_desync.go.
func FragmentWrites(b []byte, chunkSize int) [][]byte {
	if chunkSize <= 0 || len(b) == 0 {
		return [][]byte{b}
	}
	var chunks [][]byte
	for len(b) > 0 {
		end := chunkSize
		if end > len(b) {
			end = len(b)
		}
		chunks = append(chunks, b[:end])
		b = b[end:]
	}
	return chunks
}

// isClientHelloRecord detects if a TLS record starts with a Client Hello handshake.
// Maps to upstream isClientHello() helper.
func isClientHelloRecord(b []byte) bool {
	// TLS record type 0x16 = Handshake, handshake type 0x01 = ClientHello
	return len(b) >= 6 && b[0] == 0x16 && b[5] == 0x01
}

// ─── Scan Orchestration ───────────────────────────────────────────────────────

// ScanJobFunc is the function signature for processing a single scan target.
type ScanJobFunc[T any, R any] func(ctx context.Context, item T) R

// ScanBatchStats tracks progress counters during a scan batch.
type ScanBatchStats struct {
	mu          sync.RWMutex
	Total       int
	Checked     int64
	Working     int64
	TLSWorking  int64
	HTTPWorking int64
	Down        int64
	Batches     int
	Batch       int
}

// Getters & Setters for ScanBatchStats
func (s *ScanBatchStats) GetTotal() int { s.mu.RLock(); defer s.mu.RUnlock(); return s.Total }
func (s *ScanBatchStats) SetTotal(v int) { s.mu.Lock(); defer s.mu.Unlock(); s.Total = v }
func (s *ScanBatchStats) GetChecked() int64 { return atomic.LoadInt64(&s.Checked) }
func (s *ScanBatchStats) AddChecked() int64 { return atomic.AddInt64(&s.Checked, 1) }
func (s *ScanBatchStats) GetWorking() int64 { return atomic.LoadInt64(&s.Working) }
func (s *ScanBatchStats) AddWorking() int64 { return atomic.AddInt64(&s.Working, 1) }
func (s *ScanBatchStats) GetTLSWorking() int64 { return atomic.LoadInt64(&s.TLSWorking) }
func (s *ScanBatchStats) AddTLSWorking() int64 { return atomic.AddInt64(&s.TLSWorking, 1) }
func (s *ScanBatchStats) GetHTTPWorking() int64 { return atomic.LoadInt64(&s.HTTPWorking) }
func (s *ScanBatchStats) AddHTTPWorking() int64 { return atomic.AddInt64(&s.HTTPWorking, 1) }
func (s *ScanBatchStats) GetDown() int64 { return atomic.LoadInt64(&s.Down) }
func (s *ScanBatchStats) AddDown() int64 { return atomic.AddInt64(&s.Down, 1) }
func (s *ScanBatchStats) GetBatch() int { s.mu.RLock(); defer s.mu.RUnlock(); return s.Batch }
func (s *ScanBatchStats) SetBatch(v int) { s.mu.Lock(); defer s.mu.Unlock(); s.Batch = v }
func (s *ScanBatchStats) GetBatches() int { s.mu.RLock(); defer s.mu.RUnlock(); return s.Batches }
func (s *ScanBatchStats) SetBatches(v int) { s.mu.Lock(); defer s.mu.Unlock(); s.Batches = v }

// ScanOrchestrationConfig holds scan-level concurrency and throttle settings.
// Maps to upstream scanRequest fields used in normalize().
type ScanOrchestrationConfig struct {
	mu           sync.RWMutex
	Threads      int
	TimeoutMS    int
	Ports        []int
	HTTPPath     string
	MaxTargets   int
	MaxCIDRHosts int
	BatchSize    int
	RatePerSecond int
	JitterMS     int
}

// Getters & Setters for ScanOrchestrationConfig
func (c *ScanOrchestrationConfig) GetThreads() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.Threads }
func (c *ScanOrchestrationConfig) SetThreads(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.Threads = v }
func (c *ScanOrchestrationConfig) GetTimeoutMS() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.TimeoutMS }
func (c *ScanOrchestrationConfig) SetTimeoutMS(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.TimeoutMS = v }
func (c *ScanOrchestrationConfig) GetPorts() []int { c.mu.RLock(); defer c.mu.RUnlock(); return c.Ports }
func (c *ScanOrchestrationConfig) SetPorts(v []int) { c.mu.Lock(); defer c.mu.Unlock(); c.Ports = v }
func (c *ScanOrchestrationConfig) GetHTTPPath() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.HTTPPath }
func (c *ScanOrchestrationConfig) SetHTTPPath(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.HTTPPath = v }
func (c *ScanOrchestrationConfig) GetBatchSize() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.BatchSize }
func (c *ScanOrchestrationConfig) SetBatchSize(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.BatchSize = v }
func (c *ScanOrchestrationConfig) GetRatePerSecond() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.RatePerSecond }
func (c *ScanOrchestrationConfig) SetRatePerSecond(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.RatePerSecond = v }
func (c *ScanOrchestrationConfig) GetJitterMS() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.JitterMS }
func (c *ScanOrchestrationConfig) SetJitterMS(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.JitterMS = v }
func (c *ScanOrchestrationConfig) GetMaxTargets() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.MaxTargets }
func (c *ScanOrchestrationConfig) SetMaxTargets(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.MaxTargets = v }

// Builders for ScanOrchestrationConfig
func (c *ScanOrchestrationConfig) WithThreads(v int) *ScanOrchestrationConfig { c.SetThreads(v); return c }
func (c *ScanOrchestrationConfig) WithTimeoutMS(v int) *ScanOrchestrationConfig { c.SetTimeoutMS(v); return c }
func (c *ScanOrchestrationConfig) WithPorts(v []int) *ScanOrchestrationConfig { c.SetPorts(v); return c }
func (c *ScanOrchestrationConfig) WithHTTPPath(v string) *ScanOrchestrationConfig { c.SetHTTPPath(v); return c }
func (c *ScanOrchestrationConfig) WithBatchSize(v int) *ScanOrchestrationConfig { c.SetBatchSize(v); return c }
func (c *ScanOrchestrationConfig) WithRatePerSecond(v int) *ScanOrchestrationConfig { c.SetRatePerSecond(v); return c }

// NewDefaultScanOrchestrationConfig creates a config with upstream defaults.
// Maps to upstream scanRequest.normalize() defaults.
func NewDefaultScanOrchestrationConfig() *ScanOrchestrationConfig {
	return &ScanOrchestrationConfig{
		Threads:       max(4, runtime.NumCPU()*2),
		TimeoutMS:     2500,
		Ports:         []int{443},
		HTTPPath:      "/",
		BatchSize:     12000,
		RatePerSecond: 0,
		JitterMS:      0,
	}
}

// NormalizePorts filters invalid ports and ensures at least port 443 is present.
// Maps to upstream scanRequest.normalize() port normalization.
func NormalizePorts(ports []int) []int {
	var out []int
	for _, port := range ports {
		if port > 0 && port < 65536 {
			out = append(out, port)
		}
	}
	if len(out) == 0 {
		return []int{443}
	}
	return out
}

// NormalizeHTTPPath ensures the path starts with '/'.
// Maps to upstream scanRequest.normalize() httpPath normalization.
func NormalizeHTTPPath(path string) string {
	if strings.TrimSpace(path) == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		return "/" + path
	}
	return path
}

// ScanBatchOrchestrator runs a batch of probe jobs concurrently with context cancellation.
// Maps to upstream runScanBatch() function.
type ScanBatchOrchestrator[T any, R any] struct {
	Threads        int
	GlobalBackoffNS *atomic.Int64
	ResultBuffer   int
}

// NewScanBatchOrchestrator creates a new orchestrator with the given thread count.
func NewScanBatchOrchestrator[T any, R any](threads, resultBuffer int) *ScanBatchOrchestrator[T, R] {
	if threads <= 0 {
		threads = max(4, runtime.NumCPU()*2)
	}
	if resultBuffer <= 0 {
		resultBuffer = threads * 4
	}
	return &ScanBatchOrchestrator[T, R]{
		Threads:        threads,
		GlobalBackoffNS: &atomic.Int64{},
		ResultBuffer:   resultBuffer,
	}
}

// Run submits all items to the concurrent worker pool and returns results via a channel.
// Maps to upstream runScanBatch().
func (o *ScanBatchOrchestrator[T, R]) Run(ctx context.Context, items []T, probeOne func(context.Context, T) R) <-chan R {
	results := make(chan R, o.ResultBuffer)
	jobs := make(chan T)
	var wg sync.WaitGroup
	threads := o.Threads
	if threads > len(items) {
		threads = len(items)
	}
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				if ctx.Err() != nil {
					return
				}
				if backoff := o.GlobalBackoffNS.Load(); backoff > 0 {
					select {
					case <-ctx.Done():
						return
					case <-time.After(time.Duration(backoff)):
					}
				}
				res := probeOne(ctx, item)
				select {
				case <-ctx.Done():
					return
				case results <- res:
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, item := range items {
			select {
			case <-ctx.Done():
				return
			case jobs <- item:
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()
	return results
}

// SetBackoffNS sets the global backoff delay in nanoseconds.
func (o *ScanBatchOrchestrator[T, R]) SetBackoffNS(ns int64) {
	o.GlobalBackoffNS.Store(ns)
}

// ResetBackoff clears the global backoff delay.
func (o *ScanBatchOrchestrator[T, R]) ResetBackoff() {
	o.GlobalBackoffNS.Store(0)
}
