// Package relay provides HTTP relay proxy and bandwidth throttling utilities.
// Ported from XHTTPRelayECO-master/api/index.js — createGlobalLimiter / createThrottleTransform.
// Algorithm: token-bucket, burst = max(BPS, 256KiB), 5ms drain tick, per-chunk slice pump.
package relay

import (
	"io"
	"sync"
	"time"
)

const (
	// minBurst is the minimum burst capacity: 256 KiB.
	minBurst = 262144
	// drainInterval is the timer tick used to refill tokens and drain the queue.
	drainInterval = 5 * time.Millisecond
)

// acquireRequest is an enqueued request for N bytes from the limiter.
type acquireRequest struct {
	maxBytes int64
	ch       chan int64 // resolved with granted bytes
}

// GlobalLimiter is a token-bucket rate limiter shared across all streams.
// It mirrors the JS createGlobalLimiter() implementation from XHTTPRelayECO:
//   - burst cap = max(BPS, 262144)
//   - refill proportional to elapsed wall-clock time
//   - 5 ms periodic drain ticker
//   - FIFO acquire queue; each call blocks until at least 1 byte is granted
type GlobalLimiter struct {
	bps      int64
	burstCap int64

	mu         sync.Mutex
	tokens     float64
	lastRefill time.Time
	queue      []acquireRequest

	once    sync.Once
	stopCh  chan struct{}
	stopped bool
}

// NewGlobalLimiter creates a limiter at bytesPerSecond rate.
// Returns nil when bps <= 0 (no throttling).
func NewGlobalLimiter(bps int64) *GlobalLimiter {
	if bps <= 0 {
		return nil
	}
	burst := bps
	if burst < minBurst {
		burst = minBurst
	}
	l := &GlobalLimiter{
		bps:        bps,
		burstCap:   burst,
		tokens:     float64(burst),
		lastRefill: time.Now(),
		stopCh:     make(chan struct{}),
	}
	l.startDrainLoop()
	return l
}

// Stop shuts down the background drain goroutine and releases pending waiters.
// After Stop, the limiter becomes pass-through so callers cannot deadlock during
// shutdown while still preserving Acquire's positive-grant contract.
func (l *GlobalLimiter) Stop() {
	l.once.Do(func() {
		l.mu.Lock()
		l.stopped = true
		pending := l.queue
		l.queue = nil
		close(l.stopCh)
		l.mu.Unlock()

		for _, req := range pending {
			req.ch <- req.maxBytes
		}
	})
}

// Acquire blocks until at least 1 byte of the requested maxBytes can be granted.
// Returns the actual number of bytes granted (1 ≤ grant ≤ maxBytes).
func (l *GlobalLimiter) Acquire(maxBytes int64) int64 {
	if maxBytes < 1 {
		maxBytes = 1
	}
	ch := make(chan int64, 1)
	l.mu.Lock()
	if l.stopped {
		l.mu.Unlock()
		return maxBytes
	}
	l.queue = append(l.queue, acquireRequest{maxBytes: maxBytes, ch: ch})
	l.tryDrain()
	l.mu.Unlock()
	return <-ch
}

// refill adds tokens proportional to elapsed time since last refill.
// Must be called with l.mu held.
func (l *GlobalLimiter) refill() {
	now := time.Now()
	elapsed := now.Sub(l.lastRefill).Seconds()
	if elapsed <= 0 {
		return
	}
	l.tokens += elapsed * float64(l.bps)
	if l.tokens > float64(l.burstCap) {
		l.tokens = float64(l.burstCap)
	}
	l.lastRefill = now
}

// tryDrain resolves as many queued acquire requests as tokens allow.
// Must be called with l.mu held.
func (l *GlobalLimiter) tryDrain() {
	l.refill()
	for len(l.queue) > 0 && l.tokens >= 1 {
		req := l.queue[0]
		grant := int64(l.tokens)
		if grant > req.maxBytes {
			grant = req.maxBytes
		}
		if grant < 1 {
			break
		}
		l.tokens -= float64(grant)
		l.queue = l.queue[1:]
		req.ch <- grant
	}
}

// startDrainLoop starts a background goroutine that ticks every 5ms to drain the queue.
func (l *GlobalLimiter) startDrainLoop() {
	go func() {
		ticker := time.NewTicker(drainInterval)
		defer ticker.Stop()
		for {
			select {
			case <-l.stopCh:
				return
			case <-ticker.C:
				l.mu.Lock()
				if len(l.queue) > 0 {
					l.tryDrain()
				}
				l.mu.Unlock()
			}
		}
	}()
}

// ThrottledReader wraps an io.Reader and rate-limits reads through a GlobalLimiter.
// It mirrors createThrottleTransform(limiter) from XHTTPRelayECO:
//   - per-chunk acquire loop: while offset < len(chunk), acquire remaining, advance offset
type ThrottledReader struct {
	r       io.Reader
	limiter *GlobalLimiter
	buf     []byte
}

// NewThrottledReader wraps r with bandwidth throttling via limiter.
// If limiter is nil, r is returned as-is (no wrapping needed — caller should check).
func NewThrottledReader(r io.Reader, limiter *GlobalLimiter) io.Reader {
	if limiter == nil {
		return r
	}
	return &ThrottledReader{r: r, limiter: limiter, buf: make([]byte, 32*1024)}
}

// Read implements io.Reader with token-bucket throttling.
// It reads a chunk from the underlying reader, then slices it through the limiter,
// returning only the granted portion on each call.
func (t *ThrottledReader) Read(p []byte) (int, error) {
	// Read from underlying source
	size := len(p)
	if size > len(t.buf) {
		size = len(t.buf)
	}
	n, err := t.r.Read(t.buf[:size])
	if n == 0 {
		return 0, err
	}

	// Pump chunk through limiter, offset by offset (mirrors JS while loop)
	chunk := t.buf[:n]
	written := 0
	offset := int64(0)
	for offset < int64(n) {
		remaining := int64(n) - offset
		grant := t.limiter.Acquire(remaining)
		end := offset + grant
		copy(p[written:], chunk[offset:end])
		written += int(grant)
		offset = end
	}
	return written, err
}
