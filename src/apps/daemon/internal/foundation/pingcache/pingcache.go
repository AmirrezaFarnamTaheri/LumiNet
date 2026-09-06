// Package pingcache provides a concurrent, TTL-bounded ping result cache
// with deduplication of in-flight requests.
// and ZedSecure lib/services/native_ping_service.dart (NativePingService)
//
// Key micro-logic transplanted:
//   - _pingCache keyed by "host:port" with 1-hour TTL (MMKV → file-backed JSON)
//   - _pendingPings dedup using singleflight (Completer<int?> equivalent)
//   - TCP connect latency as the primary probe (mirrors Flutter's measureOutboundDelay)
//   - Continuous ping stream via goroutine + ticker
package pingcache

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"sync"
	"time"
)

const (
	cacheTTL        = time.Hour
	defaultTimeout  = 5 * time.Second
	continuousStop  = "stop"
)

// PingResult holds one latency probe result.
type PingResult struct {
	Success   bool      `json:"success"`
	LatencyMs int       `json:"latency_ms"` // -1 on failure
	Method    string    `json:"method"`
	Error     string    `json:"error,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// cacheEntry is the on-disk representation of a cached result.
type cacheEntry struct {
	LatencyMs int       `json:"latency_ms"`
	Timestamp time.Time `json:"timestamp"`
}

// PingCache is a concurrent, TTL-bounded latency cache with
// in-flight deduplication.
type PingCache struct {
	mu       sync.RWMutex
	cache    map[string]cacheEntry    // keyed "host:port"
	inflight map[string]*inflightPing // in-progress pings
	filePath string
}

type inflightPing struct {
	ch  chan struct{}
	val int
}

// New creates a PingCache, loading existing entries from filePath.
func New(filePath string) *PingCache {
	pc := &PingCache{
		cache:    make(map[string]cacheEntry),
		inflight: make(map[string]*inflightPing),
		filePath: filePath,
	}
	_ = pc.load()
	return pc
}

// GetDelay returns latency to host:port, using the cache if valid.
// Concurrent calls for the same host:port are deduplicated — only one TCP
// probe fires; others block and share the result. Mirrors ZedSecure's
// _pendingPings Completer pattern.
func (pc *PingCache) GetDelay(ctx context.Context, host string, port int, useCache bool) PingResult {
	key := net.JoinHostPort(host, itoa(port))

	if useCache {
		if r, ok := pc.getCached(key); ok {
			return r
		}
	}

	// Dedup in-flight
	pc.mu.Lock()
	if inf, ok := pc.inflight[key]; ok {
		pc.mu.Unlock()
		select {
		case <-inf.ch:
			return PingResult{
				Success:   inf.val >= 0,
				LatencyMs: inf.val,
				Method:    "tcp-dedup",
				Timestamp: time.Now(),
			}
		case <-ctx.Done():
			return pingError("context cancelled")
		}
	}
	inf := &inflightPing{ch: make(chan struct{})}
	pc.inflight[key] = inf
	pc.mu.Unlock()

	// Run TCP probe
	ms := probeTCP(ctx, host, port)

	pc.mu.Lock()
	inf.val = ms
	close(inf.ch)
	delete(pc.inflight, key)
	if ms >= 0 {
		pc.cache[key] = cacheEntry{LatencyMs: ms, Timestamp: time.Now()}
	}
	pc.mu.Unlock()

	_ = pc.save()

	return PingResult{
		Success:   ms >= 0,
		LatencyMs: ms,
		Method:    "tcp",
		Timestamp: time.Now(),
	}
}

// ContinuousPing returns a channel that receives PingResult every interval
// until the returned stop func is called.
func (pc *PingCache) ContinuousPing(host string, port int, interval time.Duration) (<-chan PingResult, func()) {
	ch := make(chan PingResult, 4)
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		defer close(ch)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r := pc.GetDelay(ctx, host, port, false)
				select {
				case ch <- r:
				default:
				}
			}
		}
	}()

	return ch, cancel
}

// PingMultiple probes all (host, port) pairs concurrently and returns results
// keyed by "host:port". .pingMultipleHosts().
func (pc *PingCache) PingMultiple(ctx context.Context, hosts []HostPort, timeout time.Duration) map[string]PingResult {
	type kv struct {
		key string
		r   PingResult
	}
	out := make(chan kv, len(hosts))
	for _, h := range hosts {
		go func(h HostPort) {
			subCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			r := pc.GetDelay(subCtx, h.Host, h.Port, true)
			out <- kv{key: net.JoinHostPort(h.Host, itoa(h.Port)), r: r}
		}(h)
	}
	results := make(map[string]PingResult, len(hosts))
	for range hosts {
		kv := <-out
		results[kv.key] = kv.r
	}
	return results
}

// TestConnectivity probes the four fixed well-known endpoints.
func (pc *PingCache) TestConnectivity(ctx context.Context) map[string]PingResult {
	return pc.PingMultiple(ctx, []HostPort{
		{"google.com", 80},
		{"cloudflare.com", 80},
		{"1.1.1.1", 53},
		{"8.8.8.8", 53},
	}, 3*time.Second)
}

// ClearCache removes the entry for host:port, or all entries if both are zero.
func (pc *PingCache) ClearCache(host string, port int) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if host == "" {
		pc.cache = make(map[string]cacheEntry)
	} else {
		delete(pc.cache, net.JoinHostPort(host, itoa(port)))
	}
	_ = pc.save()
}

// HostPort is a host+port pair for PingMultiple.
type HostPort struct {
	Host string
	Port int
}

// getCached returns a PingResult if the cache entry is still within TTL.
func (pc *PingCache) getCached(key string) (PingResult, bool) {
	pc.mu.RLock()
	e, ok := pc.cache[key]
	pc.mu.RUnlock()
	if !ok {
		return PingResult{}, false
	}
	if time.Since(e.Timestamp) > cacheTTL {
		return PingResult{}, false
	}
	return PingResult{
		Success:   e.LatencyMs >= 0,
		LatencyMs: e.LatencyMs,
		Method:    "cache",
		Timestamp: e.Timestamp,
	}, true
}

// probeTCP measures TCP connect latency in milliseconds. Returns -1 on error.
func probeTCP(ctx context.Context, host string, port int) int {
	addr := net.JoinHostPort(host, itoa(port))
	d := net.Dialer{}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return -1
	}
	_ = conn.Close()
	return int(time.Since(start).Milliseconds())
}

func (pc *PingCache) save() error {
	pc.mu.RLock()
	data, err := json.Marshal(pc.cache)
	pc.mu.RUnlock()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dirOf(pc.filePath), 0o750); err != nil {
		return err
	}
	return os.WriteFile(pc.filePath, data, 0o640)
}

func (pc *PingCache) load() error {
	data, err := os.ReadFile(pc.filePath)
	if err != nil {
		return err
	}
	pc.mu.Lock()
	defer pc.mu.Unlock()
	return json.Unmarshal(data, &pc.cache)
}

func pingError(msg string) PingResult {
	return PingResult{Success: false, LatencyMs: -1, Method: "error", Error: msg, Timestamp: time.Now()}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := [20]byte{}
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}

func dirOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' || p[i] == '\\' {
			return p[:i]
		}
	}
	return "."
}
