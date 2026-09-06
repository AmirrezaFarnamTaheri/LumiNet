// Package dns includes bounded DNS-over-HTTPS response caching with POST->GET
// rewriting, stale-if-error resilience, and in-flight request coalescing.
//
// POST body (raw DNS wire) -> base64url encode -> ?dns=<encoded> GET request.
// This preserves the original CDN/proxy cacheability benefit while keeping the
// daemon's own cache bounded and failure-aware.
package dns

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultDoHCacheTTL = 5 * time.Minute
	defaultDoHStaleTTL = 5 * time.Minute
)

// DoHCachePolicy controls local response ownership. StaleTTL is an additional
// window after TTL during which a previously successful DNS answer may be
// served only when refresh fails.
type DoHCachePolicy struct {
	TTL        time.Duration
	StaleTTL   time.Duration
	MaxEntries int
	Timeout    time.Duration
}

// DoHCache caches successful DNS-over-HTTPS responses. Upstream HTTP errors are
// never inserted into the cache.
type DoHCache struct {
	cache     *boundedTTLCache[[]byte]
	ttl       time.Duration
	staleTTL  time.Duration
	upstream  string
	client    *http.Client
	now       func() time.Time
	flightMu  sync.Mutex
	inflight  map[string]*dohCacheFlight
	hits      atomic.Uint64
	misses    atomic.Uint64
	staleHits atomic.Uint64
	coalesced atomic.Uint64
	failures  atomic.Uint64
}

type dohCacheFlight struct {
	done chan struct{}
	data []byte
	err  error
}

// NewDoHCache creates a bounded DoH cache with a conservative stale-if-error
// window. Use NewDoHCacheWithPolicy for explicit bounds.
func NewDoHCache(upstream string, ttl time.Duration) *DoHCache {
	return NewDoHCacheWithPolicy(upstream, DoHCachePolicy{TTL: ttl})
}

func NewDoHCacheWithPolicy(upstream string, policy DoHCachePolicy) *DoHCache {
	if policy.TTL <= 0 {
		policy.TTL = defaultDoHCacheTTL
	}
	if policy.StaleTTL < 0 {
		policy.StaleTTL = 0
	} else if policy.StaleTTL == 0 {
		policy.StaleTTL = defaultDoHStaleTTL
	}
	if policy.MaxEntries <= 0 {
		policy.MaxEntries = defaultDNSCacheEntries
	}
	if policy.Timeout <= 0 {
		policy.Timeout = 10 * time.Second
	}
	return &DoHCache{
		cache: newBoundedTTLCache[[]byte](policy.MaxEntries, func(v []byte) []byte {
			return bytes.Clone(v)
		}),
		ttl:      policy.TTL,
		staleTTL: policy.StaleTTL,
		upstream: strings.TrimSpace(upstream),
		client:   &http.Client{Timeout: policy.Timeout},
		now:      time.Now,
		inflight: make(map[string]*dohCacheFlight),
	}
}

// ServeHTTP handles RFC 8484 GET/POST requests. POST requests are converted to
// canonical GET cache keys before forwarding.
func (c *DoHCache) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		body, err := readBoundedDNSBody(r.Body)
		if err != nil || len(body) == 0 {
			http.Error(w, "Invalid DNS request body", http.StatusBadRequest)
			return
		}
		c.serveKey(w, r, base64RawURLEncode(body))
	case http.MethodGet:
		dnsParam := r.URL.Query().Get("dns")
		if err := validateDoHCacheKey(dnsParam); err != nil {
			http.Error(w, "Invalid dns parameter", http.StatusBadRequest)
			return
		}
		c.serveKey(w, r, dnsParam)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (c *DoHCache) serveKey(w http.ResponseWriter, r *http.Request, cacheKey string) {
	now := c.now()
	cached, state := c.cache.Get(cacheKey, now, true)
	if state == cacheFresh {
		c.hits.Add(1)
		writeDoHCacheResponse(w, cached, "HIT")
		return
	}
	c.misses.Add(1)
	var stale []byte
	if state == cacheStale {
		stale = cached
	}

	data, err := c.fetchCoalesced(r.Context(), cacheKey)
	if err != nil {
		c.failures.Add(1)
		if len(stale) > 0 {
			c.staleHits.Add(1)
			writeDoHCacheResponse(w, stale, "STALE")
			return
		}
		http.Error(w, "Upstream DoH unavailable", http.StatusBadGateway)
		return
	}
	writeDoHCacheResponse(w, data, "MISS")
}

func (c *DoHCache) fetchCoalesced(ctx context.Context, cacheKey string) ([]byte, error) {
	// A racing request may have filled the cache after the caller's first lookup.
	if data, state := c.cache.Get(cacheKey, c.now(), false); state == cacheFresh {
		c.hits.Add(1)
		return data, nil
	}

	c.flightMu.Lock()
	if existing, ok := c.inflight[cacheKey]; ok {
		c.coalesced.Add(1)
		c.flightMu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-existing.done:
			return bytes.Clone(existing.data), existing.err
		}
	}
	flight := &dohCacheFlight{done: make(chan struct{})}
	c.inflight[cacheKey] = flight
	c.flightMu.Unlock()

	data, err := c.fetchUpstream(ctx, cacheKey)
	flight.data = bytes.Clone(data)
	flight.err = err
	close(flight.done)
	c.flightMu.Lock()
	delete(c.inflight, cacheKey)
	c.flightMu.Unlock()
	return data, err
}

func (c *DoHCache) fetchUpstream(ctx context.Context, cacheKey string) ([]byte, error) {
	getURL, err := buildDoHUpstreamURL(c.upstream, cacheKey)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, getURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream DoH HTTP %d", resp.StatusCode)
	}
	data, err := readBoundedDNSBody(resp.Body)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, errors.New("upstream DoH returned empty DNS message")
	}

	now := c.now()
	expires := now.Add(c.ttl)
	c.cache.Set(cacheKey, data, expires, expires.Add(c.staleTTL))
	return data, nil
}

func buildDoHUpstreamURL(upstream, cacheKey string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(upstream))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", errors.New("invalid DoH upstream URL")
	}
	q := u.Query()
	q.Set("dns", cacheKey)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func validateDoHCacheKey(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("empty dns parameter")
	}
	// Avoid allocating on an arbitrarily large query parameter before decode.
	maxEncoded := base64.RawURLEncoding.EncodedLen(int(maxDNSHTTPBodyBytes))
	if len(value) > maxEncoded {
		return errors.New("dns parameter exceeds wire-message bound")
	}
	decoded, err := base64RawURLDecode(value)
	if err != nil || len(decoded) == 0 || int64(len(decoded)) > maxDNSHTTPBodyBytes {
		return errors.New("invalid dns parameter")
	}
	return nil
}

func writeDoHCacheResponse(w http.ResponseWriter, data []byte, cacheState string) {
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("X-Cache", cacheState)
	if cacheState == "STALE" {
		w.Header().Set("Warning", `110 - "Response is stale"`)
	}
	_, _ = w.Write(data)
}

// EvictExpired removes entries whose fresh and stale lifetimes have both ended.
func (c *DoHCache) EvictExpired() int {
	return c.cache.EvictExpired(c.now())
}

// StartEviction runs cancellable maintenance. The caller owns ctx and therefore
// owns the goroutine lifetime; interval <= 0 is ignored.
func (c *DoHCache) StartEviction(ctx context.Context, interval time.Duration) {
	if ctx == nil || interval <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.EvictExpired()
			}
		}
	}()
}

// CacheStats reports bounded local-cache and refresh behavior.
type CacheStats struct {
	Entries   int
	Hits      uint64
	Misses    uint64
	StaleHits uint64
	Coalesced uint64
	Failures  uint64
	Evictions uint64
}

func (c *DoHCache) Stats() CacheStats {
	return CacheStats{
		Entries:   c.cache.Len(),
		Hits:      c.hits.Load(),
		Misses:    c.misses.Load(),
		StaleHits: c.staleHits.Load(),
		Coalesced: c.coalesced.Load(),
		Failures:  c.failures.Load(),
		Evictions: c.cache.Evictions(),
	}
}

// base64RawURLEncode encodes bytes to base64url without padding (RFC 4648 section 5).
func base64RawURLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// base64RawURLDecode accepts canonical unpadded base64url plus legacy padded
// inputs so existing clients keep working while new POST rewrites are canonical.
func base64RawURLDecode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if decoded, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return decoded, nil
	}
	return base64.URLEncoding.DecodeString(s)
}
