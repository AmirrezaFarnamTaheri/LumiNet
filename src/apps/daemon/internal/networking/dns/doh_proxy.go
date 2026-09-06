// Package dns provides a weighted-random RFC 8484 DNS-over-HTTPS query distributor.
//
// - Weighted random provider selection across multiple DoH backends
// - Sequential failover when primary provider returns an error
// - In-memory DNS response TTL caching keyed by query hash
// - RFC 8484 GET (dns= parameter) and POST (application/dns-message) support
package dns

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"sync"
	"time"
)

// DoHProvider describes a single DNS-over-HTTPS provider.
type DoHProvider struct {
	Name       string
	URL        string
	Weight     int
	IsDomestic bool
}

// DefaultDoHProviders is the canonical provider list .js.
var DefaultDoHProviders = []DoHProvider{
	{Name: "Cloudflare", URL: "https://cloudflare-dns.com/dns-query", Weight: 20},
	{Name: "Google", URL: "https://dns.google/dns-query", Weight: 15},
	{Name: "Quad9", URL: "https://dns.quad9.net/dns-query", Weight: 15},
	{Name: "OpenDNS", URL: "https://doh.opendns.com/dns-query", Weight: 10},
	{Name: "AdGuard", URL: "https://dns.adguard.com/dns-query", Weight: 10},
	{Name: "ControlD", URL: "https://freedns.controld.com/p2", Weight: 10},
	{Name: "Mullvad", URL: "https://adblock.dns.mullvad.net/dns-query", Weight: 10},
	{Name: "NextDNS", URL: "https://dns.nextdns.io/dns-query", Weight: 10},
}

// CacheTTL is the default DNS response cache TTL.
const CacheTTL = 5 * time.Minute

// DoHProxy is a weighted-random RFC 8484 DoH load balancer with failover.
type DoHProxy struct {
	providers []DoHProvider
	client    *http.Client
	cache     *boundedTTLCache[[]byte]
	rngMu     sync.Mutex
	rng       *rand.Rand
}

// NewDoHProxy creates a DoHProxy with the default provider list.
func NewDoHProxy() *DoHProxy {
	return NewDoHProxyWithProviders(DefaultDoHProviders)
}

// NewDoHProxyWithProviders creates a DoHProxy with a custom provider list.
func NewDoHProxyWithProviders(providers []DoHProvider) *DoHProxy {
	return &DoHProxy{
		providers: append([]DoHProvider(nil), providers...),
		client:    &http.Client{Timeout: 10 * time.Second},
		cache: newBoundedTTLCache[[]byte](defaultDNSCacheEntries, func(v []byte) []byte {
			return bytes.Clone(v)
		}),
		rng: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// SelectProvider performs weighted-random provider selection:
//
//	totalWeight = sum of all provider weights
//	random = rand() * totalWeight
//	iterate providers, subtract weight until random < 0
func (p *DoHProxy) SelectProvider() DoHProvider {
	if len(p.providers) == 0 {
		return DoHProvider{}
	}
	totalWeight := 0
	for _, prov := range p.providers {
		if prov.Weight > 0 {
			totalWeight += prov.Weight
		}
	}
	if totalWeight <= 0 {
		return p.providers[0]
	}

	p.rngMu.Lock()
	random := p.rng.Intn(totalWeight)
	p.rngMu.Unlock()
	for _, prov := range p.providers {
		if prov.Weight <= 0 {
			continue
		}
		if random < prov.Weight {
			return prov
		}
		random -= prov.Weight
	}
	// Fallback to first provider
	return p.providers[0]
}

// QueryGET performs a DoH GET query with the given base64url-encoded DNS message.
// Returns the raw DNS response binary.
func (p *DoHProxy) QueryGET(dnsParam string) ([]byte, error) {
	cacheKey := hex.EncodeToString(sha256Sum([]byte("GET:" + dnsParam)))

	if cached := p.getCache(cacheKey); cached != nil {
		return cached, nil
	}

	primary := p.SelectProvider()
	if primary.Name == "" || primary.URL == "" {
		return nil, errors.New("doh_proxy: no providers configured")
	}
	body, err := p.doGETQuery(primary, dnsParam)
	if err != nil {
		// Failover to remaining providers in order
		for _, prov := range p.providers {
			if prov.Name == primary.Name {
				continue
			}
			body, err = p.doGETQuery(prov, dnsParam)
			if err == nil {
				break
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("doh_proxy: all providers failed: %w", err)
	}

	p.setCache(cacheKey, body)
	return body, nil
}

// QueryPOST performs a DoH POST query with the given raw DNS message bytes.
// Returns the raw DNS response binary.
func (p *DoHProxy) QueryPOST(dnsMessage []byte) ([]byte, error) {
	cacheKey := hex.EncodeToString(sha256Sum(append([]byte("POST:"), dnsMessage...)))

	if cached := p.getCache(cacheKey); cached != nil {
		return cached, nil
	}

	primary := p.SelectProvider()
	if primary.Name == "" || primary.URL == "" {
		return nil, errors.New("doh_proxy: no providers configured")
	}
	body, err := p.doPOSTQuery(primary, dnsMessage)
	if err != nil {
		for _, prov := range p.providers {
			if prov.Name == primary.Name {
				continue
			}
			body, err = p.doPOSTQuery(prov, dnsMessage)
			if err == nil {
				break
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("doh_proxy: all providers failed: %w", err)
	}

	p.setCache(cacheKey, body)
	return body, nil
}

func (p *DoHProxy) doGETQuery(provider DoHProvider, dnsParam string) ([]byte, error) {
	url := provider.URL + "?dns=" + dnsParam
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", "LumiNet-DoH-Proxy/1.0")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("provider %s returned HTTP %d", provider.Name, resp.StatusCode)
	}

	return readBoundedDNSBody(resp.Body)
}

func (p *DoHProxy) doPOSTQuery(provider DoHProvider, dnsMessage []byte) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost, provider.URL, bytes.NewReader(dnsMessage))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", "LumiNet-DoH-Proxy/1.0")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("provider %s returned HTTP %d", provider.Name, resp.StatusCode)
	}

	return readBoundedDNSBody(resp.Body)
}

func (p *DoHProxy) getCache(key string) []byte {
	if cached, state := p.cache.Get(key, time.Now(), false); state == cacheFresh {
		return cached
	}
	return nil
}

func (p *DoHProxy) setCache(key string, body []byte) {
	expires := time.Now().Add(CacheTTL)
	p.cache.Set(key, body, expires, expires)
}

// PurgeExpiredCache removes expired DNS response cache entries.
func (p *DoHProxy) PurgeExpiredCache() int {
	return p.cache.EvictExpired(time.Now())
}

// ServeHTTP implements http.Handler for the DoH proxy endpoint.
// Supports both GET (?dns=...) and POST (application/dns-message) RFC 8484 requests.
func (p *DoHProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			http.Error(w, "missing 'dns' query parameter", http.StatusBadRequest)
			return
		}
		body, err := p.QueryGET(dnsParam)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(CacheTTL.Seconds())))
		_, _ = w.Write(body)

	case http.MethodPost:
		if ct := r.Header.Get("Content-Type"); ct != "application/dns-message" {
			http.Error(w, "Content-Type must be application/dns-message", http.StatusUnsupportedMediaType)
			return
		}
		dnsMessage, err := readBoundedDNSBody(r.Body)
		if err != nil {
			http.Error(w, "failed to read request body", http.StatusBadRequest)
			return
		}
		body, err := p.QueryPOST(dnsMessage)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(CacheTTL.Seconds())))
		_, _ = w.Write(body)

	case http.MethodOptions:
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept")
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ErrNoProviders is returned when the provider list is empty.
var ErrNoProviders = errors.New("doh_proxy: no providers configured")

// Base64URLDecodeDNSParam decodes a base64url-encoded DNS query parameter.
func Base64URLDecodeDNSParam(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func sha256Sum(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
