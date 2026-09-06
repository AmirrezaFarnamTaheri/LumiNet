package dns

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/maybeknott/luminet/internal/networking/geoip"
	"golang.org/x/sync/singleflight"
)

type FailoverDOHResolver struct {
	providers       []DoHProvider
	client          *http.Client
	cache           *boundedTTLCache[[]string]
	cacheMu         sync.RWMutex
	ttl             time.Duration
	sfGroup         singleflight.Group
	geoIP           *geoip.Service
	bypassProviders map[string]bool
	lookupSlots     chan struct{}
}

const (
	maxConcurrentDOHLookups = 32
	sharedDOHLookupTimeout  = 5 * time.Second
)

var errDOHLookupCapacity = errors.New("doh: lookup capacity exhausted")

func NewFailoverDOHResolver(ttl time.Duration) *FailoverDOHResolver {
	if ttl == 0 {
		ttl = 300 * time.Second
	}
	geo, _ := geoip.NewService("") // Fallback online lookup
	return &FailoverDOHResolver{
		providers: []DoHProvider{
			{"Cloudflare", "https://cloudflare-dns.com/dns-query", 20, false},
			{"Google", "https://dns.google/dns-query", 15, false},
			{"Quad9", "https://dns.quad9.net/dns-query", 15, false},
			{"OpenDNS", "https://doh.opendns.com/dns-query", 10, false},
			{"AdGuard", "https://dns.adguard.com/dns-query", 10, false},
			{"ControlD", "https://freedns.controld.com/p2", 10, false},
			{"Mullvad", "https://adblock.dns.mullvad.net/dns-query", 10, false},
			{"NextDNS", "https://dns.nextdns.io/dns-query", 10, false},
			{"DNSPod", "https://doh.pub/dns-query", 20, true},
			{"Alidns", "https://dns.alidns.com/dns-query", 20, true},
		},
		client: &http.Client{Timeout: 5 * time.Second},
		cache: newBoundedTTLCache[[]string](defaultDNSCacheEntries, func(v []string) []string {
			return append([]string(nil), v...)
		}),
		ttl:             ttl,
		geoIP:           geo,
		bypassProviders: make(map[string]bool),
		lookupSlots:     make(chan struct{}, maxConcurrentDOHLookups),
	}
}

// SelectProvider selects a provider using weighted random choice. An empty
// registry is represented by the zero DoHProvider rather than panicking; callers
// that require a provider treat the empty name/URL as unavailable.
func (r *FailoverDOHResolver) SelectProvider() DoHProvider {
	providers := r.providerSnapshot()
	return selectWeightedProvider(providers)
}

func selectWeightedProvider(providers []DoHProvider) DoHProvider {
	if len(providers) == 0 {
		return DoHProvider{}
	}
	totalWeight := 0
	for _, p := range providers {
		if p.Weight > 0 {
			totalWeight += p.Weight
		}
	}
	if totalWeight <= 0 {
		return providers[0]
	}
	choice := rand.Intn(totalWeight)
	cumulative := 0
	for _, p := range providers {
		if p.Weight <= 0 {
			continue
		}
		cumulative += p.Weight
		if choice < cumulative {
			return p
		}
	}
	return providers[0]
}

func (r *FailoverDOHResolver) providerSnapshot() []DoHProvider {
	r.cacheMu.RLock()
	defer r.cacheMu.RUnlock()
	return append([]DoHProvider(nil), r.providers...)
}

// ResolveDNS sends a raw DNS wire-format message to the given DoH provider.
func (r *FailoverDOHResolver) ResolveDNS(ctx context.Context, provider DoHProvider, dnsMessage []byte) ([]byte, error) {
	if strings.TrimSpace(provider.URL) == "" {
		return nil, fmt.Errorf("doh: provider URL is required")
	}
	req, err := http.NewRequestWithContext(ctx, "POST", provider.URL, bytes.NewReader(dnsMessage))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	r.cacheMu.RLock()
	client := r.client
	r.cacheMu.RUnlock()
	if client == nil {
		return nil, fmt.Errorf("doh: HTTP client is unavailable")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("doh: provider %s returned HTTP %d", provider.Name, resp.StatusCode)
	}
	return readBoundedDNSBody(resp.Body)
}

// buildDNSQuery constructs a minimal DNS wire-format A-record query for host.
func buildDNSQuery(host string) []byte {
	var buf bytes.Buffer
	// Transaction ID
	buf.Write([]byte{0x00, 0x01})
	// Flags: QR=0 (query), Opcode=0, RD=1
	buf.Write([]byte{0x01, 0x00})
	// QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
	buf.Write([]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	// Encode hostname labels
	for _, label := range strings.Split(host, ".") {
		if label == "" {
			continue
		}
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0) // root label terminator
	// QTYPE=A (1), QCLASS=IN (1)
	buf.Write([]byte{0x00, 0x01, 0x00, 0x01})
	return buf.Bytes()
}

func parseDNSName(msg []byte, start int) (string, int, error) {
	if start < 0 || start >= len(msg) {
		return "", 0, fmt.Errorf("doh: DNS name offset out of bounds")
	}
	labels := make([]string, 0, 4)
	offset := start
	next := -1
	visited := make(map[int]struct{})
	for steps := 0; steps < 128; steps++ {
		if offset >= len(msg) {
			return "", 0, fmt.Errorf("doh: truncated DNS name")
		}
		length := msg[offset]
		if length&0xc0 == 0xc0 {
			if offset+1 >= len(msg) {
				return "", 0, fmt.Errorf("doh: truncated DNS compression pointer")
			}
			ptr := int(length&0x3f)<<8 | int(msg[offset+1])
			if ptr >= len(msg) {
				return "", 0, fmt.Errorf("doh: DNS compression pointer out of bounds")
			}
			if _, ok := visited[ptr]; ok {
				return "", 0, fmt.Errorf("doh: DNS compression pointer loop")
			}
			visited[ptr] = struct{}{}
			if next < 0 {
				next = offset + 2
			}
			offset = ptr
			continue
		}
		if length&0xc0 != 0 {
			return "", 0, fmt.Errorf("doh: unsupported DNS label encoding")
		}
		offset++
		if length == 0 {
			if next < 0 {
				next = offset
			}
			return strings.Join(labels, "."), next, nil
		}
		if length > 63 || offset+int(length) > len(msg) {
			return "", 0, fmt.Errorf("doh: invalid DNS label length")
		}
		labels = append(labels, string(msg[offset:offset+int(length)]))
		offset += int(length)
	}
	return "", 0, fmt.Errorf("doh: DNS name exceeds pointer traversal bound")
}

func parseDNSQuestion(msg []byte) (string, uint16, uint16, error) {
	if len(msg) < 12 || binary.BigEndian.Uint16(msg[4:6]) == 0 {
		return "", 0, 0, fmt.Errorf("doh: DNS message has no question")
	}
	name, next, err := parseDNSName(msg, 12)
	if err != nil {
		return "", 0, 0, err
	}
	if next+4 > len(msg) {
		return "", 0, 0, fmt.Errorf("doh: truncated DNS question")
	}
	return name, binary.BigEndian.Uint16(msg[next : next+2]), binary.BigEndian.Uint16(msg[next+2 : next+4]), nil
}

func validateDNSResponseIdentity(query, response []byte) error {
	if len(query) < 12 || len(response) < 12 {
		return fmt.Errorf("doh: DNS query/response header is truncated")
	}
	if !bytes.Equal(query[:2], response[:2]) {
		return fmt.Errorf("doh: response transaction ID does not match query")
	}
	qName, qType, qClass, err := parseDNSQuestion(query)
	if err != nil {
		return fmt.Errorf("doh: invalid query question: %w", err)
	}
	rName, rType, rClass, err := parseDNSQuestion(response)
	if err != nil {
		return fmt.Errorf("doh: invalid response question: %w", err)
	}
	if !strings.EqualFold(qName, rName) || qType != rType || qClass != rClass {
		return fmt.Errorf("doh: response question does not match query")
	}
	return nil
}

// parseARecords extracts IPv4 addresses from a DNS wire-format response.
func parseARecords(resp []byte) []string {
	if len(resp) < 12 {
		return nil
	}
	qdCount := int(binary.BigEndian.Uint16(resp[4:6]))
	anCount := int(binary.BigEndian.Uint16(resp[6:8]))
	offset := 12
	// Skip questions section
	for i := 0; i < qdCount; i++ {
		for offset < len(resp) {
			if resp[offset] == 0 {
				offset++
				break
			}
			if resp[offset]&0xC0 == 0xC0 {
				offset += 2
				break
			}
			offset += int(resp[offset]) + 1
		}
		offset += 4 // skip QTYPE + QCLASS
	}
	var ips []string
	for i := 0; i < anCount && offset < len(resp); i++ {
		// Skip name (pointer or labels)
		if offset < len(resp) && resp[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(resp) {
				if resp[offset] == 0 {
					offset++
					break
				}
				offset += int(resp[offset]) + 1
			}
		}
		if offset+10 > len(resp) {
			break
		}
		rtype := binary.BigEndian.Uint16(resp[offset : offset+2])
		rdlength := int(binary.BigEndian.Uint16(resp[offset+8 : offset+10]))
		offset += 10
		if rtype == 1 && rdlength == 4 && offset+4 <= len(resp) {
			ip := fmt.Sprintf("%d.%d.%d.%d",
				resp[offset], resp[offset+1], resp[offset+2], resp[offset+3])
			ips = append(ips, ip)
		}
		offset += rdlength
	}
	return ips
}

// LookupHost resolves host to IPv4 addresses, with in-memory caching,
// singleflight DNS query racing, and GeoIP poisoned response filtering.
func (r *FailoverDOHResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	if ips, state := r.cache.Get(host, time.Now(), false); state == cacheFresh {
		return ips, nil
	}

	// Use singleflight racing to avoid duplicate queries
	resChan := r.sfGroup.DoChan(host, func() (interface{}, error) {
		return r.lookupShared(ctx, host)
	})

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-resChan:
		if res.Err != nil {
			return nil, res.Err
		}
		ips := res.Val.([]string)
		return ips, nil
	}
}

func (r *FailoverDOHResolver) lookupShared(parent context.Context, host string) ([]string, error) {
	sharedCtx, cancel := context.WithTimeout(context.WithoutCancel(parent), sharedDOHLookupTimeout)
	defer cancel()

	if r.lookupSlots == nil {
		return nil, fmt.Errorf("doh: lookup admission is unavailable")
	}
	select {
	case r.lookupSlots <- struct{}{}:
		defer func() { <-r.lookupSlots }()
	default:
		return nil, errDOHLookupCapacity
	}

	return r.lookupRace(sharedCtx, host)
}

func (r *FailoverDOHResolver) lookupRace(ctx context.Context, host string) ([]string, error) {
	providers := r.providerSnapshot()
	if len(providers) == 0 {
		return nil, fmt.Errorf("doh: no providers configured")
	}
	query := buildDNSQuery(host)

	type dnsRaceResult struct {
		ips      []string
		provider DoHProvider
		err      error
	}

	resultsCh := make(chan dnsRaceResult, 2)
	ctxRace, cancelRace := context.WithCancel(ctx)
	defer cancelRace()

	// Select a domestic and a foreign provider
	var domesticProvider DoHProvider
	var foreignProvider DoHProvider
	for _, p := range providers {
		if p.IsDomestic && domesticProvider.Name == "" {
			domesticProvider = p
		} else if !p.IsDomestic && foreignProvider.Name == "" {
			foreignProvider = p
		}
	}
	if domesticProvider.Name == "" {
		domesticProvider = providers[rand.Intn(len(providers))]
	}
	if foreignProvider.Name == "" {
		foreignProvider = providers[rand.Intn(len(providers))]
	}

	// Race them concurrently
	go func() {
		raw, err := r.ResolveDNS(ctxRace, domesticProvider, query)
		if err != nil {
			resultsCh <- dnsRaceResult{err: err}
			return
		}
		if err := validateDNSResponseIdentity(query, raw); err != nil {
			resultsCh <- dnsRaceResult{err: err}
			return
		}
		ips := parseARecords(raw)
		resultsCh <- dnsRaceResult{ips: ips, provider: domesticProvider}
	}()

	go func() {
		raw, err := r.ResolveDNS(ctxRace, foreignProvider, query)
		if err != nil {
			resultsCh <- dnsRaceResult{err: err}
			return
		}
		if err := validateDNSResponseIdentity(query, raw); err != nil {
			resultsCh <- dnsRaceResult{err: err}
			return
		}
		ips := parseARecords(raw)
		resultsCh <- dnsRaceResult{ips: ips, provider: foreignProvider}
	}()

	var lastErr error
	for i := 0; i < 2; i++ {
		select {
		case <-ctxRace.Done():
			return nil, ctxRace.Err()
		case res := <-resultsCh:
			if res.err != nil {
				lastErr = res.err
				continue
			}
			if len(res.ips) > 0 {
				// GeoIP poisoned response filtering
				if res.provider.IsDomestic && r.geoIP != nil {
					// Check if resolved IP is domestic (CN)
					isPoisoned := false
					for _, ip := range res.ips {
						code, err := r.checkIPCountry(ctx, ip)
						if err == nil && code != "" && code != "CN" {
							// IP outside China resolved by Chinese DNS resolver -> discard/poisoned!
							isPoisoned = true
							break
						}
					}
					if isPoisoned {
						// Discard domestic response and continue waiting for foreign response
						lastErr = fmt.Errorf("poisoned domestic response discarded")
						continue
					}
				}
				// We got a valid (non-poisoned) result! Cache it and return.
				r.cacheMu.RLock()
				ttl := r.ttl
				r.cacheMu.RUnlock()
				expires := time.Now().Add(ttl)
				r.cache.Set(host, res.ips, expires, expires)
				return res.ips, nil
			}
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("doh: all race queries failed")
}

func (r *FailoverDOHResolver) checkIPCountry(ctx context.Context, ip string) (string, error) {
	r.cacheMu.RLock()
	geo := r.geoIP
	r.cacheMu.RUnlock()
	if geo == nil {
		return "", fmt.Errorf("doh: GeoIP service is unavailable")
	}
	_, code, _, _, _, _, err := geo.Lookup(ctx, ip)
	return code, err
}

// ProcessFilter represents rule-based matching based on the originating process name.
// Typical in Clash for skipping DNS caching/proxying for specific local processes.
type ProcessFilter struct {
	DirectProcesses []string
	ProxyProcesses  []string
	mu              sync.RWMutex
}

func NewProcessFilter() *ProcessFilter {
	return &ProcessFilter{
		DirectProcesses: []string{"curl", "wget", "git", "ssh"},
		ProxyProcesses:  []string{"chrome", "firefox", "edge", "telegram"},
	}
}

// MatchProcessName checks if the given process name matches the filter lists.
func (pf *ProcessFilter) MatchProcessName(processName string) string {
	pf.mu.RLock()
	defer pf.mu.RUnlock()

	proc := strings.ToLower(processName)

	for _, p := range pf.DirectProcesses {
		if strings.Contains(proc, p) {
			return "direct"
		}
	}

	for _, p := range pf.ProxyProcesses {
		if strings.Contains(proc, p) {
			return "proxy"
		}
	}

	return ""
}

// 7. GetTTL returns cache TTL.
func (r *FailoverDOHResolver) GetTTL() time.Duration {
	r.cacheMu.RLock()
	defer r.cacheMu.RUnlock()
	return r.ttl
}

// 8. SetTTL overrides cache TTL.
func (r *FailoverDOHResolver) SetTTL(d time.Duration) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	r.ttl = d
}

// 9. AddProvider registers new DoH provider.
func (r *FailoverDOHResolver) AddProvider(p DoHProvider) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	r.providers = append(r.providers, p)
}

// 12. ClearProviders resets providers registry.
func (r *FailoverDOHResolver) ClearProviders() {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	r.providers = make([]DoHProvider, 0)
}

// 14. ClearCache flushes active DNS cache.
func (r *FailoverDOHResolver) ClearCache() {
	r.cache.Clear()
}

// 15. GetCacheSize returns size of active cache.
func (r *FailoverDOHResolver) GetCacheSize() int {
	return r.cache.Len()
}

// 19. SetCachedIPs updates cached IPs.
func (r *FailoverDOHResolver) SetCachedIPs(host string, ips []string) {
	r.cacheMu.RLock()
	ttl := r.ttl
	r.cacheMu.RUnlock()
	expires := time.Now().Add(ttl)
	r.cache.Set(host, ips, expires, expires)
}

// 23. GetHTTPClientTimeout returns HTTP timeout duration.
func (r *FailoverDOHResolver) GetHTTPClientTimeout() time.Duration {
	r.cacheMu.RLock()
	defer r.cacheMu.RUnlock()
	if r.client == nil {
		return 0
	}
	return r.client.Timeout
}

// 24. SetHTTPClientTimeout overrides HTTP timeout duration by replacing the
// client snapshot instead of mutating a client concurrently used by ResolveDNS.
func (r *FailoverDOHResolver) SetHTTPClientTimeout(t time.Duration) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	client := &http.Client{}
	if r.client != nil {
		*client = *r.client
	}
	client.Timeout = t
	r.client = client
}

// 47. SetClientTransport configures HTTP client transport.
func (r *FailoverDOHResolver) SetClientTransport(transport *http.Transport) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	client := &http.Client{}
	if r.client != nil {
		*client = *r.client
	}
	client.Transport = transport
	r.client = client
}

// 48. GetClientTransport returns HTTP client transport.
func (r *FailoverDOHResolver) GetClientTransport() *http.Transport {
	r.cacheMu.RLock()
	defer r.cacheMu.RUnlock()
	if r.client == nil {
		return nil
	}
	if t, ok := r.client.Transport.(*http.Transport); ok {
		return t
	}
	return nil
}
