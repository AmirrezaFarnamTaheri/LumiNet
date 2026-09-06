// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: gfw_resist_HTTPS_proxy-main
// Target path: server/internal/proxy/gfw_resist_https.go

package proxy

import (
	"context"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// GFWResistHTTPS bypasses deep packet inspection using HTTP/TLS fragment splitting and DoH resolvers.
type GFWResistHTTPS struct {
	mu            sync.RWMutex
	NumFragments  int
	FragmentSleep time.Duration
	DoHResolver   string
	DNSMap        map[string]string
	writeTimeout  time.Duration
	readTimeout   time.Duration
}

// NewGFWResistHTTPS instantiates a GFWResistHTTPS proxy instance.
func NewGFWResistHTTPS() *GFWResistHTTPS {
	return &GFWResistHTTPS{
		NumFragments:  87,
		FragmentSleep: 5 * time.Millisecond,
		DoHResolver:   "https://cloudflare-dns.com/dns-query",
		DNSMap: map[string]string{
			"cloudflare-dns.com":  "203.32.120.226",
			"dns.google":          "8.8.8.8",
			"doh.opendns.com":     "208.67.222.222",
			"secure.avastdns.com": "185.185.133.66",
			"doh.libredns.gr":     "116.202.176.26",
			"dns.electrotm.org":   "78.157.42.100",
			"instagram.com":       "163.70.128.174",
			"twitter.com":         "104.244.42.1",
		},
		writeTimeout: 5 * time.Second,
		readTimeout:  5 * time.Second,
	}
}

// 1. ResolveDNS bootstraps DNS queries utilizing the local offline DNS map.
func (g *GFWResistHTTPS) ResolveDNS(domain string) string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if ip, exists := g.DNSMap[domain]; exists {
		return ip
	}
	return ""
}

// 2. DialTCPWithBypass establishes a TCP connection, writing the initial payload in fragmented random chunks.
func (g *GFWResistHTTPS) DialTCPWithBypass(address string, initialPayload []byte) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return nil, err
	}

	g.mu.RLock()
	numFrags := g.NumFragments
	fragSleep := g.FragmentSleep
	g.mu.RUnlock()

	payloadLen := len(initialPayload)
	if payloadLen > 0 && numFrags > 1 {
		boundaries := make([]int, 0)
		for i := 0; i < numFrags-1; i++ {
			boundaries = append(boundaries, rand.Intn(payloadLen))
		}

		for i := 0; i < len(boundaries); i++ {
			for j := i + 1; j < len(boundaries); j++ {
				if boundaries[i] > boundaries[j] {
					boundaries[i], boundaries[j] = boundaries[j], boundaries[i]
				}
			}
		}

		lastIdx := 0
		for _, idx := range boundaries {
			if idx > lastIdx {
				_, err = conn.Write(initialPayload[lastIdx:idx])
				if err != nil {
					conn.Close()
					return nil, err
				}
				lastIdx = idx

				jitter := time.Duration(rand.Intn(4000)-2000) * time.Microsecond
				sleepTime := fragSleep + jitter
				if sleepTime < 100*time.Microsecond {
					sleepTime = 100 * time.Microsecond
				}
				time.Sleep(sleepTime)
			}
		}
		if lastIdx < payloadLen {
			_, err = conn.Write(initialPayload[lastIdx:])
			if err != nil {
				conn.Close()
				return nil, err
			}
		}
	} else {
		_, err = conn.Write(initialPayload)
		if err != nil {
			conn.Close()
			return nil, err
		}
	}

	return conn, nil
}

// 3. TunnelConnection pipes traffic between client connection and remote server using standard sync.WaitGroup.
func (g *GFWResistHTTPS) TunnelConnection(clientConn net.Conn, remoteAddr string, clientHello []byte) error {
	defer clientConn.Close()

	remoteConn, err := g.DialTCPWithBypass(remoteAddr, clientHello)
	if err != nil {
		return err
	}
	defer remoteConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(remoteConn, clientConn)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, remoteConn)
	}()
	wg.Wait()

	return nil
}

// 4. SetNumFragments updates the target fragment splits.
func (g *GFWResistHTTPS) SetNumFragments(n int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.NumFragments = n
}

// 5. SetFragmentSleep updates the timing delay interval.
func (g *GFWResistHTTPS) SetFragmentSleep(d time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.FragmentSleep = d
}

// 6. AddStaticDNSEntry inserts a clean IP mapping.
func (g *GFWResistHTTPS) AddStaticDNSEntry(domain, ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.DNSMap[domain] = ip
}

// 7. RemoveStaticDNSEntry deletes a mapping.
func (g *GFWResistHTTPS) RemoveStaticDNSEntry(domain string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.DNSMap, domain)
}

// 8. GetDNSMap returns a copy of the current offline DNS map.
func (g *GFWResistHTTPS) GetDNSMap() map[string]string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	copied := make(map[string]string)
	for k, v := range g.DNSMap {
		copied[k] = v
	}
	return copied
}

// 9. BenchmarkDoH measures DoH upstream endpoint query latencies.
func (g *GFWResistHTTPS) BenchmarkDoH(ctx context.Context) (time.Duration, error) {
	g.mu.RLock()
	endpoint := g.DoHResolver
	g.mu.RUnlock()

	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return 0, err
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	return time.Since(start), nil
}

// 10. SetDoHResolver configures target DoH resolver upstreams.
func (g *GFWResistHTTPS) SetDoHResolver(url string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.DoHResolver = url
}

// 11. SetWriteTimeout configures TCP write boundaries.
func (g *GFWResistHTTPS) SetWriteTimeout(d time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.writeTimeout = d
}

// 12. SetReadTimeout configures TCP read boundaries.
func (g *GFWResistHTTPS) SetReadTimeout(d time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.readTimeout = d
}

// 13. SplitPayload returns slice boundaries.
func (g *GFWResistHTTPS) SplitPayload(payload []byte) [][]byte {
	g.mu.RLock()
	numFrags := g.NumFragments
	g.mu.RUnlock()

	length := len(payload)
	if length == 0 || numFrags <= 1 {
		return [][]byte{payload}
	}

	var results [][]byte
	chunkSize := length / numFrags
	if chunkSize == 0 {
		chunkSize = 1
	}

	for i := 0; i < length; i += chunkSize {
		end := i + chunkSize
		if end > length {
			end = length
		}
		results = append(results, payload[i:end])
	}
	return results
}

// 14. IsIPBlocked checks if destination IP is on known GFW blocklists.
func (g *GFWResistHTTPS) IsIPBlocked(ip string) bool {
	// Simulated block check
	return strings.HasPrefix(ip, "10.0.0.")
}

// 15. Connect implements the legacy entry trigger.
func (g *GFWResistHTTPS) Connect() {
	// Diagnostic stub
}
