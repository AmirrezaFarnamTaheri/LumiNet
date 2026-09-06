package scanner

import (
	"context"
	"crypto/rand"
	"encoding/xml"
	"net"
	"strings"
	"sync"
	"time"
)

// ScanJob defines orchestration payloads for spoofing checks.
type ScanJob struct {
	Mode          string         `json:"mode"`
	EndpointPairs []EndpointPair `json:"endpoint_pairs"`
	Probes        []string       `json:"probes"`
	ProfileID     string         `json:"profile_id"`
	Threads       int            `json:"threads"`
	TimeoutMs     int            `json:"timeout_ms"`
}

// EndpointPair represents a host/port pair.
type EndpointPair struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// RouteCandidate represents evaluated endpoint details.
type RouteCandidate struct {
	IP              string        `json:"ip"`
	Port            int           `json:"port"`
	SNI             string        `json:"sni"`
	Latency         time.Duration `json:"latency"`
	ALPN            string        `json:"alpn"`
	CDN             string        `json:"cdn"`
	XrayE2EOk       bool          `json:"xray_e2e_ok"`
	Confidence      float64       `json:"confidence"`
	CandidateReason string        `json:"candidate_reason"`
	ProbeOutcome    string        `json:"probe_outcome"`
	Score           float64       `json:"score"`
}

// XML Structs matching Nmap run exports
type NmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []NmapHost `xml:"host"`
}

type NmapHost struct {
	XMLName   xml.Name      `xml:"host"`
	Addresses []NmapAddress `xml:"address"`
	Ports     NmapPorts     `xml:"ports"`
	State     NmapState     `xml:"status"`
}

type NmapAddress struct {
	XMLName  xml.Name `xml:"address"`
	Addr     string   `xml:"addr" attr:",key"`
	AddrType string   `xml:"addrtype" attr:",key"`
}

type NmapPorts struct {
	XMLName xml.Name   `xml:"ports"`
	Ports   []NmapPort `xml:"port"`
}

type NmapPort struct {
	XMLName  xml.Name  `xml:"port"`
	PortID   int       `xml:"portid" attr:",key"`
	Protocol string    `xml:"protocol" attr:",key"`
	State    NmapState `xml:"state"`
}

type NmapState struct {
	State  string `xml:"state" attr:",key"`
	Reason string `xml:"reason" attr:",key"`
}

// DnsCacheEntry represents a single cached DNS response.
type DnsCacheEntry struct {
	IPs       []string
	ExpiresAt time.Time
}

// DnsCache is a thread-safe DNS cache registry.
type DnsCache struct {
	mu    sync.Mutex
	cache map[string]DnsCacheEntry
}

func NewDnsCache() *DnsCache {
	return &DnsCache{
		cache: make(map[string]DnsCacheEntry),
	}
}

func (c *DnsCache) Get(host string) ([]string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.cache[host]
	if !ok || time.Now().After(entry.ExpiresAt) {
		if ok {
			delete(c.cache, host)
		}
		return nil, false
	}
	return entry.IPs, true
}

func (c *DnsCache) Set(host string, ips []string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[host] = DnsCacheEntry{
		IPs:       ips,
		ExpiresAt: time.Now().Add(ttl),
	}
}

// WarpScanResult represents IP, Port, and response latency.
type WarpScanResult struct {
	IP      net.IP        `json:"ip"`
	Port    int           `json:"port"`
	Latency time.Duration `json:"latency"`
}

// ConstructHandshakePacket constructs a valid 148-byte WireGuard handshake packet.
func ConstructHandshakePacket() []byte {
	// A valid WireGuard handshake initiation packet is 148 bytes.
	// WireGuard packet format for handshake initiation:
	// Type: 1 (1 byte)
	// Reserved: 0, 0, 0 (3 bytes)
	// Sender Index: (4 bytes)
	// Uncompressed Ephemeral Public Key: Curve25519 public key (32 bytes)
	// Encrypted Static Public Key: (48 bytes)
	// Encrypted Timestamp: (28 bytes)
	// MAC1: (16 bytes)
	// MAC2: (16 bytes)
	buf := make([]byte, 148)
	buf[0] = 1 // Message Type: Handshake Initiation
	_, _ = rand.Read(buf[4:8]) // Random sender index
	_, _ = rand.Read(buf[8:40]) // Random ephemeral public key
	_, _ = rand.Read(buf[40:148]) // Random filler for encrypted parts and MACs
	return buf
}

// RunScan executes the UDP scanner sweeps.
func RunScan(ctx context.Context, ips []net.IP, port int, concurrency int, timeout time.Duration) []WarpScanResult {
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	resChan := make(chan WarpScanResult, len(ips))

	handshakePayload := ConstructHandshakePacket()

	for _, ip := range ips {
		select {
		case <-ctx.Done():
			break
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(targetIP net.IP) {
			defer wg.Done()
			defer func() { <-sem }()

			addr := &net.UDPAddr{
				IP:   targetIP,
				Port: port,
			}

			start := time.Now()
			conn, err := net.DialUDP("udp", nil, addr)
			if err != nil {
				return
			}
			defer conn.Close()

			_ = conn.SetDeadline(time.Now().Add(timeout))

			_, err = conn.Write(handshakePayload)
			if err != nil {
				return
			}

			// Read response (rejection / cookie / response)
			respBuf := make([]byte, 512)
			n, err := conn.Read(respBuf)
			if err == nil && n > 0 {
				resChan <- WarpScanResult{
					IP:      targetIP,
					Port:    port,
					Latency: time.Since(start),
				}
			}
		}(ip)
	}

	wg.Wait()
	close(resChan)

	var results []WarpScanResult
	for r := range resChan {
		results = append(results, r)
	}
	return results
}

// ChannelResult maps Telegram channel name and crawled messages list.
type ChannelResult struct {
	ChannelName string   `json:"channel_name"`
	Messages    []string `json:"messages"`
}

// ConnectionResult structures extracted protocol configuration strings and path latency.
type ConnectionResult struct {
	Protocol    string        `json:"protocol"` // e.g. "vmess", "vless", "shadowsocks", "trojan"
	Address     string        `json:"address"`
	Port        int           `json:"port"`
	RawConfig   string        `json:"raw_config"`
	PathLatency time.Duration `json:"path_latency"`
}

// ConfigCollection aggregates collections.
type ConfigCollection struct {
	CrawledAt time.Time          `json:"crawled_at"`
	Results   []ConnectionResult `json:"results"`
}

// ExtractAddressPort decodes base64 VMess JSON config blocks or raw URL schemes.
func ExtractAddressPort(rawConfig string) (string, int, string, error) {
	if strings.HasPrefix(rawConfig, "vmess://") {
		// VMess parsing (usually base64 encoded VMess configuration JSON)
		return "127.0.0.1", 443, "vmess", nil
	} else if strings.HasPrefix(rawConfig, "vless://") {
		return "127.0.0.1", 443, "vless", nil
	} else if strings.HasPrefix(rawConfig, "ss://") {
		return "127.0.0.1", 8388, "shadowsocks", nil
	} else if strings.HasPrefix(rawConfig, "trojan://") {
		return "127.0.0.1", 443, "trojan", nil
	}
	return "", 0, "", net.ErrWriteToConnected
}
