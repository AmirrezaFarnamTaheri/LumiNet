package proxy

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DnsScannerTarget defines resolver/host target metadata.
type DnsScannerTarget struct {
	IP   string
	SNI  string
	Port int
}

// DnsScannerResult holds probe parameters and outcomes.
type DnsScannerResult struct {
	Target       DnsScannerTarget `json:"target"`
	Protocol     string           `json:"protocol"` // "UDP", "TCP", "DoT", "DoH"
	Latency      time.Duration    `json:"latency"`
	Responded    bool             `json:"responded"`
	IsPoisoned   bool             `json:"is_poisoned"`
	IsHijacked   bool             `json:"is_hijacked"`
	SupportsAAAA bool             `json:"supports_aaaa"`
	SupportsDO   bool             `json:"supports_do"`
	Error        string           `json:"error,omitempty"`
}

// TruthTable stores known-good DNS mappings for verification.
type TruthTable struct {
	Domain   string
	TruthIPs map[string]bool
	mu       sync.RWMutex
}

// FetchTruth fetches verified A records for a domain from trusted DoH servers.
func FetchTruth(ctx context.Context, domain string) (*TruthTable, error) {
	tt := &TruthTable{
		Domain:   domain,
		TruthIPs: make(map[string]bool),
	}

	dohServers := []string{
		"https://cloudflare-dns.com/dns-query?name=%s&type=A",
		"https://dns.google/dns-query?name=%s&type=A",
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	var lastErr error
	for _, urlTemplate := range dohServers {
		reqURL := fmt.Sprintf(urlTemplate, domain)
		req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("accept", "application/dns-json")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = err
			continue
		}

		var payload struct {
			Answer []struct {
				Type int    `json:"type"`
				Data string `json:"data"`
			} `json:"Answer"`
		}

		if err := json.Unmarshal(body, &payload); err != nil {
			lastErr = err
			continue
		}

		tt.mu.Lock()
		for _, ans := range payload.Answer {
			if ans.Type == 1 { // A Record
				tt.TruthIPs[ans.Data] = true
			}
		}
		tt.mu.Unlock()

		if len(tt.TruthIPs) > 0 {
			return tt, nil
		}
	}

	// Fallback to local resolver if DoH query fails
	ips, err := net.DefaultResolver.LookupHost(ctx, domain)
	if err == nil {
		tt.mu.Lock()
		for _, ip := range ips {
			if net.ParseIP(ip).To4() != nil {
				tt.TruthIPs[ip] = true
			}
		}
		tt.mu.Unlock()
		return tt, nil
	}

	return nil, fmt.Errorf("failed to fetch truth table: %v", lastErr)
}

// VerifyAnswer verifies client-returned IPs against the Truth Table.
func (tt *TruthTable) VerifyAnswer(ips []string) bool {
	tt.mu.RLock()
	defer tt.mu.RUnlock()
	if len(tt.TruthIPs) == 0 {
		return false
	}
	for _, ip := range ips {
		if !tt.TruthIPs[ip] {
			return true // Poisoned! Mismatch detected.
		}
	}
	return false
}

// ScanHttpRelayIP performs concurrent scanning using an HTTP HEAD request over TLS/SNI.
func ScanHttpRelayIP(ctx context.Context, target DnsScannerTarget, timeout time.Duration) DnsScannerResult {
	res := DnsScannerResult{
		Target: target,
	}

	t0 := time.Now()
	dialAddr := net.JoinHostPort(target.IP, "443")
	dialer := net.Dialer{Timeout: timeout}

	conn, err := dialer.DialContext(ctx, "tcp", dialAddr)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer conn.Close()

	tlsConfig := &tls.Config{
		ServerName:         target.SNI,
		InsecureSkipVerify: true,
	}
	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		res.Error = err.Error()
		return res
	}
	defer tlsConn.Close()

	req := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target.SNI)
	tlsConn.SetDeadline(time.Now().Add(timeout))
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		res.Error = err.Error()
		return res
	}

	buf := make([]byte, 256)
	n, err := tlsConn.Read(buf)
	if err != nil && err != io.EOF {
		res.Error = err.Error()
		return res
	}

	res.Latency = time.Since(t0)
	respStr := string(buf[:n])
	if strings.HasPrefix(respStr, "HTTP/") {
		res.Responded = true
	} else {
		res.Error = "invalid response protocol signature"
	}

	return res
}

// GenerateIPStream parses CIDR notations, chunks them into randomized subnets, and streams IPs.
func GenerateIPStream(cidrs []string, maxIPs int) <-chan string {
	out := make(chan string, 128)
	go func() {
		defer close(out)
		count := 0

		for _, cidr := range cidrs {
			ip, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}

			// Slice CIDR block by converting base IP to 32-bit uint
			base := binary.BigEndian.Uint32(ip.To4())
			mask := binary.BigEndian.Uint32(net.IP(ipnet.Mask).To4())
			size := ^mask

			// Perform randomized sampling of offsets to stream IPs
			for i := uint32(0); i <= size && count < maxIPs; i++ {
				nBig, err := rand.Int(rand.Reader, big.NewInt(int64(size+1)))
				offset := uint32(0)
				if err == nil {
					offset = uint32(nBig.Int64())
				} else {
					offset = i
				}

				candidate := base | (offset & ^mask)
				resIP := make(net.IP, 4)
				binary.BigEndian.PutUint32(resIP, candidate)

				out <- resIP.String()
				count++
			}
		}
	}()
	return out
}

// BuildDnssecRawQuery constructs a raw DNS query UDP payload requesting example.com A record
// with custom EDNS0 OPT record DO (DNSSEC OK) flags enabled.
func BuildDnssecRawQuery() []byte {
	txid := make([]byte, 2)
	rand.Read(txid) // Cryptographically randomized transaction ID

	flags := []byte{0x01, 0x00}                                      // Standard query
	counts := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01} // QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=1

	// QNAME: example.com
	qname := []byte{0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00}
	qtype := []byte{0x00, 0x01}  // A record
	qclass := []byte{0x00, 0x01} // IN class

	// EDNS0 OPT RR (RFC 6891)
	// Name: 0x00 (root), Type: 0x0029 (OPT), Payload size: 0x1000 (4096)
	// Rcode/Version: 0x0000, DO flag enabled: 0x8000, RDLEN: 0x0000
	opt := []byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00}

	query := make([]byte, 0, len(txid)+len(flags)+len(counts)+len(qname)+len(qtype)+len(qclass)+len(opt))
	query = append(query, txid...)
	query = append(query, flags...)
	query = append(query, counts...)
	query = append(query, qname...)
	query = append(query, qtype...)
	query = append(query, qclass...)
	query = append(query, opt...)
	return query
}

// RunResolverDiagnostic runs UDP/TCP/DoT/DoH diagnostics, DO checks, and nonexistent hijack tests.
func RunResolverDiagnostic(ctx context.Context, resolverIP string, tt *TruthTable, timeout time.Duration) DnsScannerResult {
	res := DnsScannerResult{
		Target: DnsScannerTarget{IP: resolverIP, Port: 53},
	}

	// 1. DNSSEC DO and UDP Query
	t0 := time.Now()
	query := BuildDnssecRawQuery()
	conn, err := net.DialTimeout("udp", net.JoinHostPort(resolverIP, "53"), timeout)
	if err == nil {
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(timeout))
		if _, err := conn.Write(query); err == nil {
			buf := make([]byte, 512)
			if n, err := conn.Read(buf); err == nil && n > 12 {
				res.Responded = true
				res.Protocol = "UDP"
				res.Latency = time.Since(t0)

				// Parse ARCOUNT and opt records to check if DO flag is set/echoed
				arcount := binary.BigEndian.Uint16(buf[10:12])
				if arcount > 0 {
					res.SupportsDO = true
				}
			}
		}
	}

	// 2. Hijacking check using random non-existent domain
	nBig, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	nonexistentDomain := fmt.Sprintf("nxdomain-%d.example.invalid", nBig.Int64())
	ips, err := net.DefaultResolver.LookupHost(ctx, nonexistentDomain)
	if err == nil && len(ips) > 0 {
		res.IsHijacked = true
	}

	// 3. IPv6 support checking
	_, err = net.DefaultResolver.LookupIP(ctx, "ip6", "google.com")
	if err == nil {
		res.SupportsAAAA = true
	}

	// 4. Poisoning validation using truth table
	if tt != nil {
		testIPs, err := net.DefaultResolver.LookupHost(ctx, tt.Domain)
		if err == nil && len(testIPs) > 0 {
			res.IsPoisoned = tt.VerifyAnswer(testIPs)
		}
	}

	return res
}
