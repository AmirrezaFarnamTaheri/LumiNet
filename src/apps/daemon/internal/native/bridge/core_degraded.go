//go:build !cgo || android || ios

package bridge

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// NativeCoreLinked reports whether this build is backed by the linked LumiCore native implementation.
const NativeCoreLinked = false

// IcmpScan requires native ICMP probing; DNS resolution is not a substitute
// for reachability and must not be reported as scan success.
func IcmpScan([]string, ScanConfig) ([]ProbeResult, error) {
	return nil, fmt.Errorf("%w: ICMP scan", ErrNativeCoreUnavailable)
}

// TcpConnect performs a real TCP connection check in pure Go.
func TcpConnect(target string, port uint16, timeout uint32) (*ProbeResult, error) {
	start := time.Now()
	addr := net.JoinHostPort(target, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, time.Duration(timeout)*time.Millisecond)
	latency := float64(time.Since(start).Milliseconds())

	if err != nil {
		return &ProbeResult{
			Target:    target,
			Port:      port,
			Alive:     false,
			LatencyMs: latency,
			Error:     err.Error(),
			ErrorCode: "CONNECTION_FAILED",
			Timestamp: uint64(time.Now().Unix()),
		}, nil
	}
	defer conn.Close()

	ip := ""
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		ip = tcpAddr.IP.String()
	}

	return &ProbeResult{
		Target:    target,
		Port:      port,
		IP:        ip,
		Alive:     true,
		LatencyMs: latency,
		Timestamp: uint64(time.Now().Unix()),
	}, nil
}

// PortScan runs a concurrent port scan using pure Go net.Dial.
func PortScan(target string, ports []uint16, config ScanConfig) ([]PortResult, error) {
	if config.Concurrency == 0 {
		config.Concurrency = 1
	}
	results := make([]PortResult, len(ports))
	type sem struct{}
	limit := make(chan sem, config.Concurrency)

	for i, port := range ports {
		limit <- sem{}
		go func(idx int, p uint16) {
			defer func() { <-limit }()
			start := time.Now()
			addr := net.JoinHostPort(target, fmt.Sprintf("%d", p))
			conn, err := net.DialTimeout("tcp", addr, time.Duration(config.Timeout)*time.Millisecond)
			latency := float64(time.Since(start).Milliseconds())

			if err != nil {
				results[idx] = PortResult{
					IP:        target,
					Port:      p,
					Open:      false,
					Protocol:  "tcp",
					LatencyMs: latency,
				}
				return
			}
			conn.Close()

			results[idx] = PortResult{
				IP:        target,
				Port:      p,
				Open:      true,
				Protocol:  "tcp",
				LatencyMs: latency,
			}
		}(i, port)
	}

	// Wait for all goroutines to finish by filling the limit channel
	for i := 0; i < int(config.Concurrency); i++ {
		limit <- sem{}
	}

	return results, nil
}

// DnsResolve queries the requested DNS server with the historical 3-second timeout.
func DnsResolve(server, domain string, recordType string) (*DnsServerResult, error) {
	return DnsResolveWithTimeout(server, domain, recordType, 3000)
}

// DnsResolveWithTimeout is a behaviorally real pure-Go fallback. Standard Go
// lookups are routed to the caller-selected UDP DNS server. TTL is reported as
// zero because net.Resolver does not expose authoritative TTL values.
func DnsResolveWithTimeout(server, domain string, recordType string, timeoutMs uint32) (*DnsServerResult, error) {
	if timeoutMs == 0 {
		timeoutMs = 3000
	}
	if server == "" {
		return nil, fmt.Errorf("empty DNS server")
	}
	if strings.Contains(server, "://") {
		return nil, fmt.Errorf("%w: DoH DNS fallback", ErrNativeCoreUnavailable)
	}
	if host, port, err := net.SplitHostPort(server); err == nil {
		if port == "853" {
			return nil, fmt.Errorf("%w: DoT DNS fallback", ErrNativeCoreUnavailable)
		}
		server = net.JoinHostPort(host, port)
	} else {
		server = net.JoinHostPort(server, "53")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp", server)
		},
	}
	started := time.Now()
	records, err := lookupDNSRecords(ctx, resolver, domain, strings.ToUpper(recordType))
	latency := float64(time.Since(started).Milliseconds())
	result := &DnsServerResult{Server: server, Protocol: "udp", LatencyMs: latency, Records: records}
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}
	result.Success = true
	return result, nil
}

func lookupDNSRecords(ctx context.Context, resolver *net.Resolver, domain, recordType string) ([]DnsRecord, error) {
	makeRecord := func(value string) DnsRecord {
		return DnsRecord{Name: domain, Type: recordType, Value: value, TTL: 0, Class: "IN"}
	}
	switch recordType {
	case "A", "AAAA":
		network := "ip4"
		if recordType == "AAAA" {
			network = "ip6"
		}
		ips, err := resolver.LookupIP(ctx, network, domain)
		if err != nil {
			return nil, err
		}
		out := make([]DnsRecord, 0, len(ips))
		for _, ip := range ips {
			out = append(out, makeRecord(ip.String()))
		}
		return out, nil
	case "CNAME":
		value, err := resolver.LookupCNAME(ctx, domain)
		if err != nil {
			return nil, err
		}
		return []DnsRecord{makeRecord(value)}, nil
	case "TXT":
		values, err := resolver.LookupTXT(ctx, domain)
		if err != nil {
			return nil, err
		}
		out := make([]DnsRecord, 0, len(values))
		for _, value := range values {
			out = append(out, makeRecord(value))
		}
		return out, nil
	case "MX":
		values, err := resolver.LookupMX(ctx, domain)
		if err != nil {
			return nil, err
		}
		out := make([]DnsRecord, 0, len(values))
		for _, value := range values {
			out = append(out, makeRecord(fmt.Sprintf("%d %s", value.Pref, value.Host)))
		}
		return out, nil
	case "NS":
		values, err := resolver.LookupNS(ctx, domain)
		if err != nil {
			return nil, err
		}
		out := make([]DnsRecord, 0, len(values))
		for _, value := range values {
			out = append(out, makeRecord(value.Host))
		}
		return out, nil
	case "PTR":
		values, err := resolver.LookupAddr(ctx, domain)
		if err != nil {
			return nil, err
		}
		out := make([]DnsRecord, 0, len(values))
		for _, value := range values {
			out = append(out, makeRecord(value))
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported DNS record type %q in pure-Go fallback", recordType)
	}
}

// TlsHandshake performs a real TLS handshake in Go.
func TlsHandshake(host string, port uint16, timeout uint32) (*TlsInfo, error) {
	return TlsHandshakeWithSni(host, port, host, timeout)
}

func TlsHandshakeWithSni(host string, port uint16, sni string, timeout uint32) (*TlsInfo, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	dialer := &net.Dialer{
		Timeout: time.Duration(timeout) * time.Millisecond,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	var alpn []string
	if state.NegotiatedProtocol != "" {
		alpn = []string{state.NegotiatedProtocol}
	}

	subject := ""
	issuer := ""
	san := []string{}
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		subject = cert.Subject.String()
		issuer = cert.Issuer.String()
		san = cert.DNSNames
	}

	return &TlsInfo{
		Version:     fmt.Sprintf("%x", state.Version),
		CipherSuite: fmt.Sprintf("%d", state.CipherSuite),
		CertIssuer:  issuer,
		CertSubject: subject,
		ALPN:        alpn,
		SanDomains:  san,
		ChainLength: len(state.PeerCertificates),
	}, nil
}

// SniDetect requires the native censorship-detection implementation.
func SniDetect(string, uint32) (*SniResult, error) {
	return nil, fmt.Errorf("%w: SNI detection", ErrNativeCoreUnavailable)
}

// SpeedTest requires the native throughput implementation.
func SpeedTest(string, uint32) (*SpeedResult, error) {
	return nil, fmt.Errorf("%w: speed test", ErrNativeCoreUnavailable)
}

// WgProbe requires the native WireGuard handshake implementation.
func WgProbe(string, uint16, uint32, uint32) (*ProbeResult, error) {
	return nil, fmt.Errorf("%w: WireGuard probe", ErrNativeCoreUnavailable)
}

// InjectFakePacket requires native raw-packet injection.
func InjectFakePacket(string, uint16, uint32, *uint8, *uint32, *uint32, string) error {
	return fmt.Errorf("%w: raw packet injection", ErrNativeCoreUnavailable)
}

// DisassemblePayload requires the native disassembler.
func DisassemblePayload([]byte, string) (string, error) {
	return "", fmt.Errorf("%w: payload disassembly", ErrNativeCoreUnavailable)
}
