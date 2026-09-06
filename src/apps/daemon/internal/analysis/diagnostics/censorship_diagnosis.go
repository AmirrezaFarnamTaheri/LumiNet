package diagnostics

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// CensorshipDiagnosis holds results of automated diagnostic checks.
type CensorshipDiagnosis struct {
	Timestamp         time.Time `json:"timestamp"`
	DnsTampered       bool      `json:"dns_tampered"`
	TcpBlocked        bool      `json:"tcp_blocked"`
	SniBlocked        bool      `json:"sni_blocked"`
	ActiveMiddlebox   bool      `json:"active_middlebox"`
	EvasionSuggestion string    `json:"evasion_suggestion"`
	SuggestedConfig   string    `json:"suggested_config_profile"`
}

// CensorshipDoctor runs active probes to evaluate the network censorship layout.
// DiagnoseCensorship evaluates a target host using sequential OONI-probe style diagnostics.
func DiagnoseCensorship(ctx context.Context, target string) (*CensorshipDiagnosis, error) {
	if target == "" {
		target = "www.google.com"
	}
	diag := &CensorshipDiagnosis{
		Timestamp: time.Now(),
	}

	// 1. DNS Consistency Check
	ips, dnsErr := net.DefaultResolver.LookupHost(ctx, target)
	if dnsErr != nil || len(ips) == 0 {
		diag.DnsTampered = true
	} else {
		// Heuristic checks for RFC 3330 IP spoofing
		for _, ip := range ips {
			if ip == "0.0.0.0" || ip == "127.0.0.1" || strings.HasPrefix(ip, "192.0.2.") {
				diag.DnsTampered = true
				break
			}
		}
	}

	// 2. TCP Port 443 Reachability Check
	addr := net.JoinHostPort(target, "443")
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	tcpConn, tcpErr := dialer.DialContext(ctx, "tcp", addr)
	if tcpErr != nil {
		diag.TcpBlocked = true
	} else {
		tcpConn.Close()
	}

	// 3. TLS / SNI Inspection Check. Certificate verification is intentionally
	// disabled here because this probe distinguishes transport/SNI reachability
	// from PKI validity; request cancellation still applies to connect/handshake.
	tlsConfig := &tls.Config{
		ServerName:         target,
		InsecureSkipVerify: true, // diagnostic transport probe, not an authenticated application session
	}
	tlsDialer := &net.Dialer{Timeout: 3 * time.Second}
	rawConn, tlsErr := tlsDialer.DialContext(ctx, "tcp", addr)
	if tlsErr == nil {
		tlsConn := tls.Client(rawConn, tlsConfig)
		tlsErr = tlsConn.HandshakeContext(ctx)
		_ = tlsConn.Close()
	}
	if tlsErr != nil {
		diag.SniBlocked = true
		diag.ActiveMiddlebox = true
	}

	applyCensorshipSuggestion(diag, target)
	return diag, nil
}

func applyCensorshipSuggestion(diag *CensorshipDiagnosis, target string) {
	if diag.DnsTampered && diag.TcpBlocked {
		diag.EvasionSuggestion = fmt.Sprintf("Complete transport blocking active for %s. Use a configured GSA or serverless relay; simulated covert transports are not eligible.", target)
		diag.SuggestedConfig = "gsa"
	} else if diag.SniBlocked {
		diag.EvasionSuggestion = fmt.Sprintf("SNI inspection active (Deep Packet Inspection) for %s. Recommended ClientHello SNI casing mutation or precision SNI splits.", target)
		diag.SuggestedConfig = "sni-split-mutate"
	} else if diag.DnsTampered {
		diag.EvasionSuggestion = fmt.Sprintf("DNS poisoning active for %s. Recommended secure DNS-over-HTTPS or custom secure local resolver.", target)
		diag.SuggestedConfig = "secure-doh"
	} else {
		diag.EvasionSuggestion = fmt.Sprintf("No active network censorship detected for %s. Standard direct-dial bypass is sufficient.", target)
		diag.SuggestedConfig = "direct-bypass"
	}
}
