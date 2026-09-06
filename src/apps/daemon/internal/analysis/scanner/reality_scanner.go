package scanner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	maxRealityScanTargetLen = 1024
	maxRealityServerNameLen = 253
	maxRealityScanErrorLen  = 512
	maxRealityCertLabelLen  = 256
)

// RealityScanResult holds strict TLS camouflage validation results.
type RealityScanResult struct {
	Target      string `json:"target"`
	HandshakeOK bool   `json:"handshake_ok"`
	CertSubject string `json:"cert_subject,omitempty"`
	LatencyMs   int64  `json:"latency_ms"`
	Error       string `json:"error,omitempty"`
}

// RealityScanner verifies REALITY target server health. RootCAs is optional and
// exists primarily for deterministic tests/private trust stores; nil uses the
// platform trust store. HandshakeOK always means chain + hostname verification
// succeeded for the requested server name.
type RealityScanner struct {
	Timeout time.Duration
	RootCAs *x509.CertPool
}

// NewRealityScanner creates an instance of RealityScanner.
func NewRealityScanner() *RealityScanner {
	return &RealityScanner{Timeout: 3 * time.Second}
}

// Scan performs a strict, context-cancellable TLS handshake to validate the
// camouflage server name. It never disables certificate verification.
func (s *RealityScanner) Scan(ctx context.Context, target string, serverName string) (*RealityScanResult, error) {
	started := time.Now()
	target = strings.TrimSpace(target)
	serverName = strings.TrimSpace(serverName)
	result := &RealityScanResult{Target: boundedRealityText(target, maxRealityScanTargetLen)}
	if target == "" || len(target) > maxRealityScanTargetLen {
		result.Error = boundedRealityError(fmt.Errorf("target length must be 1..%d bytes", maxRealityScanTargetLen))
		return result, nil
	}
	if serverName == "" || len(serverName) > maxRealityServerNameLen {
		result.Error = boundedRealityError(fmt.Errorf("server name length must be 1..%d bytes", maxRealityServerNameLen))
		return result, nil
	}
	if _, _, err := net.SplitHostPort(target); err != nil {
		result.Error = boundedRealityError(fmt.Errorf("invalid target: %w", err))
		return result, nil
	}

	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	scanCtx := ctx
	cancel := func() {}
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > timeout {
		scanCtx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()

	dialer := &net.Dialer{Timeout: timeout}
	raw, err := dialer.DialContext(scanCtx, "tcp", target)
	if err != nil {
		result.LatencyMs = time.Since(started).Milliseconds()
		result.Error = boundedRealityError(err)
		return result, nil
	}
	defer raw.Close()

	conn := tls.Client(raw, &tls.Config{
		ServerName: serverName,
		RootCAs:    s.RootCAs,
		MinVersion: tls.VersionTLS12,
	})
	if err := conn.HandshakeContext(scanCtx); err != nil {
		result.LatencyMs = time.Since(started).Milliseconds()
		result.Error = boundedRealityError(err)
		return result, nil
	}
	result.LatencyMs = time.Since(started).Milliseconds()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		result.Error = "TLS handshake returned no peer certificate"
		return result, nil
	}
	leaf := state.PeerCertificates[0]
	label := strings.TrimSpace(leaf.Subject.CommonName)
	if label == "" && len(leaf.DNSNames) > 0 {
		label = strings.TrimSpace(leaf.DNSNames[0])
	}
	result.CertSubject = boundedRealityText(label, maxRealityCertLabelLen)
	result.HandshakeOK = true
	return result, nil
}

func boundedRealityError(err error) string {
	if err == nil {
		return ""
	}
	return boundedRealityText(err.Error(), maxRealityScanErrorLen)
}

func boundedRealityText(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
