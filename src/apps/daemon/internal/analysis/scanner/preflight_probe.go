// Package scanner implements host and dns probing operations.

package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// PreflightProbeResult holds DNS + TCP + TLS layered probe metrics.
type PreflightProbeResult struct {
	Status     string `json:"status"`
	ResolvedIP string `json:"resolved_ip"`
	Port       int    `json:"port"`
	Scheme     string `json:"scheme"`
	SpoofedSNI string `json:"spoofed_sni"`
	LatencyMs  int    `json:"latency_ms"`
	ErrDetails string `json:"err_details"`
}

// Getters & Setters for PreflightProbeResult
func (r *PreflightProbeResult) GetStatus() string { return r.Status }
func (r *PreflightProbeResult) SetStatus(v string) { r.Status = v }
func (r *PreflightProbeResult) GetResolvedIP() string { return r.ResolvedIP }
func (r *PreflightProbeResult) SetResolvedIP(v string) { r.ResolvedIP = v }
func (r *PreflightProbeResult) GetPort() int { return r.Port }
func (r *PreflightProbeResult) SetPort(v int) { r.Port = v }
func (r *PreflightProbeResult) GetScheme() string { return r.Scheme }
func (r *PreflightProbeResult) SetScheme(v string) { r.Scheme = v }
func (r *PreflightProbeResult) GetSpoofedSNI() string { return r.SpoofedSNI }
func (r *PreflightProbeResult) SetSpoofedSNI(v string) { r.SpoofedSNI = v }
func (r *PreflightProbeResult) GetLatencyMs() int { return r.LatencyMs }
func (r *PreflightProbeResult) SetLatencyMs(v int) { r.LatencyMs = v }
func (r *PreflightProbeResult) GetErrDetails() string { return r.ErrDetails }
func (r *PreflightProbeResult) SetErrDetails(v string) { r.ErrDetails = v }

// Builders for PreflightProbeResult
func (r *PreflightProbeResult) WithStatus(v string) *PreflightProbeResult { r.SetStatus(v); return r }
func (r *PreflightProbeResult) WithResolvedIP(v string) *PreflightProbeResult { r.SetResolvedIP(v); return r }
func (r *PreflightProbeResult) WithPort(v int) *PreflightProbeResult { r.SetPort(v); return r }
func (r *PreflightProbeResult) WithScheme(v string) *PreflightProbeResult { r.SetScheme(v); return r }
func (r *PreflightProbeResult) WithSpoofedSNI(v string) *PreflightProbeResult { r.SetSpoofedSNI(v); return r }

// PreflightProbeEngine manages active probing sessions with anti-exhaustion safety.
type PreflightProbeEngine struct {
	mu           sync.RWMutex
	SpoofedSNI   string
	ProbeTimeout time.Duration
	LastStatus   string
	SuccessCount int64
	FailureCount int64
	Retries      int
	UseFallback  bool
	IsActive     bool
}

// Getters & Setters for PreflightProbeEngine
func (e *PreflightProbeEngine) GetSpoofedSNI() string { e.mu.RLock(); defer e.mu.RUnlock(); return e.SpoofedSNI }
func (e *PreflightProbeEngine) SetSpoofedSNI(v string) { e.mu.Lock(); defer e.mu.Unlock(); e.SpoofedSNI = v }
func (e *PreflightProbeEngine) GetProbeTimeout() time.Duration { e.mu.RLock(); defer e.mu.RUnlock(); return e.ProbeTimeout }
func (e *PreflightProbeEngine) SetProbeTimeout(v time.Duration) { e.mu.Lock(); defer e.mu.Unlock(); e.ProbeTimeout = v }
func (e *PreflightProbeEngine) GetLastStatus() string { e.mu.RLock(); defer e.mu.RUnlock(); return e.LastStatus }
func (e *PreflightProbeEngine) SetLastStatus(v string) { e.mu.Lock(); defer e.mu.Unlock(); e.LastStatus = v }
func (e *PreflightProbeEngine) GetSuccessCount() int64 { return atomic.LoadInt64(&e.SuccessCount) }
func (e *PreflightProbeEngine) SetSuccessCount(v int64) { atomic.StoreInt64(&e.SuccessCount, v) }
func (e *PreflightProbeEngine) GetFailureCount() int64 { return atomic.LoadInt64(&e.FailureCount) }
func (e *PreflightProbeEngine) SetFailureCount(v int64) { atomic.StoreInt64(&e.FailureCount, v) }
func (e *PreflightProbeEngine) GetRetries() int { e.mu.RLock(); defer e.mu.RUnlock(); return e.Retries }
func (e *PreflightProbeEngine) SetRetries(v int) { e.mu.Lock(); defer e.mu.Unlock(); e.Retries = v }
func (e *PreflightProbeEngine) GetUseFallback() bool { e.mu.RLock(); defer e.mu.RUnlock(); return e.UseFallback }
func (e *PreflightProbeEngine) SetUseFallback(v bool) { e.mu.Lock(); defer e.mu.Unlock(); e.UseFallback = v }
func (e *PreflightProbeEngine) GetIsActive() bool { e.mu.RLock(); defer e.mu.RUnlock(); return e.IsActive }
func (e *PreflightProbeEngine) SetIsActive(v bool) { e.mu.Lock(); defer e.mu.Unlock(); e.IsActive = v }

// Builders for PreflightProbeEngine
func (e *PreflightProbeEngine) WithSpoofedSNI(v string) *PreflightProbeEngine { e.SetSpoofedSNI(v); return e }
func (e *PreflightProbeEngine) WithProbeTimeout(v time.Duration) *PreflightProbeEngine { e.SetProbeTimeout(v); return e }
func (e *PreflightProbeEngine) WithRetries(v int) *PreflightProbeEngine { e.SetRetries(v); return e }
func (e *PreflightProbeEngine) WithUseFallback(v bool) *PreflightProbeEngine { e.SetUseFallback(v); return e }
func (e *PreflightProbeEngine) WithIsActive(v bool) *PreflightProbeEngine { e.SetIsActive(v); return e }

// Operations
func NewPreflightProbeEngine() *PreflightProbeEngine {
	return &PreflightProbeEngine{
		ProbeTimeout: 3 * time.Second,
		Retries:      1,
		UseFallback:  true,
		IsActive:     true,
	}
}

func (e *PreflightProbeEngine) RunPreflightLayerCheck(ctx context.Context, host string, port int, scheme string) PreflightProbeResult {
	start := time.Now()
	res := PreflightProbeResult{
		Port:       port,
		Scheme:     scheme,
		SpoofedSNI: e.GetSpoofedSNI(),
	}

	if host == "" {
		res.Status = "PARSE_ERR"
		atomic.AddInt64(&e.FailureCount, 1)
		return res
	}

	// 1. Resolve host to IP
	var resolvedIP string
	if ip := net.ParseIP(host); ip != nil {
		resolvedIP = ip.String()
	} else {
		dnsCtx, cancel := context.WithTimeout(ctx, e.GetProbeTimeout())
		defer cancel()
		ips, err := net.DefaultResolver.LookupHost(dnsCtx, host)
		if err != nil || len(ips) == 0 {
			res.Status = "DNS_FAILED"
			res.ErrDetails = "LookupHost error: " + fmt.Sprint(err)
			atomic.AddInt64(&e.FailureCount, 1)
			return res
		}
		resolvedIP = ips[0]
	}
	res.ResolvedIP = resolvedIP

	// 2. TCP Handshake (Syn check)
	tcpAddr := net.JoinHostPort(resolvedIP, fmt.Sprintf("%d", port))
	dialer := &net.Dialer{Timeout: e.GetProbeTimeout()}
	conn, err := dialer.DialContext(ctx, "tcp", tcpAddr)
	if err != nil {
		res.Status = "TCP_FAILED"
		res.ErrDetails = "Dial error: " + err.Error()
		atomic.AddInt64(&e.FailureCount, 1)
		return res
	}
	conn.Close()

	// 3. TLS spoofed SNI Handshake
	if scheme == "https" {
		tlsDialer := &net.Dialer{Timeout: e.GetProbeTimeout()}
		tlsConn, err := tls.DialWithDialer(tlsDialer, "tcp", tcpAddr, &tls.Config{
			ServerName:         e.GetSpoofedSNI(),
			InsecureSkipVerify: true,
		})
		if err != nil {
			if e.IsSocketExhaustion(err) {
				res.Status = "FATAL_ERR"
			} else {
				res.Status = "TLS_FAILED"
			}
			res.ErrDetails = "TLS Dial error: " + err.Error()
			atomic.AddInt64(&e.FailureCount, 1)
			return res
		}
		tlsConn.Close()
	}

	res.Status = "PASSED"
	res.LatencyMs = int(time.Since(start).Milliseconds())
	atomic.AddInt64(&e.SuccessCount, 1)
	return res
}

func (e *PreflightProbeEngine) IsSocketExhaustion(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	patterns := []string{
		"too many open files",
		"resource temporarily unavailable",
		"emfile",
		"enfile",
		"wsaemfile",
	}
	for _, p := range patterns {
		if strings.Contains(errStr, p) {
			return true
		}
	}
	return false
}

func (e *PreflightProbeEngine) RunPreflightWithFallback(ctx context.Context, host string, port int, scheme string) PreflightProbeResult {
	res := e.RunPreflightLayerCheck(ctx, host, port, scheme)
	if res.Status == "PASSED" || !e.GetUseFallback() {
		return res
	}

	fallbackScheme := "http"
	if scheme == "http" {
		fallbackScheme = "https"
	}

	fallbackRes := e.RunPreflightLayerCheck(ctx, host, port, fallbackScheme)
	if fallbackRes.Status == "PASSED" {
		return fallbackRes
	}
	return res
}

func (e *PreflightProbeEngine) GetSuccessRate() float64 {
	success := atomic.LoadInt64(&e.SuccessCount)
	failure := atomic.LoadInt64(&e.FailureCount)
	total := success + failure
	if total == 0 {
		return 1.0
	}
	return float64(success) / float64(total)
}

func (e *PreflightProbeEngine) ResetStats() {
	atomic.StoreInt64(&e.SuccessCount, 0)
	atomic.StoreInt64(&e.FailureCount, 0)
}
