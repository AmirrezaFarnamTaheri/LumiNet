package diagnostics

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// DynamicProxyProtocol defines proxy protocol types
type DynamicProxyProtocol string

const (
	ProxyProtoHTTP   DynamicProxyProtocol = "http"
	ProxyProtoHTTPS  DynamicProxyProtocol = "https"
	ProxyProtoSocks4 DynamicProxyProtocol = "socks4"
	ProxyProtoSocks5 DynamicProxyProtocol = "socks5"
)

// DynamicAnonymityLevel describes proxy anonymity tier
type DynamicAnonymityLevel string

const (
	AnonymityTransparent DynamicAnonymityLevel = "transparent"
	AnonymityAnonymous   DynamicAnonymityLevel = "anonymous"
	AnonymityElite       DynamicAnonymityLevel = "elite"
)

// DynamicProxyRecord stores validated proxy details
type DynamicProxyRecord struct {
	Host          string
	Port          uint16
	Protocol      DynamicProxyProtocol
	IsAlive       bool
	Latency       time.Duration
	Anonymity     DynamicAnonymityLevel
	LastCheckedAt time.Time
}

// DynamicProxyValidator maintains a validated proxy pool
type DynamicProxyValidator struct {
	mu           sync.RWMutex
	ProbeTimeout time.Duration
	Pool         map[string]*DynamicProxyRecord
}

// NewDynamicProxyValidator creates a new proxy validator
func NewDynamicProxyValidator(timeout time.Duration) *DynamicProxyValidator {
	return &DynamicProxyValidator{
		ProbeTimeout: timeout,
		Pool:         make(map[string]*DynamicProxyRecord),
	}
}

// CraftSocks5Probe returns standard SOCKS5 negotiation handshake
func (v *DynamicProxyValidator) CraftSocks5Probe() []byte {
	return []byte{0x05, 0x01, 0x00}
}

// CraftHTTPProbe returns an HTTP GET probe buffer
func (v *DynamicProxyValidator) CraftHTTPProbe(host string) []byte {
	return []byte(fmt.Sprintf("GET http://%s/generate_204 HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host, host))
}

// VerifySocks5Response checks if probe handshake was accepted
func (v *DynamicProxyValidator) VerifySocks5Response(resp []byte) bool {
	return len(resp) >= 2 && resp[0] == 0x05 && resp[1] == 0x00
}

// DetermineAnonymity classifies proxy header leakage
func (v *DynamicProxyValidator) DetermineAnonymity(headers map[string]string, clientIP string) DynamicAnonymityLevel {
	hasForwardingHeader := false
	for k, val := range headers {
		lower := strings.ToLower(k)
		if lower == "x-forwarded-for" || lower == "via" || lower == "x-real-ip" || lower == "forwarded" {
			hasForwardingHeader = true
			if strings.Contains(val, clientIP) {
				return AnonymityTransparent
			}
		}
	}

	if hasForwardingHeader {
		return AnonymityAnonymous
	}
	return AnonymityElite
}

// RecordProbe records or updates a proxy result
func (v *DynamicProxyValidator) RecordProbe(host string, port uint16, proto DynamicProxyProtocol, alive bool, latency time.Duration, anon DynamicAnonymityLevel) {
	v.mu.Lock()
	defer v.mu.Unlock()

	key := fmt.Sprintf("%s:%d", host, port)
	v.Pool[key] = &DynamicProxyRecord{
		Host:          host,
		Port:          port,
		Protocol:      proto,
		IsAlive:       alive,
		Latency:       latency,
		Anonymity:     anon,
		LastCheckedAt: time.Now(),
	}
}

// GetHealthyProxies returns sorted list of alive proxies under max latency
func (v *DynamicProxyValidator) GetHealthyProxies(maxLatency time.Duration) []*DynamicProxyRecord {
	v.mu.RLock()
	defer v.mu.RUnlock()

	var result []*DynamicProxyRecord
	for _, p := range v.Pool {
		if p.IsAlive && p.Latency <= maxLatency {
			result = append(result, p)
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Latency < result[j].Latency
	})
	return result
}
