// Package scanner implements host and dns probing operations.

package scanner

import (
	"fmt"
	"time"
)

// NetLeafyBannerInfo holds payload/banner details.
type NetLeafyBannerInfo struct {
	Port            int    `json:"port"`
	Protocol        string `json:"protocol"`
	RawBanner       string `json:"raw_banner"`
	SSLFingerprint  string `json:"ssl_fingerprint,omitempty"`
	ServiceDetected string `json:"service_detected"`
}

// Getters & Setters for NetLeafyBannerInfo
func (b *NetLeafyBannerInfo) GetPort() int { return b.Port }
func (b *NetLeafyBannerInfo) SetPort(v int) { b.Port = v }
func (b *NetLeafyBannerInfo) GetRawBanner() string { return b.RawBanner }
func (b *NetLeafyBannerInfo) SetRawBanner(v string) { b.RawBanner = v }

// NetLeafyProber executes local port checks.
type NetLeafyProber struct {
	TargetIP    string        `json:"target_ip"`
	Timeout     time.Duration `json:"timeout"`
	Concurrency int           `json:"concurrency"`
}

// Getters & Setters for NetLeafyProber
func (p *NetLeafyProber) GetTargetIP() string { return p.TargetIP }
func (p *NetLeafyProber) SetTargetIP(v string) { p.TargetIP = v }

// FormatProberTarget returns diagnostic destination.
func (p *NetLeafyProber) FormatProberTarget() string {
	return fmt.Sprintf("prober-%s-timeout-%s-workers-%d", p.TargetIP, p.Timeout, p.Concurrency)
}

// Additional getters & setters for NetLeafyBannerInfo
func (b *NetLeafyBannerInfo) GetProtocol() string { return b.Protocol }
func (b *NetLeafyBannerInfo) SetProtocol(v string) { b.Protocol = v }
func (b *NetLeafyBannerInfo) GetSSLFingerprint() string { return b.SSLFingerprint }
func (b *NetLeafyBannerInfo) SetSSLFingerprint(v string) { b.SSLFingerprint = v }
func (b *NetLeafyBannerInfo) GetServiceDetected() string { return b.ServiceDetected }
func (b *NetLeafyBannerInfo) SetServiceDetected(v string) { b.ServiceDetected = v }

// Additional getters & setters for NetLeafyProber
func (p *NetLeafyProber) GetTimeout() time.Duration { return p.Timeout }
func (p *NetLeafyProber) SetTimeout(v time.Duration) { p.Timeout = v }
func (p *NetLeafyProber) GetConcurrency() int { return p.Concurrency }
func (p *NetLeafyProber) SetConcurrency(v int) { p.Concurrency = v }
