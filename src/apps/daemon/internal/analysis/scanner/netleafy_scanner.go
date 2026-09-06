// Package scanner implements host and dns probing operations.

package scanner

import (
	"fmt"
	"time"
)

// NetLeafyScanResult holds the output of probing a single TCP/UDP port.
type NetLeafyScanResult struct {
	Port      int           `json:"port"`
	Status    string        `json:"status"` // open, closed, filtered
	Service   string        `json:"service,omitempty"`
	Banner    string        `json:"banner,omitempty"`
	LatencyMs time.Duration `json:"latency_ms"`
	TLSActive bool          `json:"tls_active"`
}

// Getters & Setters for NetLeafyScanResult
func (r *NetLeafyScanResult) GetPort() int { return r.Port }
func (r *NetLeafyScanResult) SetPort(v int) { r.Port = v }
func (r *NetLeafyScanResult) GetStatus() string { return r.Status }
func (r *NetLeafyScanResult) SetStatus(v string) { r.Status = v }

// NetLeafyScannerConfig configures the IP network port prober.
type NetLeafyScannerConfig struct {
	TargetHost      string        `json:"target_host"`
	StartPort       int           `json:"start_port"`
	EndPort         int           `json:"end_port"`
	ConcurrentLimit int           `json:"concurrent_limit"`
	TimeoutSecs     time.Duration `json:"timeout_secs"`
	Protocol        string        `json:"protocol"` // tcp, udp
	OutputFile      string        `json:"output_file,omitempty"`
}

// Getters & Setters for NetLeafyScannerConfig
func (c *NetLeafyScannerConfig) GetTargetHost() string { return c.TargetHost }
func (c *NetLeafyScannerConfig) SetTargetHost(v string) { c.TargetHost = v }
func (c *NetLeafyScannerConfig) GetProtocol() string { return c.Protocol }
func (c *NetLeafyScannerConfig) SetProtocol(v string) { c.Protocol = v }

// FormatScanTargetString generates prober identifiers.
func (c *NetLeafyScannerConfig) FormatScanTargetString() string {
	return fmt.Sprintf("target-%s-range-%d-%d", c.TargetHost, c.StartPort, c.EndPort)
}

// Additional getters & setters for NetLeafyScanResult
func (r *NetLeafyScanResult) GetService() string { return r.Service }
func (r *NetLeafyScanResult) SetService(v string) { r.Service = v }
func (r *NetLeafyScanResult) GetBanner() string { return r.Banner }
func (r *NetLeafyScanResult) SetBanner(v string) { r.Banner = v }
func (r *NetLeafyScanResult) GetLatencyMs() time.Duration { return r.LatencyMs }
func (r *NetLeafyScanResult) SetLatencyMs(v time.Duration) { r.LatencyMs = v }
func (r *NetLeafyScanResult) GetTLSActive() bool { return r.TLSActive }
func (r *NetLeafyScanResult) SetTLSActive(v bool) { r.TLSActive = v }

// Additional getters & setters for NetLeafyScannerConfig
func (c *NetLeafyScannerConfig) GetStartPort() int { return c.StartPort }
func (c *NetLeafyScannerConfig) SetStartPort(v int) { c.StartPort = v }
func (c *NetLeafyScannerConfig) GetEndPort() int { return c.EndPort }
func (c *NetLeafyScannerConfig) SetEndPort(v int) { c.EndPort = v }
func (c *NetLeafyScannerConfig) GetConcurrentLimit() int { return c.ConcurrentLimit }
func (c *NetLeafyScannerConfig) SetConcurrentLimit(v int) { c.ConcurrentLimit = v }
func (c *NetLeafyScannerConfig) GetTimeoutSecs() time.Duration { return c.TimeoutSecs }
func (c *NetLeafyScannerConfig) SetTimeoutSecs(v time.Duration) { c.TimeoutSecs = v }
func (c *NetLeafyScannerConfig) GetOutputFile() string { return c.OutputFile }
func (c *NetLeafyScannerConfig) SetOutputFile(v string) { c.OutputFile = v }

// NetLeafyOSFingerprint stores parsed OS banners and accuracy ratings.
type NetLeafyOSFingerprint struct {
	FingerprintID   int
	OperatingSystem string
	Accuracy        int
	Vendor          string
}

// Getters & Setters for NetLeafyOSFingerprint
func (f *NetLeafyOSFingerprint) GetFingerprintID() int { return f.FingerprintID }
func (f *NetLeafyOSFingerprint) SetFingerprintID(v int) { f.FingerprintID = v }
func (f *NetLeafyOSFingerprint) GetOperatingSystem() string { return f.OperatingSystem }
func (f *NetLeafyOSFingerprint) SetOperatingSystem(v string) { f.OperatingSystem = v }
func (f *NetLeafyOSFingerprint) GetAccuracy() int { return f.Accuracy }
func (f *NetLeafyOSFingerprint) SetAccuracy(v int) { f.Accuracy = v }
func (f *NetLeafyOSFingerprint) GetVendor() string { return f.Vendor }
func (f *NetLeafyOSFingerprint) SetVendor(v string) { f.Vendor = v }

// NetLeafyScanTarget defines active host destination endpoints.
type NetLeafyScanTarget struct {
	TargetID  int
	IPAddress string
	Hostname  string
}

// Getters & Setters for NetLeafyScanTarget
func (t *NetLeafyScanTarget) GetTargetID() int { return t.TargetID }
func (t *NetLeafyScanTarget) SetTargetID(v int) { t.TargetID = v }
func (t *NetLeafyScanTarget) GetIPAddress() string { return t.IPAddress }
func (t *NetLeafyScanTarget) SetIPAddress(v string) { t.IPAddress = v }
func (t *NetLeafyScanTarget) GetHostname() string { return t.Hostname }
func (t *NetLeafyScanTarget) SetHostname(v string) { t.Hostname = v }

// NetLeafyXrayConfig represents outbound proxy settings in xray.
type NetLeafyXrayConfig struct {
	Protocol  string
	Address   string
	Port      int
	UUID      string
	Flow      string
	TLS       string
	SNI       string
	Fingerprint string
	ALPN      string
	PublicKey string
	ShortID   string
	Path      string
}

// Getters & Setters for NetLeafyXrayConfig
func (x *NetLeafyXrayConfig) GetProtocol() string { return x.Protocol }
func (x *NetLeafyXrayConfig) SetProtocol(v string) { x.Protocol = v }
func (x *NetLeafyXrayConfig) GetAddress() string { return x.Address }
func (x *NetLeafyXrayConfig) SetAddress(v string) { x.Address = v }
func (x *NetLeafyXrayConfig) GetPort() int { return x.Port }
func (x *NetLeafyXrayConfig) SetPort(v int) { x.Port = v }
func (x *NetLeafyXrayConfig) GetUUID() string { return x.UUID }
func (x *NetLeafyXrayConfig) SetUUID(v string) { x.UUID = v }
func (x *NetLeafyXrayConfig) GetFlow() string { return x.Flow }
func (x *NetLeafyXrayConfig) SetFlow(v string) { x.Flow = v }
func (x *NetLeafyXrayConfig) GetTLS() string { return x.TLS }
func (x *NetLeafyXrayConfig) SetTLS(v string) { x.TLS = v }
func (x *NetLeafyXrayConfig) GetSNI() string { return x.SNI }
func (x *NetLeafyXrayConfig) SetSNI(v string) { x.SNI = v }
func (x *NetLeafyXrayConfig) GetFingerprint() string { return x.Fingerprint }
func (x *NetLeafyXrayConfig) SetFingerprint(v string) { x.Fingerprint = v }
func (x *NetLeafyXrayConfig) GetALPN() string { return x.ALPN }
func (x *NetLeafyXrayConfig) SetALPN(v string) { x.ALPN = v }
func (x *NetLeafyXrayConfig) GetPublicKey() string { return x.PublicKey }
func (x *NetLeafyXrayConfig) SetPublicKey(v string) { x.PublicKey = v }
func (x *NetLeafyXrayConfig) GetShortID() string { return x.ShortID }
func (x *NetLeafyXrayConfig) SetShortID(v string) { x.ShortID = v }
func (x *NetLeafyXrayConfig) GetPath() string { return x.Path }
func (x *NetLeafyXrayConfig) SetPath(v string) { x.Path = v }

// NetLeafyProfile holds performance variables.
type NetLeafyProfile struct {
	ProfileID    string
	ProfileName  string
	ThreadsCount int
	TimeoutSec   int
	PingCount    int
}

// Getters & Setters for NetLeafyProfile
func (p *NetLeafyProfile) GetProfileID() string { return p.ProfileID }
func (p *NetLeafyProfile) SetProfileID(v string) { p.ProfileID = v }
func (p *NetLeafyProfile) GetProfileName() string { return p.ProfileName }
func (p *NetLeafyProfile) SetProfileName(v string) { p.ProfileName = v }
func (p *NetLeafyProfile) GetThreadsCount() int { return p.ThreadsCount }
func (p *NetLeafyProfile) SetThreadsCount(v int) { p.ThreadsCount = v }
func (p *NetLeafyProfile) GetTimeoutSec() int { return p.TimeoutSec }
func (p *NetLeafyProfile) SetTimeoutSec(v int) { p.TimeoutSec = v }
func (p *NetLeafyProfile) GetPingCount() int { return p.PingCount }
func (p *NetLeafyProfile) SetPingCount(v int) { p.PingCount = v }
