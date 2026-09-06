// Package proxy implements TCP-over-HTTP relay models ported from JJTcpOverHttpRelayVpn.
// Source: src/core/constants.py
// Target: server/internal/proxy/jjtcprelay_config.go

package proxy

import "time"

// JJRelayConfig holds all tuneable parameters from the upstream constants.py.
type JJRelayConfig struct {
	MaxRequestBodyBytes  int
	MaxResponseBodyBytes int
	MaxHeaderBytes       int
	ClientIdleTimeout    time.Duration
	RelayTimeout         time.Duration
	TLSConnectTimeout    time.Duration
	TCPConnectTimeout    time.Duration

	// Google IP scanner settings
	GoogleScannerTimeout     time.Duration
	GoogleScannerConcurrency int

	// Response cache
	CacheMaxMB         int
	CacheTTLStaticLong time.Duration
	CacheTTLStaticMed  time.Duration
	CacheTTLMax        time.Duration

	// Connection pool
	PoolMax       int
	PoolMinIdle   int
	ConnTTL       time.Duration
	SemaphoreMax  int
	WarmPoolCount int

	// Batch windows
	BatchWindowMicro time.Duration
	BatchWindowMacro time.Duration
	BatchMax         int

	// Fan-out relay
	ScriptBlacklistTTL time.Duration

	// Stats logging
	StatsLogInterval time.Duration
	StatsLogTopN     int

	// Rate sampling
	SuccessLogSampleRate    float64
	SuccessLogMinDurationMs int
	ErrorLogMinIntervalMs   int

	// Bandwidth limits (bytes per second)
	MaxUpBPS    int
	MaxDownBPS  int
	MaxInflight int

	// Upstream timeout
	UpstreamTimeoutMs int
}

// NewJJRelayConfig returns a JJRelayConfig with upstream defaults from constants.py.
func NewJJRelayConfig() *JJRelayConfig {
	return &JJRelayConfig{
		MaxRequestBodyBytes:      100 * 1024 * 1024,
		MaxResponseBodyBytes:     200 * 1024 * 1024,
		MaxHeaderBytes:           64 * 1024,
		ClientIdleTimeout:        120 * time.Second,
		RelayTimeout:             25 * time.Second,
		TLSConnectTimeout:        15 * time.Second,
		TCPConnectTimeout:        10 * time.Second,
		GoogleScannerTimeout:     4 * time.Second,
		GoogleScannerConcurrency: 8,
		CacheMaxMB:               50,
		CacheTTLStaticLong:       3600 * time.Second,
		CacheTTLStaticMed:        1800 * time.Second,
		CacheTTLMax:              86400 * time.Second,
		PoolMax:                  50,
		PoolMinIdle:              15,
		ConnTTL:                  45 * time.Second,
		SemaphoreMax:             50,
		WarmPoolCount:            30,
		BatchWindowMicro:         15 * time.Millisecond,
		BatchWindowMacro:         120 * time.Millisecond,
		BatchMax:                 64,
		ScriptBlacklistTTL:       600 * time.Second,
		StatsLogInterval:         300 * time.Second,
		StatsLogTopN:             10,
		MaxUpBPS:                 2621440,
		MaxDownBPS:               2621440,
		MaxInflight:              128,
		UpstreamTimeoutMs:        25000,
	}
}

// Getters & Setters for JJRelayConfig
func (c *JJRelayConfig) GetMaxRequestBodyBytes() int             { return c.MaxRequestBodyBytes }
func (c *JJRelayConfig) SetMaxRequestBodyBytes(v int)            { c.MaxRequestBodyBytes = v }
func (c *JJRelayConfig) GetMaxResponseBodyBytes() int            { return c.MaxResponseBodyBytes }
func (c *JJRelayConfig) SetMaxResponseBodyBytes(v int)           { c.MaxResponseBodyBytes = v }
func (c *JJRelayConfig) GetMaxHeaderBytes() int                  { return c.MaxHeaderBytes }
func (c *JJRelayConfig) SetMaxHeaderBytes(v int)                 { c.MaxHeaderBytes = v }
func (c *JJRelayConfig) GetClientIdleTimeout() time.Duration     { return c.ClientIdleTimeout }
func (c *JJRelayConfig) SetClientIdleTimeout(v time.Duration)    { c.ClientIdleTimeout = v }
func (c *JJRelayConfig) GetRelayTimeout() time.Duration          { return c.RelayTimeout }
func (c *JJRelayConfig) SetRelayTimeout(v time.Duration)         { c.RelayTimeout = v }
func (c *JJRelayConfig) GetTLSConnectTimeout() time.Duration     { return c.TLSConnectTimeout }
func (c *JJRelayConfig) SetTLSConnectTimeout(v time.Duration)    { c.TLSConnectTimeout = v }
func (c *JJRelayConfig) GetTCPConnectTimeout() time.Duration     { return c.TCPConnectTimeout }
func (c *JJRelayConfig) SetTCPConnectTimeout(v time.Duration)    { c.TCPConnectTimeout = v }
func (c *JJRelayConfig) GetGoogleScannerTimeout() time.Duration  { return c.GoogleScannerTimeout }
func (c *JJRelayConfig) SetGoogleScannerTimeout(v time.Duration) { c.GoogleScannerTimeout = v }
func (c *JJRelayConfig) GetGoogleScannerConcurrency() int        { return c.GoogleScannerConcurrency }
func (c *JJRelayConfig) SetGoogleScannerConcurrency(v int)       { c.GoogleScannerConcurrency = v }
func (c *JJRelayConfig) GetCacheMaxMB() int                      { return c.CacheMaxMB }
func (c *JJRelayConfig) SetCacheMaxMB(v int)                     { c.CacheMaxMB = v }
func (c *JJRelayConfig) GetPoolMax() int                         { return c.PoolMax }
func (c *JJRelayConfig) SetPoolMax(v int)                        { c.PoolMax = v }
func (c *JJRelayConfig) GetPoolMinIdle() int                     { return c.PoolMinIdle }
func (c *JJRelayConfig) SetPoolMinIdle(v int)                    { c.PoolMinIdle = v }
func (c *JJRelayConfig) GetConnTTL() time.Duration               { return c.ConnTTL }
func (c *JJRelayConfig) SetConnTTL(v time.Duration)              { c.ConnTTL = v }
func (c *JJRelayConfig) GetSemaphoreMax() int                    { return c.SemaphoreMax }
func (c *JJRelayConfig) SetSemaphoreMax(v int)                   { c.SemaphoreMax = v }
func (c *JJRelayConfig) GetWarmPoolCount() int                   { return c.WarmPoolCount }
func (c *JJRelayConfig) SetWarmPoolCount(v int)                  { c.WarmPoolCount = v }
func (c *JJRelayConfig) GetBatchMax() int                        { return c.BatchMax }
func (c *JJRelayConfig) SetBatchMax(v int)                       { c.BatchMax = v }
func (c *JJRelayConfig) GetScriptBlacklistTTL() time.Duration    { return c.ScriptBlacklistTTL }
func (c *JJRelayConfig) SetScriptBlacklistTTL(v time.Duration)   { c.ScriptBlacklistTTL = v }
func (c *JJRelayConfig) GetStatsLogTopN() int                    { return c.StatsLogTopN }
func (c *JJRelayConfig) SetStatsLogTopN(v int)                   { c.StatsLogTopN = v }
func (c *JJRelayConfig) GetMaxUpBPS() int                        { return c.MaxUpBPS }
func (c *JJRelayConfig) SetMaxUpBPS(v int)                       { c.MaxUpBPS = v }
func (c *JJRelayConfig) GetMaxDownBPS() int                      { return c.MaxDownBPS }
func (c *JJRelayConfig) SetMaxDownBPS(v int)                     { c.MaxDownBPS = v }
func (c *JJRelayConfig) GetMaxInflight() int                     { return c.MaxInflight }
func (c *JJRelayConfig) SetMaxInflight(v int)                    { c.MaxInflight = v }
func (c *JJRelayConfig) GetUpstreamTimeoutMs() int               { return c.UpstreamTimeoutMs }
func (c *JJRelayConfig) SetUpstreamTimeoutMs(v int)              { c.UpstreamTimeoutMs = v }

// JJRelaySNIPool holds SNI rotation pools from constants.py FRONT_SNI_POOL_GOOGLE.
type JJRelaySNIPool struct {
	GoogleFrontSNIs      []string
	SNIRewriteSuffixes   []string
	GoogleOwnedSuffixes  []string
	GoogleDirectExcludes []string
	GoogleDirectAllows   []string
	TraceHostSuffixes    []string
}

func NewJJRelaySNIPool() *JJRelaySNIPool {
	return &JJRelaySNIPool{
		GoogleFrontSNIs: []string{
			"mail.google.com",
			"accounts.google.com",
			"www.google.com",
		},
		SNIRewriteSuffixes: []string{
			"youtube.com", "youtu.be", "youtube-nocookie.com",
			"ytimg.com", "ggpht.com", "gvt1.com", "gvt2.com",
			"doubleclick.net", "googlesyndication.com",
			"googleadservices.com", "google-analytics.com",
			"googletagmanager.com", "googletagservices.com",
			"fonts.googleapis.com", "script.google.com",
		},
		GoogleOwnedSuffixes: []string{
			".google.com", ".google.co", ".googleapis.com",
			".gstatic.com", ".googleusercontent.com",
		},
		GoogleDirectExcludes: []string{
			"gemini.google.com", "aistudio.google.com",
			"notebooklm.google.com", "labs.google.com",
			"meet.google.com", "accounts.google.com",
			"ogs.google.com", "mail.google.com",
		},
		GoogleDirectAllows: []string{
			"www.google.com", "google.com", "safebrowsing.google.com",
		},
		TraceHostSuffixes: []string{
			"chatgpt.com", "openai.com", "gemini.google.com",
			"google.com", "cloudflare.com",
		},
	}
}

func (p *JJRelaySNIPool) GetGoogleFrontSNIs() []string       { return p.GoogleFrontSNIs }
func (p *JJRelaySNIPool) SetGoogleFrontSNIs(v []string)      { p.GoogleFrontSNIs = v }
func (p *JJRelaySNIPool) GetSNIRewriteSuffixes() []string    { return p.SNIRewriteSuffixes }
func (p *JJRelaySNIPool) SetSNIRewriteSuffixes(v []string)   { p.SNIRewriteSuffixes = v }
func (p *JJRelaySNIPool) GetGoogleOwnedSuffixes() []string   { return p.GoogleOwnedSuffixes }
func (p *JJRelaySNIPool) SetGoogleOwnedSuffixes(v []string)  { p.GoogleOwnedSuffixes = v }
func (p *JJRelaySNIPool) GetGoogleDirectExcludes() []string  { return p.GoogleDirectExcludes }
func (p *JJRelaySNIPool) SetGoogleDirectExcludes(v []string) { p.GoogleDirectExcludes = v }
func (p *JJRelaySNIPool) GetGoogleDirectAllows() []string    { return p.GoogleDirectAllows }
func (p *JJRelaySNIPool) SetGoogleDirectAllows(v []string)   { p.GoogleDirectAllows = v }
func (p *JJRelaySNIPool) GetTraceHostSuffixes() []string     { return p.TraceHostSuffixes }
func (p *JJRelaySNIPool) SetTraceHostSuffixes(v []string)    { p.TraceHostSuffixes = v }

// JJRelayCandidateGoogleIPs holds the upstream candidate Google frontend IPs.
// Source: constants.py CANDIDATE_IPS tuple
var JJRelayCandidateGoogleIPs = []string{
	"216.239.32.120", "216.239.34.120", "216.239.36.120", "216.239.38.120",
	"142.250.80.142", "142.250.80.138", "142.250.179.110", "142.250.185.110",
	"142.250.184.206", "142.250.190.238", "142.250.191.78",
	"172.217.1.206", "172.217.14.206", "172.217.16.142", "172.217.22.174",
	"172.217.164.110", "172.217.168.206", "172.217.169.206",
	"34.107.221.82",
	"142.251.32.110", "142.251.33.110", "142.251.46.206", "142.251.46.238",
	"142.250.80.170", "142.250.72.206", "142.250.64.206", "142.250.72.110",
}
