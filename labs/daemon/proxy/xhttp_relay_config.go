// Package proxy implements XHTTP relay config ported from XHTTPRelayAzure-main / XHTTPRelayECO-master.
// Source: XHTTPRelayAzure-main/index.js, XHTTPRelayECO-master/api/index.js
// Target: server/internal/proxy/xhttp_relay_config.go

package proxy

import "time"

// XHTTPRelayConfig holds all configuration for an XHTTP relay instance.
// Source: XHTTPRelayAzure-main/index.js global constants.
type XHTTPRelayConfig struct {
	// TargetBase is the upstream target base URL (no trailing slash).
	TargetBase string
	// RelayPath is the server-side path that maps to the upstream relay path.
	RelayPath string
	// PublicRelayPath is the publicly exposed path clients connect to.
	PublicRelayPath string
	// RelayKey is the optional shared secret (min 16 chars). Empty = unauthenticated.
	RelayKey string
	// UpstreamTimeoutMs is the read/write timeout for upstream connections.
	UpstreamTimeoutMs int
	// MaxInflight is the maximum number of concurrent relay requests.
	MaxInflight int
	// MaxUpBPS is the global upload bandwidth limit in bytes per second.
	MaxUpBPS int
	// MaxDownBPS is the global download bandwidth limit in bytes per second.
	MaxDownBPS int
	// SuccessLogSampleRate is the fraction of successful requests to log (0–1).
	SuccessLogSampleRate float64
	// SuccessLogMinDurationMs — only log successes exceeding this duration.
	SuccessLogMinDurationMs int
	// ErrorLogMinIntervalMs — minimum interval between error log entries.
	ErrorLogMinIntervalMs int
	// UpstreamDNSOrder controls DNS resolution order ("ipv4first" or "verbatim").
	UpstreamDNSOrder string
}

// NewXHTTPRelayConfig returns a default XHTTPRelayConfig from upstream defaults.
// Source: XHTTPRelayAzure-main/index.js constant declarations.
func NewXHTTPRelayConfig() *XHTTPRelayConfig {
	return &XHTTPRelayConfig{
		RelayPath:               "",
		PublicRelayPath:         "/api",
		RelayKey:                "",
		UpstreamTimeoutMs:       0,
		MaxInflight:             128,
		MaxUpBPS:                2621440,
		MaxDownBPS:              2621440,
		SuccessLogSampleRate:    0,
		SuccessLogMinDurationMs: 3000,
		ErrorLogMinIntervalMs:   5000,
		UpstreamDNSOrder:        "ipv4first",
	}
}

func (c *XHTTPRelayConfig) GetTargetBase() string             { return c.TargetBase }
func (c *XHTTPRelayConfig) SetTargetBase(v string)            { c.TargetBase = v }
func (c *XHTTPRelayConfig) GetRelayPath() string              { return c.RelayPath }
func (c *XHTTPRelayConfig) SetRelayPath(v string)             { c.RelayPath = v }
func (c *XHTTPRelayConfig) GetPublicRelayPath() string        { return c.PublicRelayPath }
func (c *XHTTPRelayConfig) SetPublicRelayPath(v string)       { c.PublicRelayPath = v }
func (c *XHTTPRelayConfig) GetRelayKey() string               { return c.RelayKey }
func (c *XHTTPRelayConfig) SetRelayKey(v string)              { c.RelayKey = v }
func (c *XHTTPRelayConfig) GetUpstreamTimeoutMs() int         { return c.UpstreamTimeoutMs }
func (c *XHTTPRelayConfig) SetUpstreamTimeoutMs(v int)        { c.UpstreamTimeoutMs = v }
func (c *XHTTPRelayConfig) GetMaxInflight() int               { return c.MaxInflight }
func (c *XHTTPRelayConfig) SetMaxInflight(v int)              { c.MaxInflight = v }
func (c *XHTTPRelayConfig) GetMaxUpBPS() int                  { return c.MaxUpBPS }
func (c *XHTTPRelayConfig) SetMaxUpBPS(v int)                 { c.MaxUpBPS = v }
func (c *XHTTPRelayConfig) GetMaxDownBPS() int                { return c.MaxDownBPS }
func (c *XHTTPRelayConfig) SetMaxDownBPS(v int)               { c.MaxDownBPS = v }
func (c *XHTTPRelayConfig) GetSuccessLogSampleRate() float64  { return c.SuccessLogSampleRate }
func (c *XHTTPRelayConfig) SetSuccessLogSampleRate(v float64) { c.SuccessLogSampleRate = v }
func (c *XHTTPRelayConfig) GetSuccessLogMinDurationMs() int   { return c.SuccessLogMinDurationMs }
func (c *XHTTPRelayConfig) SetSuccessLogMinDurationMs(v int)  { c.SuccessLogMinDurationMs = v }
func (c *XHTTPRelayConfig) GetErrorLogMinIntervalMs() int     { return c.ErrorLogMinIntervalMs }
func (c *XHTTPRelayConfig) SetErrorLogMinIntervalMs(v int)    { c.ErrorLogMinIntervalMs = v }
func (c *XHTTPRelayConfig) GetUpstreamDNSOrder() string       { return c.UpstreamDNSOrder }
func (c *XHTTPRelayConfig) SetUpstreamDNSOrder(v string)      { c.UpstreamDNSOrder = v }

// XHTTPRelayForwardHeaders defines the header filtering rules for XHTTP relay.
// Source: XHTTPRelayAzure-main/index.js FORWARD_HEADER_EXACT, FORWARD_HEADER_PREFIXES, STRIP_HEADERS.
type XHTTPRelayForwardHeaders struct {
	// ForwardExact is the set of headers to forward exactly.
	ForwardExact []string
	// ForwardPrefixes are header name prefixes that should be forwarded.
	ForwardPrefixes []string
	// StripHeaders is the set of headers that must be stripped from forwarded requests.
	StripHeaders []string
}

// NewXHTTPRelayForwardHeaders returns the upstream default header filtering rules.
func NewXHTTPRelayForwardHeaders() *XHTTPRelayForwardHeaders {
	return &XHTTPRelayForwardHeaders{
		ForwardExact: []string{
			"accept", "accept-encoding", "accept-language",
			"cache-control", "content-length", "content-type",
			"pragma", "range", "referer", "user-agent",
		},
		ForwardPrefixes: []string{"sec-ch-", "sec-fetch-"},
		StripHeaders: []string{
			"host", "connection", "proxy-connection", "keep-alive",
			"via", "proxy-authenticate", "proxy-authorization",
			"te", "trailer", "transfer-encoding", "upgrade",
			"forwarded", "x-forwarded-host", "x-forwarded-proto",
			"x-forwarded-port", "x-forwarded-for", "x-real-ip", "x-original-url",
		},
	}
}

func (h *XHTTPRelayForwardHeaders) GetForwardExact() []string     { return h.ForwardExact }
func (h *XHTTPRelayForwardHeaders) SetForwardExact(v []string)    { h.ForwardExact = v }
func (h *XHTTPRelayForwardHeaders) GetForwardPrefixes() []string  { return h.ForwardPrefixes }
func (h *XHTTPRelayForwardHeaders) SetForwardPrefixes(v []string) { h.ForwardPrefixes = v }
func (h *XHTTPRelayForwardHeaders) GetStripHeaders() []string     { return h.StripHeaders }
func (h *XHTTPRelayForwardHeaders) SetStripHeaders(v []string)    { h.StripHeaders = v }

// XHTTPRelayLogState tracks error and timeout suppression windows.
// Source: XHTTPRelayAzure-main/index.js logState object.
type XHTTPRelayLogState struct {
	TimeoutLastAt     int64
	TimeoutSuppressed int
	ErrorLastAt       int64
	ErrorSuppressed   int
}

func (l *XHTTPRelayLogState) GetTimeoutLastAt() int64    { return l.TimeoutLastAt }
func (l *XHTTPRelayLogState) SetTimeoutLastAt(v int64)   { l.TimeoutLastAt = v }
func (l *XHTTPRelayLogState) GetTimeoutSuppressed() int  { return l.TimeoutSuppressed }
func (l *XHTTPRelayLogState) SetTimeoutSuppressed(v int) { l.TimeoutSuppressed = v }
func (l *XHTTPRelayLogState) GetErrorLastAt() int64      { return l.ErrorLastAt }
func (l *XHTTPRelayLogState) SetErrorLastAt(v int64)     { l.ErrorLastAt = v }
func (l *XHTTPRelayLogState) GetErrorSuppressed() int    { return l.ErrorSuppressed }
func (l *XHTTPRelayLogState) SetErrorSuppressed(v int)   { l.ErrorSuppressed = v }

// XHTTPRelayRequestMeta holds per-request metadata during relay processing.
// Source: XHTTPRelayAzure-main/index.js handleRelay local variables.
type XHTTPRelayRequestMeta struct {
	RequestID          string
	StartedAt          time.Time
	SlotAcquired       bool
	HitUpstreamTimeout bool
	UpstreamPath       string
	TargetURL          string
	Method             string
	StatusCode         int
	DurationMs         int64
}

func (r *XHTTPRelayRequestMeta) GetRequestID() string         { return r.RequestID }
func (r *XHTTPRelayRequestMeta) SetRequestID(v string)        { r.RequestID = v }
func (r *XHTTPRelayRequestMeta) GetStartedAt() time.Time      { return r.StartedAt }
func (r *XHTTPRelayRequestMeta) SetStartedAt(v time.Time)     { r.StartedAt = v }
func (r *XHTTPRelayRequestMeta) GetSlotAcquired() bool        { return r.SlotAcquired }
func (r *XHTTPRelayRequestMeta) SetSlotAcquired(v bool)       { r.SlotAcquired = v }
func (r *XHTTPRelayRequestMeta) GetHitUpstreamTimeout() bool  { return r.HitUpstreamTimeout }
func (r *XHTTPRelayRequestMeta) SetHitUpstreamTimeout(v bool) { r.HitUpstreamTimeout = v }
func (r *XHTTPRelayRequestMeta) GetUpstreamPath() string      { return r.UpstreamPath }
func (r *XHTTPRelayRequestMeta) SetUpstreamPath(v string)     { r.UpstreamPath = v }
func (r *XHTTPRelayRequestMeta) GetTargetURL() string         { return r.TargetURL }
func (r *XHTTPRelayRequestMeta) SetTargetURL(v string)        { r.TargetURL = v }
func (r *XHTTPRelayRequestMeta) GetMethod() string            { return r.Method }
func (r *XHTTPRelayRequestMeta) SetMethod(v string)           { r.Method = v }
func (r *XHTTPRelayRequestMeta) GetStatusCode() int           { return r.StatusCode }
func (r *XHTTPRelayRequestMeta) SetStatusCode(v int)          { r.StatusCode = v }
func (r *XHTTPRelayRequestMeta) GetDurationMs() int64         { return r.DurationMs }
func (r *XHTTPRelayRequestMeta) SetDurationMs(v int64)        { r.DurationMs = v }
