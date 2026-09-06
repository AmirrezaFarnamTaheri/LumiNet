// Package proxy implements HTTP-relay VPN client config ported from MasterHttpRelayVPN-RUST-main.
// Source: src/config.rs
// Target: server/internal/proxy/master_http_relay_config.go

package proxy

// MasterHTTPRelayMode enumerates operating modes of the HTTP relay VPN.
// Source: config.rs Mode enum
type MasterHTTPRelayMode string

const (
	// MasterHTTPRelayModeAppsScript — full client; MITMs TLS locally and relays through Apps Script.
	MasterHTTPRelayModeAppsScript MasterHTTPRelayMode = "apps_script"
	// MasterHTTPRelayModeDirect — SNI-rewrite only, no Apps Script relay.
	// Deprecated alias "google_only" is also accepted by upstream.
	MasterHTTPRelayModeDirect MasterHTTPRelayMode = "direct"
	// MasterHTTPRelayModeFull — full tunnel mode including UDP relay (v1.7.0+).
	MasterHTTPRelayModeFull MasterHTTPRelayMode = "full"
)

// MasterHTTPRelayConfig holds all configuration for a MasterHttpRelayVPN client.
// Source: config.rs Config struct
type MasterHTTPRelayConfig struct {
	// Mode is one of "apps_script", "direct", "full".
	Mode string
	// GoogleIP is the Google edge IP to connect to.
	GoogleIP string
	// FrontDomain is the SNI domain used for TLS fronting.
	FrontDomain string
	// ScriptIDs is the Apps Script deployment ID list (one or many).
	ScriptIDs []string
	// AuthKey is the shared secret for authenticating relay requests.
	AuthKey string
	// ListenHost is the local MITM proxy listen address.
	ListenHost string
	// ListenPort is the local MITM proxy listen port.
	ListenPort uint16
	// SOCKS5Port is the optional local SOCKS5 listener port.
	SOCKS5Port *uint16
	// LogLevel is the logging verbosity (e.g. "info", "debug").
	LogLevel string
	// VerifySSL controls whether upstream TLS certificates are verified.
	VerifySSL bool
	// Hosts maps hostnames to overrides/annotations.
	Hosts map[string]string
	// EnableBatching activates request coalescing to the Apps Script relay.
	EnableBatching bool
	// UpstreamSOCKS5 is an optional upstream SOCKS5 proxy for raw TCP flows.
	UpstreamSOCKS5 string
	// ParallelRelay is the Apps Script fan-out factor per request (0/1=off).
	ParallelRelay uint8
	// CoalesceStepMs is the adaptive batch coalesce wait per arrival (ms).
	CoalesceStepMs uint16
	// CoalesceMaxMs is the hard cap on total coalesce wait (ms).
	CoalesceMaxMs uint16
	// SNIHosts is an explicit SNI rotation pool (empty = auto-expanded from FrontDomain).
	SNIHosts []string
	// FetchIPsFromAPI controls whether to fetch candidate Google IPs from upstream API.
	FetchIPsFromAPI bool
	// MaxIPsToScan caps how many IPs are scanned per run.
	MaxIPsToScan int
	// ScanBatchSize is the concurrency batch size for IP scanning.
	ScanBatchSize int
	// GoogleIPValidation enables/disables Apps Script IP validation.
	GoogleIPValidation bool
	// NormalizeXGraphQL strips Twitter/X graphql request noise for better cache hit rate.
	NormalizeXGraphQL bool
	// YouTubeViaRelay routes YouTube through Apps Script instead of SNI-rewrite.
	YouTubeViaRelay bool
	// PassthroughHosts lists hostnames that bypass the relay entirely.
	PassthroughHosts []string
	// BlockQUIC drops UDP/443 at the SOCKS5 listener to force TCP fallback.
	BlockQUIC bool
	// BlockSTUN drops STUN/TURN UDP ports (3478,5349,19302) to force TCP TURN.
	BlockSTUN bool
	// DisablePadding suppresses the DPI-evasion random _pad field in Apps Script requests.
	DisablePadding bool
	// ForceHTTP1 disables HTTP/2 multiplexing on the relay leg.
	ForceHTTP1 bool
	// TunnelDoH keeps DoH inside the relay tunnel (default true since v1.9.0).
	TunnelDoH bool
	// ExtraDoHHosts supplements the built-in DoH bypass host list.
	ExtraDoHHosts []string
}

// NewMasterHTTPRelayConfig returns a MasterHTTPRelayConfig with upstream defaults.
// Source: config.rs serde defaults (default_* functions and struct defaults).
func NewMasterHTTPRelayConfig() *MasterHTTPRelayConfig {
	return &MasterHTTPRelayConfig{
		Mode:               string(MasterHTTPRelayModeAppsScript),
		GoogleIP:           "216.239.32.120",
		FrontDomain:        "www.google.com",
		ListenHost:         "127.0.0.1",
		ListenPort:         8080,
		LogLevel:           "info",
		VerifySSL:          true,
		Hosts:              make(map[string]string),
		EnableBatching:     false,
		ParallelRelay:      0,
		CoalesceStepMs:     0,
		CoalesceMaxMs:      0,
		FetchIPsFromAPI:    true,
		MaxIPsToScan:       100,
		ScanBatchSize:      20,
		GoogleIPValidation: true,
		NormalizeXGraphQL:  false,
		YouTubeViaRelay:    false,
		BlockQUIC:          false,
		BlockSTUN:          true,
		DisablePadding:     false,
		ForceHTTP1:         false,
		TunnelDoH:          true,
	}
}

func (c *MasterHTTPRelayConfig) GetMode() string                { return c.Mode }
func (c *MasterHTTPRelayConfig) SetMode(v string)               { c.Mode = v }
func (c *MasterHTTPRelayConfig) GetGoogleIP() string            { return c.GoogleIP }
func (c *MasterHTTPRelayConfig) SetGoogleIP(v string)           { c.GoogleIP = v }
func (c *MasterHTTPRelayConfig) GetFrontDomain() string         { return c.FrontDomain }
func (c *MasterHTTPRelayConfig) SetFrontDomain(v string)        { c.FrontDomain = v }
func (c *MasterHTTPRelayConfig) GetScriptIDs() []string         { return c.ScriptIDs }
func (c *MasterHTTPRelayConfig) SetScriptIDs(v []string)        { c.ScriptIDs = v }
func (c *MasterHTTPRelayConfig) GetAuthKey() string             { return c.AuthKey }
func (c *MasterHTTPRelayConfig) SetAuthKey(v string)            { c.AuthKey = v }
func (c *MasterHTTPRelayConfig) GetListenHost() string          { return c.ListenHost }
func (c *MasterHTTPRelayConfig) SetListenHost(v string)         { c.ListenHost = v }
func (c *MasterHTTPRelayConfig) GetListenPort() uint16          { return c.ListenPort }
func (c *MasterHTTPRelayConfig) SetListenPort(v uint16)         { c.ListenPort = v }
func (c *MasterHTTPRelayConfig) GetSOCKS5Port() *uint16         { return c.SOCKS5Port }
func (c *MasterHTTPRelayConfig) SetSOCKS5Port(v *uint16)        { c.SOCKS5Port = v }
func (c *MasterHTTPRelayConfig) GetLogLevel() string            { return c.LogLevel }
func (c *MasterHTTPRelayConfig) SetLogLevel(v string)           { c.LogLevel = v }
func (c *MasterHTTPRelayConfig) GetVerifySSL() bool             { return c.VerifySSL }
func (c *MasterHTTPRelayConfig) SetVerifySSL(v bool)            { c.VerifySSL = v }
func (c *MasterHTTPRelayConfig) GetHosts() map[string]string    { return c.Hosts }
func (c *MasterHTTPRelayConfig) SetHosts(v map[string]string)   { c.Hosts = v }
func (c *MasterHTTPRelayConfig) GetEnableBatching() bool        { return c.EnableBatching }
func (c *MasterHTTPRelayConfig) SetEnableBatching(v bool)       { c.EnableBatching = v }
func (c *MasterHTTPRelayConfig) GetUpstreamSOCKS5() string      { return c.UpstreamSOCKS5 }
func (c *MasterHTTPRelayConfig) SetUpstreamSOCKS5(v string)     { c.UpstreamSOCKS5 = v }
func (c *MasterHTTPRelayConfig) GetParallelRelay() uint8        { return c.ParallelRelay }
func (c *MasterHTTPRelayConfig) SetParallelRelay(v uint8)       { c.ParallelRelay = v }
func (c *MasterHTTPRelayConfig) GetCoalesceStepMs() uint16      { return c.CoalesceStepMs }
func (c *MasterHTTPRelayConfig) SetCoalesceStepMs(v uint16)     { c.CoalesceStepMs = v }
func (c *MasterHTTPRelayConfig) GetCoalesceMaxMs() uint16       { return c.CoalesceMaxMs }
func (c *MasterHTTPRelayConfig) SetCoalesceMaxMs(v uint16)      { c.CoalesceMaxMs = v }
func (c *MasterHTTPRelayConfig) GetSNIHosts() []string          { return c.SNIHosts }
func (c *MasterHTTPRelayConfig) SetSNIHosts(v []string)         { c.SNIHosts = v }
func (c *MasterHTTPRelayConfig) GetFetchIPsFromAPI() bool       { return c.FetchIPsFromAPI }
func (c *MasterHTTPRelayConfig) SetFetchIPsFromAPI(v bool)      { c.FetchIPsFromAPI = v }
func (c *MasterHTTPRelayConfig) GetMaxIPsToScan() int           { return c.MaxIPsToScan }
func (c *MasterHTTPRelayConfig) SetMaxIPsToScan(v int)          { c.MaxIPsToScan = v }
func (c *MasterHTTPRelayConfig) GetScanBatchSize() int          { return c.ScanBatchSize }
func (c *MasterHTTPRelayConfig) SetScanBatchSize(v int)         { c.ScanBatchSize = v }
func (c *MasterHTTPRelayConfig) GetGoogleIPValidation() bool    { return c.GoogleIPValidation }
func (c *MasterHTTPRelayConfig) SetGoogleIPValidation(v bool)   { c.GoogleIPValidation = v }
func (c *MasterHTTPRelayConfig) GetNormalizeXGraphQL() bool     { return c.NormalizeXGraphQL }
func (c *MasterHTTPRelayConfig) SetNormalizeXGraphQL(v bool)    { c.NormalizeXGraphQL = v }
func (c *MasterHTTPRelayConfig) GetYouTubeViaRelay() bool       { return c.YouTubeViaRelay }
func (c *MasterHTTPRelayConfig) SetYouTubeViaRelay(v bool)      { c.YouTubeViaRelay = v }
func (c *MasterHTTPRelayConfig) GetPassthroughHosts() []string  { return c.PassthroughHosts }
func (c *MasterHTTPRelayConfig) SetPassthroughHosts(v []string) { c.PassthroughHosts = v }
func (c *MasterHTTPRelayConfig) GetBlockQUIC() bool             { return c.BlockQUIC }
func (c *MasterHTTPRelayConfig) SetBlockQUIC(v bool)            { c.BlockQUIC = v }
func (c *MasterHTTPRelayConfig) GetBlockSTUN() bool             { return c.BlockSTUN }
func (c *MasterHTTPRelayConfig) SetBlockSTUN(v bool)            { c.BlockSTUN = v }
func (c *MasterHTTPRelayConfig) GetDisablePadding() bool        { return c.DisablePadding }
func (c *MasterHTTPRelayConfig) SetDisablePadding(v bool)       { c.DisablePadding = v }
func (c *MasterHTTPRelayConfig) GetForceHTTP1() bool            { return c.ForceHTTP1 }
func (c *MasterHTTPRelayConfig) SetForceHTTP1(v bool)           { c.ForceHTTP1 = v }
func (c *MasterHTTPRelayConfig) GetTunnelDoH() bool             { return c.TunnelDoH }
func (c *MasterHTTPRelayConfig) SetTunnelDoH(v bool)            { c.TunnelDoH = v }
func (c *MasterHTTPRelayConfig) GetExtraDoHHosts() []string     { return c.ExtraDoHHosts }
func (c *MasterHTTPRelayConfig) SetExtraDoHHosts(v []string)    { c.ExtraDoHHosts = v }

// MasterHTTPRelayFrontingGroup defines a CDN fronting group.
// Source: config.rs FrontingGroup struct (referenced from Config).
type MasterHTTPRelayFrontingGroup struct {
	// Name is the display name for this fronting group.
	Name string
	// EdgeIP is the CDN edge IP to TLS-connect to.
	EdgeIP string
	// SNIHosts is the rotation pool of SNI values for this group.
	SNIHosts []string
	// HostHeader overrides the HTTP Host header sent to the CDN edge.
	HostHeader string
}

func (g *MasterHTTPRelayFrontingGroup) GetName() string        { return g.Name }
func (g *MasterHTTPRelayFrontingGroup) SetName(v string)       { g.Name = v }
func (g *MasterHTTPRelayFrontingGroup) GetEdgeIP() string      { return g.EdgeIP }
func (g *MasterHTTPRelayFrontingGroup) SetEdgeIP(v string)     { g.EdgeIP = v }
func (g *MasterHTTPRelayFrontingGroup) GetSNIHosts() []string  { return g.SNIHosts }
func (g *MasterHTTPRelayFrontingGroup) SetSNIHosts(v []string) { g.SNIHosts = v }
func (g *MasterHTTPRelayFrontingGroup) GetHostHeader() string  { return g.HostHeader }
func (g *MasterHTTPRelayFrontingGroup) SetHostHeader(v string) { g.HostHeader = v }
