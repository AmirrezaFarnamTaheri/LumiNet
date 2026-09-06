// Package scanner implements host and dns probing operations.

package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ─── ProviderRouteReadiness ───────────────────────────────────────────────────

// ProviderRouteReadiness captures the live readiness state of a routing plugin/provider.
type ProviderRouteReadiness struct {
	ProviderID           string            `json:"provider_id"`
	RouteID              string            `json:"route_id"`
	ProtocolMode         string            `json:"protocol_mode"`
	RouteBinding         string            `json:"route_binding"`
	RouteStrategy        string            `json:"route_strategy,omitempty"`
	ConduitMode          string            `json:"conduit_mode,omitempty"`
	ProviderChain        string            `json:"provider_chain,omitempty"`
	FrontingPolicy       string            `json:"fronting_policy,omitempty"`
	LANSharing           bool              `json:"lan_sharing,omitempty"`
	BeastMode            bool              `json:"beast_mode,omitempty"`
	ReadinessState       string            `json:"readiness_state"`
	Status               string            `json:"status"`
	SOCKSPort            int               `json:"socks_port,omitempty"`
	HTTPProxyPort        int               `json:"http_proxy_port,omitempty"`
	LANSOCKSPort         int               `json:"lan_socks_port,omitempty"`
	LANHTTPProxyPort     int               `json:"lan_http_proxy_port,omitempty"`
	ExternalVPNObserved  bool              `json:"external_vpn_observed,omitempty"`
	LocalProxyObserved   bool              `json:"local_proxy_observed,omitempty"`
	DNSPolicyObserved    string            `json:"dns_policy_observed,omitempty"`
	InterfaceHint        string            `json:"interface_hint,omitempty"`
	ErrorCode            string            `json:"error_code,omitempty"`
	Evidence             map[string]string `json:"evidence,omitempty"`
	LastTransitionUnixMS int64             `json:"last_transition_unix_ms"`
}

// Getters & Setters for ProviderRouteReadiness
func (r *ProviderRouteReadiness) GetProviderID() string { return r.ProviderID }
func (r *ProviderRouteReadiness) SetProviderID(v string) { r.ProviderID = v }
func (r *ProviderRouteReadiness) GetRouteID() string { return r.RouteID }
func (r *ProviderRouteReadiness) SetRouteID(v string) { r.RouteID = v }
func (r *ProviderRouteReadiness) GetProtocolMode() string { return r.ProtocolMode }
func (r *ProviderRouteReadiness) SetProtocolMode(v string) { r.ProtocolMode = v }
func (r *ProviderRouteReadiness) GetRouteBinding() string { return r.RouteBinding }
func (r *ProviderRouteReadiness) SetRouteBinding(v string) { r.RouteBinding = v }
func (r *ProviderRouteReadiness) GetRouteStrategy() string { return r.RouteStrategy }
func (r *ProviderRouteReadiness) SetRouteStrategy(v string) { r.RouteStrategy = v }
func (r *ProviderRouteReadiness) GetConduitMode() string { return r.ConduitMode }
func (r *ProviderRouteReadiness) SetConduitMode(v string) { r.ConduitMode = v }
func (r *ProviderRouteReadiness) GetFrontingPolicy() string { return r.FrontingPolicy }
func (r *ProviderRouteReadiness) SetFrontingPolicy(v string) { r.FrontingPolicy = v }
func (r *ProviderRouteReadiness) GetLANSharing() bool { return r.LANSharing }
func (r *ProviderRouteReadiness) SetLANSharing(v bool) { r.LANSharing = v }
func (r *ProviderRouteReadiness) GetBeastMode() bool { return r.BeastMode }
func (r *ProviderRouteReadiness) SetBeastMode(v bool) { r.BeastMode = v }
func (r *ProviderRouteReadiness) GetReadinessState() string { return r.ReadinessState }
func (r *ProviderRouteReadiness) SetReadinessState(v string) { r.ReadinessState = v }
func (r *ProviderRouteReadiness) GetStatus() string { return r.Status }
func (r *ProviderRouteReadiness) SetStatus(v string) { r.Status = v }
func (r *ProviderRouteReadiness) GetSOCKSPort() int { return r.SOCKSPort }
func (r *ProviderRouteReadiness) SetSOCKSPort(v int) { r.SOCKSPort = v }
func (r *ProviderRouteReadiness) GetHTTPProxyPort() int { return r.HTTPProxyPort }
func (r *ProviderRouteReadiness) SetHTTPProxyPort(v int) { r.HTTPProxyPort = v }
func (r *ProviderRouteReadiness) GetLANSOCKSPort() int { return r.LANSOCKSPort }
func (r *ProviderRouteReadiness) SetLANSOCKSPort(v int) { r.LANSOCKSPort = v }
func (r *ProviderRouteReadiness) GetLANHTTPProxyPort() int { return r.LANHTTPProxyPort }
func (r *ProviderRouteReadiness) SetLANHTTPProxyPort(v int) { r.LANHTTPProxyPort = v }
func (r *ProviderRouteReadiness) GetExternalVPNObserved() bool { return r.ExternalVPNObserved }
func (r *ProviderRouteReadiness) SetExternalVPNObserved(v bool) { r.ExternalVPNObserved = v }
func (r *ProviderRouteReadiness) GetLocalProxyObserved() bool { return r.LocalProxyObserved }
func (r *ProviderRouteReadiness) SetLocalProxyObserved(v bool) { r.LocalProxyObserved = v }
func (r *ProviderRouteReadiness) GetDNSPolicyObserved() string { return r.DNSPolicyObserved }
func (r *ProviderRouteReadiness) SetDNSPolicyObserved(v string) { r.DNSPolicyObserved = v }
func (r *ProviderRouteReadiness) GetInterfaceHint() string { return r.InterfaceHint }
func (r *ProviderRouteReadiness) SetInterfaceHint(v string) { r.InterfaceHint = v }
func (r *ProviderRouteReadiness) GetErrorCode() string { return r.ErrorCode }
func (r *ProviderRouteReadiness) SetErrorCode(v string) { r.ErrorCode = v }
func (r *ProviderRouteReadiness) GetEvidence() map[string]string { return r.Evidence }
func (r *ProviderRouteReadiness) SetEvidence(v map[string]string) { r.Evidence = v }
func (r *ProviderRouteReadiness) GetLastTransitionUnixMS() int64 { return r.LastTransitionUnixMS }
func (r *ProviderRouteReadiness) SetLastTransitionUnixMS(v int64) { r.LastTransitionUnixMS = v }
func (r *ProviderRouteReadiness) GetProviderChain() string { return r.ProviderChain }
func (r *ProviderRouteReadiness) SetProviderChain(v string) { r.ProviderChain = v }

// Builders for ProviderRouteReadiness
func (r *ProviderRouteReadiness) WithProviderID(v string) *ProviderRouteReadiness { r.SetProviderID(v); return r }
func (r *ProviderRouteReadiness) WithRouteID(v string) *ProviderRouteReadiness { r.SetRouteID(v); return r }
func (r *ProviderRouteReadiness) WithProtocolMode(v string) *ProviderRouteReadiness { r.SetProtocolMode(v); return r }
func (r *ProviderRouteReadiness) WithReadinessState(v string) *ProviderRouteReadiness { r.SetReadinessState(v); return r }
func (r *ProviderRouteReadiness) WithStatus(v string) *ProviderRouteReadiness { r.SetStatus(v); return r }

// IsReady returns true if the provider is in a usable state.
func (r *ProviderRouteReadiness) IsReady() bool {
	return r.Status == "success" && (r.SOCKSPort > 0 || r.HTTPProxyPort > 0 || r.ReadinessState == "probe_passed")
}

// SetEvidenceField sets a single field in the evidence map (initialising it if nil).
func (r *ProviderRouteReadiness) SetEvidenceField(key, value string) {
	if r.Evidence == nil {
		r.Evidence = map[string]string{}
	}
	r.Evidence[key] = value
}

// ─── PsiphonNoticeParser ──────────────────────────────────────────────────────

// PsiphonNoticeParser parses JSON and text notice lines from a Psiphon tunnel_core process.
type PsiphonNoticeParser struct {
	readiness ProviderRouteReadiness
}

func NewPsiphonNoticeParser(routeID string) *PsiphonNoticeParser {
	return &PsiphonNoticeParser{readiness: ProviderRouteReadiness{
		ProviderID:           "psiphon",
		RouteID:              routeID,
		ProtocolMode:         "tunnel_core_supervised",
		RouteBinding:         "tunnel_core_local_proxy",
		RouteStrategy:        "auto",
		ConduitMode:          "auto",
		ReadinessState:       "starting",
		Status:               "starting",
		Evidence:             map[string]string{},
		LastTransitionUnixMS: time.Now().UnixMilli(),
	}}
}

// ParseLine processes a single line from the Psiphon notice stream.
// Maps to upstream ParseLine().
func (p *PsiphonNoticeParser) ParseLine(line string) ProviderRouteReadiness {
	line = strings.TrimSpace(line)
	if p.readiness.Evidence == nil {
		p.readiness.Evidence = map[string]string{}
	}
	p.readiness.LastTransitionUnixMS = time.Now().UnixMilli()
	if containsCRLFSeq(line) {
		p.readiness.Status = "failed"
		p.readiness.ReadinessState = "failed"
		p.readiness.ErrorCode = "INPUT_INVALID"
		return p.readiness
	}
	if strings.HasPrefix(line, "{") {
		var notice map[string]any
		if err := json.Unmarshal([]byte(line), &notice); err == nil {
			p.applyPsiphonNoticeMap(notice)
			return p.readiness
		}
	}
	p.applyPsiphonNoticeText(line)
	return p.readiness
}

// GetReadiness returns the current readiness state snapshot.
func (p *PsiphonNoticeParser) GetReadiness() ProviderRouteReadiness {
	return p.readiness
}

func (p *PsiphonNoticeParser) applyPsiphonNoticeMap(notice map[string]any) {
	for key, value := range notice {
		switch strings.ToLower(key) {
		case "listeningsocksproxyport", "listening_socks_proxy_port", "socks_port":
			p.readiness.SOCKSPort = intFromAny(value)
		case "listeninghttpproxyport", "listening_http_proxy_port", "http_proxy_port":
			p.readiness.HTTPProxyPort = intFromAny(value)
		case "event_name", "notice_type", "type":
			p.readiness.Evidence["last_notice"] = fmt.Sprint(value)
		case "tunnels", "tunnels.count":
			p.readiness.Evidence["tunnels"] = fmt.Sprint(value)
		case "shareproxyonnetwork", "share_proxy_on_network", "lan_sharing":
			p.readiness.LANSharing = boolFromAny(value)
		case "shareproxyonnetworksocksport", "lan_socks_port":
			p.readiness.LANSOCKSPort = intFromAny(value)
		case "shareproxyonnetworkhttpport", "lan_http_proxy_port":
			p.readiness.LANHTTPProxyPort = intFromAny(value)
		case "protocolselection", "route_strategy":
			p.readiness.RouteStrategy = strings.ToLower(fmt.Sprint(value))
		case "conduitmode", "conduit_mode":
			p.readiness.ConduitMode = strings.ToLower(fmt.Sprint(value))
		case "beastmode", "beast_mode":
			p.readiness.BeastMode = boolFromAny(value)
		}
	}
	p.updatePsiphonReady()
}

func (p *PsiphonNoticeParser) applyPsiphonNoticeText(line string) {
	lower := strings.ToLower(line)
	p.readiness.Evidence["last_notice"] = truncateEvidence(line, 180)
	for _, token := range strings.FieldsFunc(line, func(r rune) bool {
		return r == ' ' || r == ',' || r == ';'
	}) {
		parts := strings.SplitN(token, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.Trim(parts[0], `"'`))
		value := strings.Trim(parts[1], `"'`)
		switch key {
		case "listeningsocksproxyport", "socks_port":
			p.readiness.SOCKSPort, _ = strconv.Atoi(value)
		case "listeninghttpproxyport", "http_proxy_port":
			p.readiness.HTTPProxyPort, _ = strconv.Atoi(value)
		case "shareproxyonnetwork", "lan_sharing":
			p.readiness.LANSharing = strings.EqualFold(value, "true")
		case "shareproxyonnetworksocksport", "lan_socks_port":
			p.readiness.LANSOCKSPort, _ = strconv.Atoi(value)
		case "shareproxyonnetworkhttpport", "lan_http_proxy_port":
			p.readiness.LANHTTPProxyPort, _ = strconv.Atoi(value)
		}
	}
	if strings.Contains(lower, "conduit") {
		p.readiness.RouteStrategy = "conduit"
	}
	if strings.Contains(lower, "cdn_fronting") || strings.Contains(lower, "fronting") {
		p.readiness.FrontingPolicy = "cdn_fronting"
	}
	if strings.Contains(lower, "beast") {
		p.readiness.BeastMode = true
	}
	if strings.Contains(lower, "tunnel") || strings.Contains(lower, "listening") {
		p.updatePsiphonReady()
	}
}

func (p *PsiphonNoticeParser) updatePsiphonReady() {
	if p.readiness.SOCKSPort > 0 || p.readiness.HTTPProxyPort > 0 {
		p.readiness.ReadinessState = "proxy_listening"
		p.readiness.Status = "success"
		p.readiness.ErrorCode = ""
		return
	}
	p.readiness.ReadinessState = "starting"
	p.readiness.Status = "starting"
}

// ParsePsiphonNoticeStream reads an entire Psiphon notice stream and returns the final state.
// Maps to upstream ParsePsiphonNoticeStream().
func ParsePsiphonNoticeStream(routeID string, reader io.Reader) (ProviderRouteReadiness, error) {
	parser := NewPsiphonNoticeParser(routeID)
	sc := bufio.NewScanner(reader)
	sc.Buffer(make([]byte, 0, 4096), 1024*1024)
	var state ProviderRouteReadiness
	for sc.Scan() {
		state = parser.ParseLine(sc.Text())
	}
	if err := sc.Err(); err != nil {
		return state, err
	}
	return state, nil
}

// ─── ConnectivitySnapshot ────────────────────────────────────────────────────

// ConnectivitySnapshotter captures live system network connectivity.
type ConnectivitySnapshotter interface {
	Snapshot(ctx context.Context) (ConnectivitySnapshot, error)
}

// ConnectivitySnapshot holds a point-in-time snapshot of system network state.
type ConnectivitySnapshot struct {
	ExternalIP       string
	DNSResolvers     []string
	Interfaces       []string
	DefaultInterface string
	HTTPProxy        string
	SOCKSProxy       string
}

// Getters & Setters for ConnectivitySnapshot
func (c *ConnectivitySnapshot) GetExternalIP() string { return c.ExternalIP }
func (c *ConnectivitySnapshot) SetExternalIP(v string) { c.ExternalIP = v }
func (c *ConnectivitySnapshot) GetDNSResolvers() []string { return c.DNSResolvers }
func (c *ConnectivitySnapshot) SetDNSResolvers(v []string) { c.DNSResolvers = v }
func (c *ConnectivitySnapshot) GetInterfaces() []string { return c.Interfaces }
func (c *ConnectivitySnapshot) SetInterfaces(v []string) { c.Interfaces = v }
func (c *ConnectivitySnapshot) GetDefaultInterface() string { return c.DefaultInterface }
func (c *ConnectivitySnapshot) SetDefaultInterface(v string) { c.DefaultInterface = v }
func (c *ConnectivitySnapshot) GetHTTPProxy() string { return c.HTTPProxy }
func (c *ConnectivitySnapshot) SetHTTPProxy(v string) { c.HTTPProxy = v }
func (c *ConnectivitySnapshot) GetSOCKSProxy() string { return c.SOCKSProxy }
func (c *ConnectivitySnapshot) SetSOCKSProxy(v string) { c.SOCKSProxy = v }

// staticConnectivitySnapshotter provides a fixed connectivity state for testing.
type staticConnectivitySnapshotter struct {
	snapshot ConnectivitySnapshot
	err      error
}

func (s staticConnectivitySnapshotter) Snapshot(context.Context) (ConnectivitySnapshot, error) {
	return s.snapshot, s.err
}

// NewStaticConnectivitySnapshotter creates a fixed-snapshot connectivity implementation.
func NewStaticConnectivitySnapshotter(snap ConnectivitySnapshot, err error) ConnectivitySnapshotter {
	return staticConnectivitySnapshotter{snapshot: snap, err: err}
}

// ObserveDNSPolicy compares baseline and current snapshots to determine DNS policy.
// Maps to upstream observeDNSPolicy().
func ObserveDNSPolicy(dnsPolicyCfg string, baseline, current ConnectivitySnapshot) string {
	if dnsPolicyCfg == "no_dns" {
		return "no_dns"
	}
	if !StringSlicesEqual(baseline.DNSResolvers, current.DNSResolvers) {
		return dnsPolicyCfg
	}
	return "system_or_route_default"
}

// ProbeLocalHTTPProxy dials a local HTTP proxy endpoint and returns readiness.
// Maps to upstream ProbeLocalHTTPProxy().
func ProbeLocalHTTPProxy(ctx context.Context, endpoint string, timeout time.Duration) ProviderRouteReadiness {
	start := time.Now()
	state := ProviderRouteReadiness{
		ProviderID:           "windscribe",
		RouteBinding:         "local_proxy_gateway",
		ReadinessState:       "not_checked",
		Status:               "failed",
		LastTransitionUnixMS: time.Now().UnixMilli(),
	}
	if err := validateProxyEndpointURL(endpoint); err != nil {
		state.ErrorCode = "INPUT_INVALID"
		return state
	}
	parsed, _ := url.Parse(endpoint)
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", parsed.Host)
	if err != nil {
		state.ErrorCode = "PROXY_TIMEOUT"
		return state
	}
	_ = conn.Close()
	state.LocalProxyObserved = true
	state.ReadinessState = "proxy_listening"
	state.Status = "success"
	state.Evidence = map[string]string{"latency_ms": strconv.FormatInt(time.Since(start).Milliseconds(), 10)}
	return state
}

// validateProxyEndpointURL validates a proxy URL string for safety.
func validateProxyEndpointURL(endpoint string) error {
	if strings.TrimSpace(endpoint) == "" {
		return fmt.Errorf("empty proxy endpoint")
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("invalid proxy URL: %w", err)
	}
	if u.Host == "" {
		return fmt.Errorf("missing proxy host")
	}
	if containsCRLFSeq(endpoint) {
		return fmt.Errorf("proxy endpoint contains CRLF sequence")
	}
	return nil
}

// ─── utility helpers ──────────────────────────────────────────────────────────

// intFromAny converts interface{} values to int.
// Maps to upstream intFromAny().
func intFromAny(value any) int {
	switch v := value.(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		n, _ := strconv.Atoi(v)
		return n
	default:
		return 0
	}
}

// boolFromAny converts interface{} values to bool.
// Maps to upstream boolFromAny().
func boolFromAny(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(strings.TrimSpace(v), "true")
	default:
		return false
	}
}

// truncateEvidence truncates a string to a given byte limit.
// Maps to upstream truncateEvidence().
func truncateEvidence(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

// StringSlicesEqual checks if two string slices have identical contents in order.
// Maps to upstream stringSlicesEqual().
func StringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// containsCRLFSeq returns true if the string contains CR or LF characters.
func containsCRLFSeq(s string) bool {
	return strings.ContainsAny(s, "\r\n")
}

// ─── SpeedtestRequest / SpeedtestResponse ────────────────────────────────────

// SpeedtestRequest specifies inputs for the speedtest.
type SpeedtestRequest struct {
	URL            string `json:"url,omitempty"`
	Bytes          int    `json:"bytes,omitempty"`
	Proxy          string `json:"proxy,omitempty"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
}

// Getters & Setters for SpeedtestRequest
func (s *SpeedtestRequest) GetURL() string { return s.URL }
func (s *SpeedtestRequest) SetURL(v string) { s.URL = v }
func (s *SpeedtestRequest) GetBytes() int { return s.Bytes }
func (s *SpeedtestRequest) SetBytes(v int) { s.Bytes = v }
func (s *SpeedtestRequest) GetProxy() string { return s.Proxy }
func (s *SpeedtestRequest) SetProxy(v string) { s.Proxy = v }
func (s *SpeedtestRequest) GetTimeoutSeconds() int { return s.TimeoutSeconds }
func (s *SpeedtestRequest) SetTimeoutSeconds(v int) { s.TimeoutSeconds = v }

// SpeedtestResponse contains the metrics computed during the speedtest.
type SpeedtestResponse struct {
	Success             bool    `json:"success"`
	DownloadSpeedMbps   float64 `json:"download_speed_mbps"`
	DownloadTimeSeconds float64 `json:"download_time_seconds"`
	TotalTimeSeconds    float64 `json:"total_time_seconds"`
	ServerTimingSeconds float64 `json:"server_timing_seconds"`
	Error               string  `json:"error,omitempty"`
}

// Getters & Setters for SpeedtestResponse
func (s *SpeedtestResponse) GetSuccess() bool { return s.Success }
func (s *SpeedtestResponse) SetSuccess(v bool) { s.Success = v }
func (s *SpeedtestResponse) GetDownloadSpeedMbps() float64 { return s.DownloadSpeedMbps }
func (s *SpeedtestResponse) SetDownloadSpeedMbps(v float64) { s.DownloadSpeedMbps = v }
func (s *SpeedtestResponse) GetDownloadTimeSeconds() float64 { return s.DownloadTimeSeconds }
func (s *SpeedtestResponse) SetDownloadTimeSeconds(v float64) { s.DownloadTimeSeconds = v }
func (s *SpeedtestResponse) GetTotalTimeSeconds() float64 { return s.TotalTimeSeconds }
func (s *SpeedtestResponse) SetTotalTimeSeconds(v float64) { s.TotalTimeSeconds = v }
func (s *SpeedtestResponse) GetServerTimingSeconds() float64 { return s.ServerTimingSeconds }
func (s *SpeedtestResponse) SetServerTimingSeconds(v float64) { s.ServerTimingSeconds = v }
func (s *SpeedtestResponse) GetError() string { return s.Error }
func (s *SpeedtestResponse) SetError(v string) { s.Error = v }

// ParseServerTiming extracts the dur= value from a Server-Timing header (in seconds).
// Maps to upstream parseServerTiming().
func ParseServerTiming(header string) float64 {
	if header == "" {
		return 0
	}
	parts := strings.Split(header, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "dur=") {
			valStr := strings.TrimPrefix(part, "dur=")
			if val, err := strconv.ParseFloat(valStr, 64); err == nil {
				return val / 1000.0 // convert ms to seconds
			}
		}
	}
	// Fallback to simple split by '=' for backward compatibility
	if idx := strings.Index(header, "="); idx != -1 {
		valStr := strings.TrimSpace(header[idx+1:])
		if val, err := strconv.ParseFloat(valStr, 64); err == nil {
			return val / 1000.0
		}
	}
	return 0
}

// RunSpeedtest performs an HTTP download speedtest against the given request parameters.
// Maps to upstream runSpeedtestHandler() minus HTTP handler boilerplate.
func RunSpeedtest(req SpeedtestRequest) SpeedtestResponse {
	if req.URL == "" {
		req.URL = "https://speed.cloudflare.com/__down"
	}
	if req.Bytes <= 0 {
		req.Bytes = 1024 * 1024 // default 1MB
	}
	if req.TimeoutSeconds <= 0 {
		req.TimeoutSeconds = 15
	}

	var proxyURL *url.URL
	if req.Proxy != "" {
		var err error
		proxyURL, err = url.Parse(req.Proxy)
		if err != nil {
			return SpeedtestResponse{Success: false, Error: fmt.Sprintf("invalid proxy URL: %v", err)}
		}
	}

	httpReq, err := http.NewRequest("GET", req.URL, nil)
	if err != nil {
		return SpeedtestResponse{Success: false, Error: fmt.Sprintf("failed to create http request: %v", err)}
	}

	u, err := url.Parse(req.URL)
	if err == nil && u.Host == "speed.cloudflare.com" {
		q := httpReq.URL.Query()
		q.Set("bytes", strconv.Itoa(req.Bytes))
		httpReq.URL.RawQuery = q.Encode()
	} else {
		httpReq.Header.Set("Range", fmt.Sprintf("bytes=0-%d", req.Bytes-1))
	}
	httpReq.Header.Set("User-Agent", "LumiNet/Speedtest")

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(req.TimeoutSeconds) * time.Second,
	}

	startTime := time.Now()
	resp, err := client.Do(httpReq)
	if err != nil {
		return SpeedtestResponse{Success: false, Error: fmt.Sprintf("http request failed: %v", err)}
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return SpeedtestResponse{Success: false, Error: fmt.Sprintf("unexpected response status: %s", resp.Status)}
	}

	buffer := make([]byte, 32*1024)
	var totalRead int64
	for {
		n, readErr := resp.Body.Read(buffer)
		totalRead += int64(n)
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return SpeedtestResponse{Success: false, Error: fmt.Sprintf("error reading response body: %v", readErr)}
		}
	}

	totalTime := time.Since(startTime).Seconds()
	serverTimingSeconds := ParseServerTiming(resp.Header.Get("Server-Timing"))
	downloadTime := totalTime - serverTimingSeconds
	if downloadTime <= 0 {
		downloadTime = totalTime
		if downloadTime <= 0 {
			downloadTime = 0.001
		}
	}
	downloadSpeedMbps := (float64(totalRead) * 8.0) / (downloadTime * 1000000.0)

	return SpeedtestResponse{
		Success:             true,
		DownloadSpeedMbps:   downloadSpeedMbps,
		DownloadTimeSeconds: downloadTime,
		TotalTimeSeconds:    totalTime,
		ServerTimingSeconds: serverTimingSeconds,
	}
}
