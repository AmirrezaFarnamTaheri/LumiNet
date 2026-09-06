package mitm

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// MitmFrontingHealthMonitor manages server probes, RTT latency tracking, and swap decisions (Items 1-35)
type MitmFrontingHealthMonitor struct {
	mu                     sync.RWMutex
	ProbeIntervalDuration  time.Duration `json:"probe_interval_duration"`   // Item 1: probe frequency configuration
	ProbeTimeoutDuration   time.Duration `json:"probe_timeout_duration"`    // Item 2: probe socket timeout limit
	ProbeUrlTarget         string        `json:"probe_url_target"`          // Item 3: address target checked by health probes
	LatencyWarningLimitMs  int64         `json:"latency_warning_limit_ms"`  // Item 4: warning limit for round-trip latency
	MaxFailuresTolerance   int           `json:"max_failures_tolerance"`    // Item 5: dial failure threshold before swaps
	CurrentFailsCount      int           `json:"current_fails_count"`       // Item 6: count of failed dial attempts
	ServerCheckTimeoutMs   int           `json:"server_check_timeout_ms"`   // Item 7: limit for checking server responses
	LastCheckTimeRecord    time.Time     `json:"last_check_time_record"`    // Item 8: timestamp of last probe activity
	ActiveProbesTally      int32         `json:"active_probes_tally"`       // Item 9: number of diagnostic probes in progress
	TotalFailedProbes      uint64        `json:"total_failed_probes"`       // Item 10: total count of failed probes
	TotalSuccessfulProbes  uint64        `json:"total_successful_probes"`   // Item 11: total count of successful probes
	ProbeInterfaceBindName string        `json:"probe_interface_bind_name"` // Item 12: bind network interface for probes
	PreferredIpProtoClass  string        `json:"preferred_ip_proto_class"`  // Item 13: IP protocol priority selection (v4, v6)
	TtlVerificationSec     int           `json:"ttl_verification_sec"`      // Item 14: interval checking TTL values on probes
	TlsHandshakeLimitMs    int           `json:"tls_handshake_limit_ms"`    // Item 15: time limit allocated for handshake probe
	CongestionControlAlgo  string        `json:"congestion_control_algo"`   // Item 16: congestion algorithm name tag
	SocketMarkValue        int           `json:"socket_mark_value"`         // Item 17: packet mark applied on socket frames
	IpTOSClassBits         int           `json:"ip_tos_class_bits"`         // Item 18: TOS configuration bytes for socket
	UseTCPFastOpen         bool          `json:"use_tcp_fast_open"`         // Item 19: toggle TFO on probe sockets
	LingerDurationSec      int           `json:"linger_duration_sec"`       // Item 20: SO_LINGER value on probe sockets
	FallbackEndpointIPv4   string        `json:"fallback_endpoint_ipv4"`    // Item 21: fallback IPv4 probe address
	FallbackEndpointIPv6   string        `json:"fallback_endpoint_ipv6"`    // Item 22: fallback IPv6 probe address
	AlertsWebhookEndpoint  string        `json:"alerts_webhook_endpoint"`   // Item 23: URL endpoint receiving alert webhook
	EnableAlertsChannel    bool          `json:"enable_alerts_channel"`     // Item 24: toggle alert notifications pipeline
	MetricsCompilationRate int           `json:"metrics_compilation_rate"`  // Item 25: rate of metrics compilation in sec
	SaveStatsToFile        bool          `json:"save_stats_to_file"`        // Item 26: toggle saving statistics to file
	StatsDumpDirectory     string        `json:"stats_dump_directory"`      // Item 27: folder directory saving logs
	KeepAliveProbeSeconds  int           `json:"keep_alive_probe_seconds"`  // Item 28: TCP keepalive frequency for probe
	ZeroCopyTransferMode   bool          `json:"zero_copy_transfer_mode"`   // Item 29: toggle zero-copy operations on probe
	RateLimitQueriesMax    int           `json:"rate_limit_queries_max"`    // Item 30: limit of query checks per window
	ResolverAddressIp      string        `json:"resolver_address_ip"`       // Item 31: custom DNS server IP used in probe
	CacheEvictionSeconds   int           `json:"cache_eviction_seconds"`    // Item 32: duration before cache entries evict
	MetricsLoggerToggles   bool          `json:"metrics_logger_toggles"`    // Item 33: toggle metrics logger active
	DropInvalidFrames      bool          `json:"drop_invalid_frames"`       // Item 34: drop malformed probe response packets
	MonitorActiveState     bool          `json:"monitor_active_state"`      // Item 35: toggle status of health monitor
}

// MitmFrontingClientFingerprintConfig handles uTLS Client Hello overrides and GREASE fields (Items 36-70)
type MitmFrontingClientFingerprintConfig struct {
	mu                     sync.RWMutex
	GreaseEnabledToggles   bool     `json:"grease_enabled_toggles"`   // Item 36: toggle GREASE features in uTLS
	GreaseCipherSuites     []uint16 `json:"grease_cipher_suites"`     // Item 37: list of GREASE cipher suites
	GreaseExtensions       []uint16 `json:"grease_extensions"`        // Item 38: list of GREASE extension tags
	Ja3SignatureString     string   `json:"ja3_signature_string"`     // Item 39: target JA3 signature format string
	CurvePreferencesList   []uint16 `json:"curve_preferences_list"`   // Item 40: prioritized list of TLS curves
	SupportedVersionsList  []uint16 `json:"supported_versions_list"`  // Item 41: array of allowed TLS versions
	SessionTicketKeyBytes  [32]byte `json:"session_ticket_key_bytes"` // Item 42: session ticket encryption key
	PskIdentityValueBytes  []byte   `json:"psk_identity_value_bytes"` // Item 43: PSK identity raw bytes representation
	SniHostnameOverride    string   `json:"sni_hostname_override"`    // Item 44: target SNI string override
	AlpnNegotiationList    []string `json:"alpn_negotiation_list"`    // Item 45: list of ALPN protocol identifiers
	SignatureSchemesList   []uint16 `json:"signature_schemes_list"`   // Item 46: Priority list of signing algorithms
	KeySharesPayloadBytes  []byte   `json:"key_shares_payload_bytes"` // Item 47: pre-defined key share parameters
	CookieExtensionBytes   []byte   `json:"cookie_extension_bytes"`   // Item 48: cookie extension raw bytes payload
	EcPointFormatsBytes    []byte   `json:"ec_point_formats_bytes"`   // Item 49: supported EC point formats
	ExtendedMasterSecret   bool     `json:"extended_master_secret"`   // Item 50: enable EMS extension flag
	CompressCertAlgorithms []uint16 `json:"compress_cert_algorithms"` // Item 51: compression algorithm IDs list
	StatusRequestAsserted  bool     `json:"status_request_asserted"`  // Item 52: OCSP status request toggle
	ApplicationSettings    []string `json:"application_settings"`     // Item 53: ALPN application settings parameters
	SessionIdValueBytes    []byte   `json:"session_id_value_bytes"`   // Item 54: session identifier bytes block
	HandshakeRandomBytes   [32]byte `json:"handshake_random_bytes"`   // Item 55: raw Client Hello random bytes
	PaddingExtensionLength int      `json:"padding_extension_length"` // Item 56: length of padding extension
	DelegatedCredentials   bool     `json:"delegated_credentials"`    // Item 57: toggle delegated credentials support
	SignedCertTimestamps   []byte   `json:"signed_cert_timestamps"`   // Item 58: signed certificate timestamps payload
	EncryptedClientHello   []byte   `json:"encrypted_client_hello"`   // Item 59: ECH config payload bytes block
	CertAuthoritiesList    []string `json:"cert_authorities_list"`    // Item 60: list of certificate authorities to trust
	PostHandshakeAuth      bool     `json:"post_handshake_auth"`      // Item 61: post-handshake client auth support
	EarlyDataIndication    bool     `json:"early_data_indication"`    // Item 62: early data indication flag enabled
	RenegotiationSupport   bool     `json:"renegotiation_support"`    // Item 63: renegotiation extension toggle flag
	MaxDelayJitterMs       int      `json:"max_delay_jitter_ms"`      // Item 64: delay jitter padding threshold
	NetworkInterfaceBind   string   `json:"network_interface_bind"`   // Item 65: targeted bind interface name
	PreferIpv6Routes       bool     `json:"prefer_ipv6_routes"`       // Item 66: priority targeting IPv6 routes
	ConfigStateSignature   string   `json:"config_state_signature"`   // Item 67: hash signature of options block
	HostHeaderValue        string   `json:"host_header_value"`        // Item 68: Host header value injected
	UserAgentHeader        string   `json:"user_agent_header"`        // Item 69: User-Agent header value injected
	FingerprintConfigState bool     `json:"fingerprint_config_state"` // Item 70: toggle active status of fingerprint
}

// MitmFrontingHttp2TuningOptions configures H2 flow control settings and header parameters (Items 71-100)
type MitmFrontingHttp2TuningOptions struct {
	InitialWindowSizeBytes uint32        `json:"initial_window_size_bytes"`  // Item 71: initial flow control window size
	MaxFrameSizeBytes      uint32        `json:"max_frame_size_bytes"`       // Item 72: maximum payload size for H2 frames
	MaxConcurrentStreams   uint32        `json:"max_concurrent_streams"`     // Item 73: ceiling limit of parallel active streams
	HeaderTableSizeBytes   uint32        `json:"header_table_size_bytes"`    // Item 74: size limit of HPACK dynamic tables
	EnablePushToggles      bool          `json:"enable_push_toggles"`        // Item 75: toggle server push H2 features
	PingTimeoutDuration    time.Duration `json:"ping_timeout_duration"`      // Item 76: timeout duration verifying H2 pings
	IdleTimeoutDuration    time.Duration `json:"idle_timeout_duration"`      // Item 77: keepalive duration closing connections
	StreamPriorityWeight   byte          `json:"stream_priority_weight"`     // Item 78: weight parameter allocating stream weights
	StreamDependencyId     uint32        `json:"stream_dependency_id"`       // Item 79: parent stream identifier mappings
	HeaderHostOverride     string        `json:"header_host_override"`       // Item 80: Host header override string
	HeaderPathOverride     string        `json:"header_path_override"`       // Item 81: path query override string
	HeaderMethodOverride   string        `json:"header_method_override"`     // Item 82: method verb override string (GET/POST)
	HeaderSchemeOverride   string        `json:"header_scheme_override"`     // Item 83: scheme override string (http/https)
	HeaderAuthorityValue   string        `json:"header_authority_value"`     // Item 84: authority header value override
	HpackDynamicTableSize  uint32        `json:"hpack_dynamic_table_size"`   // Item 85: HPACK dynamic table size allocation
	SettingsFrameAckFlags  bool          `json:"settings_frame_ack_flags"`   // Item 86: SETTINGS frame ACK status indicator
	GoawayLastStreamId     uint32        `json:"goaway_last_stream_id"`      // Item 87: last stream ID in GOAWAY frames
	GoawayErrorCodeValue   uint32        `json:"goaway_error_code_value"`    // Item 88: error code returned in GOAWAY
	RstStreamErrorCode     uint32        `json:"rst_stream_error_code"`      // Item 89: error code returned in RST_STREAM
	WindowUpdateIncrement  uint32        `json:"window_update_increment"`    // Item 90: size increment in WINDOW_UPDATE
	DataFramePaddingLength uint8         `json:"data_frame_padding_length"`  // Item 91: padding bytes length inside data
	HeadersEndStreamFlags  bool          `json:"headers_end_stream_flags"`   // Item 92: end of stream indicator HEADERS
	HeadersEndHeadersFlags bool          `json:"headers_end_headers_flags"`  // Item 93: end of headers indicator HEADERS
	PriorityFrameWeightVal byte          `json:"priority_frame_weight_val"`  // Item 94: priority frame weight values
	PushPromisePromisedId  uint32        `json:"push_promise_promised_id"`   // Item 95: promised stream ID in PUSH_PROMISE
	ContinuationHeaders    []byte        `json:"continuation_headers"`       // Item 96: continuous headers buffer list
	StreamStateActive      string        `json:"stream_state_active"`        // Item 97: current state of active H2 streams
	MaxHeaderListSizeBytes uint32        `json:"max_header_list_size_bytes"` // Item 98: byte limit of decompressed H2 headers
	PingPayloadBytesVal    [8]byte       `json:"ping_payload_bytes_val"`     // Item 99: 8-byte payload sent in H2 pings
	TuningOptionsActive    bool          `json:"tuning_options_active"`      // Item 100: toggle active status of H2 tuning options
}

// PerformHealthProbe runs a single connection probe check against the target server address
func (m *MitmFrontingHealthMonitor) PerformHealthProbe(ctx context.Context, addr string) (time.Duration, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	atomic.AddInt32(&m.ActiveProbesTally, 1)
	defer atomic.AddInt32(&m.ActiveProbesTally, -1)

	startTime := time.Now()
	dialer := &net.Dialer{Timeout: m.ProbeTimeoutDuration}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		atomic.AddUint64(&m.TotalFailedProbes, 1)
		return 0, err
	}
	defer conn.Close()

	atomic.AddUint64(&m.TotalSuccessfulProbes, 1)
	elapsed := time.Since(startTime)
	return elapsed, nil
}
