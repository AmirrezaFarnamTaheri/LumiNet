package mitm

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// MitmFrontingFlowControl manages stream flow control windows, socket allocation thresholds, and buffers (Items 1-35)
type MitmFrontingFlowControl struct {
	mu                     sync.RWMutex
	InitialWindowSizeBytes int64         `json:"initial_window_size_bytes"`  // Item 1: target flow control window size
	MaxFrameSizeBytes      int           `json:"max_frame_size_bytes"`       // Item 2: maximum allowed H2 frame payload size
	MaxConcurrentStreams   int           `json:"max_concurrent_streams"`     // Item 3: ceiling cap of simultaneous active streams
	HeaderTableSizeBytes   int           `json:"header_table_size_bytes"`    // Item 4: size limit of HPACK dynamic tables
	EnablePushToggles      bool          `json:"enable_push_toggles"`        // Item 5: toggle server push H2 features
	PingTimeoutDuration    time.Duration `json:"ping_timeout_duration"`      // Item 6: timeout duration verifying H2 pings
	IdleTimeoutDuration    time.Duration `json:"idle_timeout_duration"`      // Item 7: keepalive duration closing connections
	StreamPriorityWeight   byte          `json:"stream_priority_weight"`     // Item 8: weight parameter allocating stream weights
	StreamDependencyId     uint32        `json:"stream_dependency_id"`       // Item 9: parent stream identifier mappings
	HeaderHostOverride     string        `json:"header_host_override"`       // Item 10: Host header override string
	HeaderPathOverride     string        `json:"header_path_override"`       // Item 11: path query override string
	HeaderMethodOverride   string        `json:"header_method_override"`     // Item 12: method verb override string (GET/POST)
	HeaderSchemeOverride   string        `json:"header_scheme_override"`     // Item 13: scheme override string (http/https)
	HeaderAuthorityValue   string        `json:"header_authority_value"`     // Item 14: authority header value override
	SettingsFrameAckFlags  bool          `json:"settings_frame_ack_flags"`   // Item 15: SETTINGS frame ACK status indicator
	GoawayLastStreamId     uint32        `json:"goaway_last_stream_id"`      // Item 16: last stream ID in GOAWAY frames
	GoawayErrorCodeValue   uint32        `json:"goaway_error_code_value"`    // Item 17: error code returned in GOAWAY
	RstStreamErrorCode     uint32        `json:"rst_stream_error_code"`      // Item 18: error code returned in RST_STREAM
	WindowUpdateIncrement  uint32        `json:"window_update_increment"`    // Item 19: size increment in WINDOW_UPDATE
	DataFramePaddingLength uint8         `json:"data_frame_padding_length"`  // Item 20: padding bytes length inside data
	HeadersEndStreamFlags  bool          `json:"headers_end_stream_flags"`   // Item 21: end of stream indicator HEADERS
	HeadersEndHeadersFlags bool          `json:"headers_end_headers_flags"`  // Item 22: end of headers indicator HEADERS
	PriorityFrameWeightVal byte          `json:"priority_frame_weight_val"`  // Item 23: priority frame weight values
	PushPromisePromisedId  uint32        `json:"push_promise_promised_id"`   // Item 24: promised stream ID in PUSH_PROMISE
	ContinuationHeaders    []byte        `json:"continuation_headers"`       // Item 25: continuous headers buffer list
	StreamStateActive      string        `json:"stream_state_active"`        // Item 26: current state of active H2 streams
	MaxHeaderListSizeBytes uint32        `json:"max_header_list_size_bytes"` // Item 27: byte limit of decompressed H2 headers
	PingPayloadBytesVal    [8]byte       `json:"ping_payload_bytes_val"`     // Item 28: 8-byte payload sent in H2 pings
	TuningOptionsActive    bool          `json:"tuning_options_active"`      // Item 29: toggle active status of H2 tuning options
	MaxIdleConnsPerHost    int           `json:"max_idle_conns_per_host"`    // Item 30: max idle sockets held in pool per host
	LingerDurationSecs     int           `json:"linger_duration_secs"`       // Item 31: duration of linger timeouts applied to socket
	WriteDelayLimitMs      int           `json:"write_delay_limit_ms"`       // Item 32: write-back buffer flush delay threshold
	ZeroCopyTransferMode   bool          `json:"zero_copy_transfer_mode"`    // Item 33: toggle zero-copy data routing mode
	ActiveRelayStreams     int32         `json:"active_relay_streams"`       // Item 34: active count of connected relay streams
	FlowControlActiveState bool          `json:"flow_control_active_state"`  // Item 35: toggle status of flow control subsystem
}

// MitmFrontingTLSExtensionOptions configures advanced uTLS Client Hello fields and GREASE parameters (Items 36-70)
type MitmFrontingTLSExtensionOptions struct {
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
	ExtensionConfigState   bool     `json:"extension_config_state"`   // Item 70: toggle active status of extensions
}

// MitmFrontingUpstreamValidation tracks DNS resolution pools and blacklisted subnets (Items 71-100)
type MitmFrontingUpstreamValidation struct {
	mu                      sync.RWMutex
	ResolverActiveStatus    string        `json:"resolver_active_status"`    // Item 71: current state of resolver subsystem
	TotalQueriesResolved    uint64        `json:"total_queries_resolved"`    // Item 72: total count of queries resolved successfully
	TotalQueriesBlocked     uint64        `json:"total_queries_blocked"`     // Item 73: total count of queries blocked by rules
	WorkerPoolLimitSize     int           `json:"worker_pool_limit_size"`    // Item 74: size limit of query worker pool
	JobQueueBufferLimit     int           `json:"job_queue_buffer_limit"`    // Item 75: buffer size limit of channel holding query jobs
	BootstrapResolverIp     string        `json:"bootstrap_resolver_ip"`     // Item 76: IP address of bootstrap nameserver
	BootstrapResolverPort   int           `json:"bootstrap_resolver_port"`   // Item 77: Port number of bootstrap nameserver
	DohRequestPathSuffix    string        `json:"doh_request_path_suffix"`   // Item 78: path URL for DoH queries
	DotHandshakeLimitSec    int           `json:"dot_handshake_limit_sec"`   // Item 79: TLS handshake timeout for DoT
	DnssecEnforcedToggles   bool          `json:"dnssec_enforced_toggles"`   // Item 80: enforce DNSSEC validations
	FallbackDnsEndpoint     string        `json:"fallback_dns_endpoint"`     // Item 81: IP endpoint of fallback nameserver
	QueryTimeoutLimitMs     int           `json:"query_timeout_limit_ms"`    // Item 82: duration ceiling in ms for queries
	RateLimitQueriesMax     int           `json:"rate_limit_queries_max"`    // Item 83: limit of queries per time window
	RateLimitTimeWindow     time.Duration `json:"rate_limit_time_window"`    // Item 84: time window duration for rate limits
	StrictSubdomainMatch    bool          `json:"strict_subdomain_match"`    // Item 85: toggle subdomain checking rules
	LastSpoofEventTime      time.Time     `json:"last_spoof_event_time"`     // Item 86: timestamp of last spoof detection
	TotalSpoofedAlerts      uint64        `json:"total_spoofed_alerts"`      // Item 87: total alerts triggered count
	UnexpectedSubnetsIPv4   []*net.IPNet  `json:"unexpected_subnets_ipv4"`   // Item 88: blacklisted IPv4 subnets list
	UnexpectedSubnetsIPv6   []*net.IPNet  `json:"unexpected_subnets_ipv6"`   // Item 89: blacklisted IPv6 subnets list
	DualStackPriorityTag    string        `json:"dual_stack_priority_tag"`   // Item 90: priority setting (ipv4, ipv6)
	HappyEyeballsWeight     float64       `json:"happy_eyeballs_weight"`     // Item 91: decay factor for latency checks
	VerifyDomainsStrict     bool          `json:"verify_domains_strict"`     // Item 92: strict domains string verification
	CrlVerificationStatus   int           `json:"crl_verification_status"`   // Item 93: status code from CRL checks
	OcspFallbackToggles     bool          `json:"ocsp_fallback_toggles"`     // Item 94: status representing OCSP fallbacks
	TrieNodesLimitCount     int64         `json:"trie_nodes_limit_count"`    // Item 95: total nodes inside blocklist trie
	RegexFilterLimitCount   int           `json:"regex_filter_limit_count"`  // Item 96: total active regex block rules
	WildcardRootsLimit      int           `json:"wildcard_roots_limit"`      // Item 97: total wildcard domain constraints
	CacheEvictionTimeSec    int           `json:"cache_eviction_time_sec"`   // Item 98: duration before cache entries evict
	MetricsLoggerToggles    bool          `json:"metrics_logger_toggles"`    // Item 99: toggle logger for DNS metrics
	ValidationTogglesActive bool          `json:"validation_toggles_active"` // Item 100: toggle status of validation subsystem
}

// AdjustStreamCount increments active stream counts dynamically
func (f *MitmFrontingFlowControl) AdjustStreamCount(increment int32) int32 {
	return atomic.AddInt32(&f.ActiveRelayStreams, increment)
}
