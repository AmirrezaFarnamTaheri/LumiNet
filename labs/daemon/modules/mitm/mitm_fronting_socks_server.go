package mitm

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// MitmFrontingSocksServer configures SOCKS5 listeners and auth settings (Items 1-35)
type MitmFrontingSocksServer struct {
	mu                       sync.RWMutex
	Socks5UsernameStr        string    `json:"socks5_username_str"`         // Item 1: SOCKS5 auth username credential
	Socks5PasswordStr        string    `json:"socks5_password_str"`         // Item 2: SOCKS5 auth password credential
	ListenBindAddress        string    `json:"listen_bind_address"`         // Item 3: bind address string for SOCKS5 server
	ListenBindPortNumber     int       `json:"listen_bind_port_number"`     // Item 4: port number SOCKS5 server listens on
	AuthMethodSupported      []byte    `json:"auth_method_supported"`       // Item 5: supported auth methods (no-auth, user-pass)
	TlsEnabledForSocks       bool      `json:"tls_enabled_for_socks"`       // Item 6: toggle SOCKS5 over TLS option
	TlsServerNameString      string    `json:"tls_server_name_string"`      // Item 7: ServerName verified on TLS handshakes
	TlsConfigOptionBlock     []byte    `json:"tls_config_option_block"`     // Item 8: serialization options for TLS configs
	MaxConcurrentClients     int       `json:"max_concurrent_clients"`      // Item 9: ceiling limit of parallel client sessions
	SessionTimeoutSeconds    int       `json:"session_timeout_seconds"`     // Item 10: duration before closing idle client sessions
	KeepAliveProbeToggles    bool      `json:"keep_alive_probe_toggles"`    // Item 11: TCP keepalive enabled on SOCKS5 sockets
	LingerCloseSecValue      int       `json:"linger_close_sec_value"`      // Item 12: linger close timeout for clients
	IpTOSClassBitsSetting    int       `json:"ip_tos_class_bits_setting"`   // Item 13: TOS configuration bytes for SOCKS5 sockets
	BbrCongestionActive      bool      `json:"bbr_congestion_active"`       // Item 14: BBR socket congestion control toggle
	OutboundSocketMarkVal    int       `json:"outbound_socket_mark_val"`    // Item 15: packet mark value applied on outbound dials
	BindInterfaceNameStr     string    `json:"bind_interface_name_str"`     // Item 16: targeted network bind interface name
	PreferIpv6DialsOption    bool      `json:"prefer_ipv6_dials_option"`    // Item 17: priority targeting IPv6 route lookups
	PROXYProtocolHeadersOk   bool      `json:"proxy_protocol_headers_ok"`   // Item 18: toggle parsing PROXY protocol headers
	BypassSubnetsRegistry    []string  `json:"bypass_subnets_registry"`     // Item 19: local subnet CIDR blocks bypassing SOCKS5
	DynamicHostsOverride     []string  `json:"dynamic_hosts_override"`      // Item 20: custom DNS hostname mappings list
	LatenciesTargetMaps      []int64   `json:"latencies_target_maps"`       // Item 21: tracked latencies for outbound endpoints
	MetricsCompilationOk     bool      `json:"metrics_compilation_ok"`      // Item 22: toggle metrics collection for SOCKS5
	ResolverAddressString    string    `json:"resolver_address_string"`     // Item 23: custom resolver server target IP
	SubdomainMatchToggles    bool      `json:"subdomain_match_toggles"`     // Item 24: toggle subdomain wildcard blocking
	TotalFailedDialsCount    uint64    `json:"total_failed_dials_count"`    // Item 25: total failed dial attempts from SOCKS5
	TotalSuccessfulDials     uint64    `json:"total_successful_dials"`      // Item 26: total successful dials from SOCKS5
	ActiveClientSessions     int32     `json:"active_client_sessions"`      // Item 27: active count of connected SOCKS5 clients
	StatsDumpDirectoryPath   string    `json:"stats_dump_directory_path"`   // Item 28: folder path saving stats logs
	StatsDumpIntervalMinutes int       `json:"stats_dump_interval_minutes"` // Item 29: interval writing stats to file paths
	MaxLatencyCeilingSec     int       `json:"max_latency_ceiling_sec"`     // Item 30: latency average ceiling threshold
	DisconnectTimerSeconds   int       `json:"disconnect_timer_seconds"`    // Item 31: time duration before disconnecting slow SOCKS
	AlertWebhookPathUrlStr   string    `json:"alert_webhook_path_url_str"`  // Item 32: URL receiving SOCKS5 webhook warnings
	AlertsActiveIndicator    bool      `json:"alerts_active_indicator"`     // Item 33: toggle alerts notification channel
	LastActivityTimestamp    time.Time `json:"last_activity_timestamp"`     // Item 34: timestamp of latest client packet exchange
	Socks5ActiveIndicator    bool      `json:"socks5_active_indicator"`     // Item 35: toggle active status of SOCKS5 server
}

// MitmFrontingHttpTunnel configures HTTP CONNECT listeners and header tuning (Items 36-70)
type MitmFrontingHttpTunnel struct {
	HttpProxyUsernameStr     string   `json:"http_proxy_username_str"`     // Item 36: HTTP CONNECT proxy username
	HttpProxyPasswordStr     string   `json:"http_proxy_password_str"`     // Item 37: HTTP CONNECT proxy password
	ListenBindAddressStr     string   `json:"listen_bind_address_str"`     // Item 38: bind address string for HTTP tunnel
	ListenBindPortNumber     int      `json:"listen_bind_port_number"`     // Item 39: port number HTTP tunnel listens on
	TlsEnabledForHttp        bool     `json:"tls_enabled_for_http"`        // Item 40: toggle HTTP tunnel over TLS option
	TlsServerNameString      string   `json:"tls_server_name_string"`      // Item 41: ServerName verified on TLS handshakes
	MaxConcurrentClients     int      `json:"max_concurrent_clients"`      // Item 42: ceiling limit of parallel client sessions
	SessionTimeoutSeconds    int      `json:"session_timeout_seconds"`     // Item 43: duration before closing idle client sessions
	KeepAliveProbeToggles    bool     `json:"keep_alive_probe_toggles"`    // Item 44: TCP keepalive enabled on HTTP sockets
	LingerCloseSecValue      int      `json:"linger_close_sec_value"`      // Item 45: linger close timeout for clients
	IpTOSClassBitsSetting    int      `json:"ip_tos_class_bits_setting"`   // Item 46: TOS configuration bytes for HTTP sockets
	BbrCongestionActive      bool     `json:"bbr_congestion_active"`       // Item 47: BBR socket congestion control toggle
	OutboundSocketMarkVal    int      `json:"outbound_socket_mark_val"`    // Item 48: packet mark value applied on outbound dials
	BindInterfaceNameStr     string   `json:"bind_interface_name_str"`     // Item 49: targeted network bind interface name
	PreferIpv6DialsOption    bool     `json:"prefer_ipv6_dials_option"`    // Item 50: priority targeting IPv6 route lookups
	PROXYProtocolHeadersOk   bool     `json:"proxy_protocol_headers_ok"`   // Item 51: toggle parsing PROXY protocol headers
	BypassSubnetsRegistry    []string `json:"bypass_subnets_registry"`     // Item 52: local subnet CIDR blocks bypassing tunnel
	DynamicHostsOverride     []string `json:"dynamic_hosts_override"`      // Item 53: custom DNS hostname mappings list
	LatenciesTargetMaps      []int64  `json:"latencies_target_maps"`       // Item 54: tracked latencies for outbound endpoints
	MetricsCompilationOk     bool     `json:"metrics_compilation_ok"`      // Item 55: toggle metrics collection for tunnel
	ResolverAddressString    string   `json:"resolver_address_string"`     // Item 56: custom resolver server target IP
	SubdomainMatchToggles    bool     `json:"subdomain_match_toggles"`     // Item 57: toggle subdomain wildcard blocking
	TotalFailedDialsCount    uint64   `json:"total_failed_dials_count"`    // Item 58: total failed dial attempts from tunnel
	TotalSuccessfulDials     uint64   `json:"total_successful_dials"`      // Item 59: total successful dials from tunnel
	ActiveClientSessions     int32    `json:"active_client_sessions"`      // Item 60: active count of connected tunnel clients
	StatsDumpDirectoryPath   string   `json:"stats_dump_directory_path"`   // Item 61: folder path saving stats logs
	StatsDumpIntervalMinutes int      `json:"stats_dump_interval_minutes"` // Item 62: interval writing stats to file paths
	DisconnectTimerSeconds   int      `json:"disconnect_timer_seconds"`    // Item 63: time duration before disconnecting slow HTTP
	AlertsActiveIndicator    bool     `json:"alerts_active_indicator"`     // Item 64: toggle alerts notification channel
	HttpTunnelActiveState    bool     `json:"http_tunnel_active_state"`    // Item 65: toggle active status of HTTP tunnel
	WriteBufferCapacity      int      `json:"write_buffer_capacity"`       // Item 66: write buffer limit size allocated
	ReadBufferCapacity       int      `json:"read_buffer_capacity"`        // Item 67: read buffer limit size allocated
	BufferGrowingFactor      int      `json:"buffer_growing_factor"`       // Item 68: multiplication factor resizing slices
	FlushTimeoutLimitMs      int      `json:"flush_timeout_limit_ms"`      // Item 69: timeout flushing dirty data buffers
	FlushOperationsCount     uint64   `json:"flush_operations_count"`      // Item 70: count of flush operations executed
}

// MitmFrontingTunnelActiveStatus configures active client status limits and stats alerts (Items 71-100)
type MitmFrontingTunnelActiveStatus struct {
	mu                    sync.RWMutex
	TotalQueriesResolved  uint64        `json:"total_queries_resolved"`   // Item 71: total count of queries resolved successfully
	TotalQueriesBlocked   uint64        `json:"total_queries_blocked"`    // Item 72: total count of queries blocked by rules
	WorkerPoolLimitSize   int           `json:"worker_pool_limit_size"`   // Item 73: size limit of query worker pool
	JobQueueBufferLimit   int           `json:"job_queue_buffer_limit"`   // Item 74: buffer size limit of channel holding query jobs
	BootstrapResolverIp   string        `json:"bootstrap_resolver_ip"`    // Item 75: IP address of bootstrap nameserver
	BootstrapResolverPort int           `json:"bootstrap_resolver_port"`  // Item 76: Port number of bootstrap nameserver
	DohRequestPathSuffix  string        `json:"doh_request_path_suffix"`  // Item 77: path URL for DoH queries
	DotHandshakeLimitSec  int           `json:"dot_handshake_limit_sec"`  // Item 78: TLS handshake timeout for DoT
	DnssecEnforcedToggles bool          `json:"dnssec_enforced_toggles"`  // Item 79: enforce DNSSEC validations
	FallbackDnsEndpoint   string        `json:"fallback_dns_endpoint"`    // Item 80: IP endpoint of fallback nameserver
	QueryTimeoutLimitMs   int           `json:"query_timeout_limit_ms"`   // Item 81: duration ceiling in ms for queries
	RateLimitQueriesMax   int           `json:"rate_limit_queries_max"`   // Item 82: limit of queries per time window
	RateLimitTimeWindow   time.Duration `json:"rate_limit_time_window"`   // Item 83: time window duration for rate limits
	StrictSubdomainMatch  bool          `json:"strict_subdomain_match"`   // Item 84: toggle subdomain checking rules
	LastSpoofEventTime    time.Time     `json:"last_spoof_event_time"`    // Item 85: timestamp of last spoof detection
	TotalSpoofedAlerts    uint64        `json:"total_spoofed_alerts"`     // Item 86: total alerts triggered count
	UnexpectedSubnetsIPv4 []*net.IPNet  `json:"unexpected_subnets_ipv4"`  // Item 87: blacklisted IPv4 subnets list
	UnexpectedSubnetsIPv6 []*net.IPNet  `json:"unexpected_subnets_ipv6"`  // Item 88: blacklisted IPv6 subnets list
	DualStackPriorityTag  string        `json:"dual_stack_priority_tag"`  // Item 89: priority setting (ipv4, ipv6)
	HappyEyeballsWeight   float64       `json:"happy_eyeballs_weight"`    // Item 90: decay factor for latency checks
	VerifyDomainsStrict   bool          `json:"verify_domains_strict"`    // Item 91: strict domains string verification
	CrlVerificationStatus int           `json:"crl_verification_status"`  // Item 92: status code from CRL checks
	OcspFallbackToggles   bool          `json:"ocsp_fallback_toggles"`    // Item 93: status representing OCSP fallbacks
	TrieNodesLimitCount   int64         `json:"trie_nodes_limit_count"`   // Item 94: total nodes inside blocklist trie
	RegexFilterLimitCount int           `json:"regex_filter_limit_count"` // Item 95: total active regex block rules
	WildcardRootsLimit    int           `json:"wildcard_roots_limit"`     // Item 96: total wildcard domain constraints
	CacheEvictionTimeSec  int           `json:"cache_eviction_time_sec"`  // Item 97: duration before cache entries evict
	MetricsLoggerToggles  bool          `json:"metrics_logger_toggles"`   // Item 98: toggle logger for DNS metrics
	DropInvalidDnsFrames  bool          `json:"drop_invalid_dns_frames"`  // Item 99: drop invalid network DNS frames
	TunnelStatusActive    bool          `json:"tunnel_status_active"`     // Item 100: toggle active status of configuration helper
}

// AdjustSessionCount increments active SOCKS session count dynamically
func (s *MitmFrontingSocksServer) AdjustSessionCount(increment int32) int32 {
	return atomic.AddInt32(&s.ActiveClientSessions, increment)
}
