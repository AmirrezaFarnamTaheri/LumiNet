package mitm

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/maybeknott/luminet/internal/netutil"
)

// MitmFrontingBandwidthShaper manages token bucket rate limits and queues (Items 1-35)
type MitmFrontingBandwidthShaper struct {
	mu                     sync.RWMutex
	LimitBytesPerSec       int64     `json:"limit_bytes_per_sec"`       // Item 1: target speed limit value
	BurstBytesLimit        int64     `json:"burst_bytes_limit"`         // Item 2: max burst byte limit allowed
	TokenRefillRateSec     int64     `json:"token_refill_rate_sec"`     // Item 3: rate of token refill per second
	AvailableTokens        int64     `json:"available_tokens"`          // Item 4: count of tokens currently available
	LastRefillTimestamp    time.Time `json:"last_refill_timestamp"`     // Item 5: timestamp of latest token refill
	QueueDelayLimitMs      int       `json:"queue_delay_limit_ms"`      // Item 6: duration ceiling before packet drops
	DiscardStatsOnExit     bool      `json:"discard_stats_on_exit"`     // Item 7: toggle stats discard on cleanup
	MaxQueuedPacketsCount  int       `json:"max_queued_packets_count"`  // Item 8: queue size limit for packet storage
	ActiveQueuedPackets    int32     `json:"active_queued_packets"`     // Item 9: number of packets currently in queue
	TotalDroppedPackets    uint64    `json:"total_dropped_packets"`     // Item 10: total count of packets dropped
	TotalDelayedPackets    uint64    `json:"total_delayed_packets"`     // Item 11: total count of packets delayed by shaper
	InterfaceDeviceName    string    `json:"interface_device_name"`     // Item 12: network interface device target name
	IpTOSClassBitsValue    int       `json:"ip_tos_class_bits_value"`   // Item 13: Type of Service class bits applied
	TtlVerificationSeconds int       `json:"ttl_verification_seconds"`  // Item 14: interval executing socket TTL checks
	TlsHandshakeLimitMs    int       `json:"tls_handshake_limit_ms"`    // Item 15: time limit allocated for handshakes
	CongestionControlName  string    `json:"congestion_control_name"`   // Item 16: congestion algorithm name tag BBR
	SocketMarkValueIndex   int       `json:"socket_mark_value_index"`   // Item 17: packet mark applied on socket routing
	LingerDurationSeconds  int       `json:"linger_duration_seconds"`   // Item 18: SO_LINGER value on shaper socket
	FallbackEndpointAddr   string    `json:"fallback_endpoint_addr"`    // Item 19: fallback target address IP
	AlertsWebhookPathUrl   string    `json:"alerts_webhook_path_url"`   // Item 20: URL endpoint receiving warnings
	EnableAlertsChannel    bool      `json:"enable_alerts_channel"`     // Item 21: toggle alerts notification system
	MetricsCollectionSec   int       `json:"metrics_collection_sec"`    // Item 22: rate of compiling metrics
	WriteBufferCapacity    int       `json:"write_buffer_capacity"`     // Item 23: write buffer limit size allocated
	ReadBufferCapacity     int       `json:"read_buffer_capacity"`      // Item 24: read buffer limit size allocated
	ZeroCopyTransferMode   bool      `json:"zero_copy_transfer_mode"`   // Item 25: toggle zero-copy data operations
	KeepAliveSecondsFreq   int       `json:"keep_alive_seconds_freq"`   // Item 26: TCP keepalive frequency
	RateLimitQueriesLimit  int       `json:"rate_limit_queries_limit"`  // Item 27: limit of query checks per window
	ResolverAddressIPv4    string    `json:"resolver_address_ipv4"`     // Item 28: custom DNS IP target
	CacheEvictionTimeLimit int       `json:"cache_eviction_time_limit"` // Item 29: duration before cache entries evict
	MetricsLoggerToggles   bool      `json:"metrics_logger_toggles"`    // Item 30: toggle metrics logger active
	DropInvalidDnsFrames   bool      `json:"drop_invalid_dns_frames"`   // Item 31: drop malformed probe response packets
	SubnetFilterMaskSize   int       `json:"subnet_filter_mask_size"`   // Item 32: subnet mask size parameter
	HappyEyeballsWeight    float64   `json:"happy_eyeballs_weight"`     // Item 33: weight decay value for latency
	VerifyDomainsStrict    bool      `json:"verify_domains_strict"`     // Item 34: strict domains string verification
	ShaperActiveToggles    bool      `json:"shaper_active_toggles"`     // Item 35: toggle status of shaper subsystem
}

// NewMitmFrontingBandwidthShaper creates a token bucket with an explicit,
// bounded rate and burst. A zero or negative rate is never a usable limiter.
func NewMitmFrontingBandwidthShaper(limitBytesPerSec, burstBytes int64) (*MitmFrontingBandwidthShaper, error) {
	policy, err := (netutil.RatePolicy{BytesPerSecond: limitBytesPerSec, BurstBytes: burstBytes}).Normalize()
	if err != nil {
		return nil, err
	}
	return &MitmFrontingBandwidthShaper{
		LimitBytesPerSec:    policy.BytesPerSecond,
		BurstBytesLimit:     policy.BurstBytes,
		TokenRefillRateSec:  policy.BytesPerSecond,
		AvailableTokens:     policy.BurstBytes,
		LastRefillTimestamp: time.Now(),
		ShaperActiveToggles: true,
	}, nil
}

// MitmFrontingSocks5ServerConfig configures SOCKS5 listeners and auth settings (Items 36-70)
type MitmFrontingSocks5ServerConfig struct {
	mu                       sync.RWMutex
	Socks5UsernameStr        string    `json:"socks5_username_str"`         // Item 36: SOCKS5 auth username credential
	Socks5PasswordStr        string    `json:"socks5_password_str"`         // Item 37: SOCKS5 auth password credential
	ListenBindAddress        string    `json:"listen_bind_address"`         // Item 38: bind address string for SOCKS5 server
	ListenBindPortNumber     int       `json:"listen_bind_port_number"`     // Item 39: port number SOCKS5 server listens on
	AuthMethodSupported      []byte    `json:"auth_method_supported"`       // Item 40: supported auth methods (no-auth, user-pass)
	TlsEnabledForSocks       bool      `json:"tls_enabled_for_socks"`       // Item 41: toggle SOCKS5 over TLS option
	TlsServerNameString      string    `json:"tls_server_name_string"`      // Item 42: ServerName verified on TLS handshakes
	TlsConfigOptionBlock     []byte    `json:"tls_config_option_block"`     // Item 43: serialization options for TLS configs
	MaxConcurrentClients     int       `json:"max_concurrent_clients"`      // Item 44: ceiling limit of parallel client sessions
	SessionTimeoutSeconds    int       `json:"session_timeout_seconds"`     // Item 45: duration before closing idle client sessions
	KeepAliveProbeToggles    bool      `json:"keep_alive_probe_toggles"`    // Item 46: TCP keepalive enabled on SOCKS5 sockets
	LingerCloseSecValue      int       `json:"linger_close_sec_value"`      // Item 47: linger close timeout for clients
	IpTOSClassBitsSetting    int       `json:"ip_tos_class_bits_setting"`   // Item 48: TOS configuration bytes for SOCKS5 sockets
	BbrCongestionActive      bool      `json:"bbr_congestion_active"`       // Item 49: BBR socket congestion control toggle
	OutboundSocketMarkVal    int       `json:"outbound_socket_mark_val"`    // Item 50: packet mark value applied on outbound dials
	BindInterfaceNameStr     string    `json:"bind_interface_name_str"`     // Item 51: targeted network bind interface name
	PreferIpv6DialsOption    bool      `json:"prefer_ipv6_dials_option"`    // Item 52: priority targeting IPv6 route lookups
	PROXYProtocolHeadersOk   bool      `json:"proxy_protocol_headers_ok"`   // Item 53: toggle parsing PROXY protocol headers
	BypassSubnetsRegistry    []string  `json:"bypass_subnets_registry"`     // Item 54: local subnet CIDR blocks bypassing SOCKS5
	DynamicHostsOverride     []string  `json:"dynamic_hosts_override"`      // Item 55: custom DNS hostname mappings list
	LatenciesTargetMaps      []int64   `json:"latencies_target_maps"`       // Item 56: tracked latencies for outbound endpoints
	MetricsCompilationOk     bool      `json:"metrics_compilation_ok"`      // Item 57: toggle metrics collection for SOCKS5
	ResolverAddressString    string    `json:"resolver_address_string"`     // Item 58: custom resolver server target IP
	SubdomainMatchToggles    bool      `json:"subdomain_match_toggles"`     // Item 59: toggle subdomain wildcard blocking
	TotalFailedDialsCount    uint64    `json:"total_failed_dials_count"`    // Item 60: total failed dial attempts from SOCKS5
	TotalSuccessfulDials     uint64    `json:"total_successful_dials"`      // Item 61: total successful dials from SOCKS5
	ActiveClientSessions     int32     `json:"active_client_sessions"`      // Item 62: active count of connected SOCKS5 clients
	StatsDumpDirectoryPath   string    `json:"stats_dump_directory_path"`   // Item 63: folder path saving stats logs
	StatsDumpIntervalMinutes int       `json:"stats_dump_interval_minutes"` // Item 64: interval writing stats to file paths
	MaxLatencyCeilingSec     int       `json:"max_latency_ceiling_sec"`     // Item 65: latency average ceiling threshold
	DisconnectTimerSeconds   int       `json:"disconnect_timer_seconds"`    // Item 66: time duration before disconnecting slow SOCKS
	AlertWebhookPathUrlStr   string    `json:"alert_webhook_path_url_str"`  // Item 67: URL receiving SOCKS5 webhook warnings
	AlertsActiveIndicator    bool      `json:"alerts_active_indicator"`     // Item 68: toggle alerts notification channel
	LastActivityTimestamp    time.Time `json:"last_activity_timestamp"`     // Item 69: timestamp of latest client packet exchange
	Socks5ActiveIndicator    bool      `json:"socks5_active_indicator"`     // Item 70: toggle active status of SOCKS5 server
}

// MitmFrontingHttpTunnelConfig configures HTTP CONNECT listeners and header tuning (Items 71-100)
type MitmFrontingHttpTunnelConfig struct {
	HttpProxyUsernameStr     string   `json:"http_proxy_username_str"`     // Item 71: HTTP CONNECT proxy username
	HttpProxyPasswordStr     string   `json:"http_proxy_password_str"`     // Item 72: HTTP CONNECT proxy password
	ListenBindAddressStr     string   `json:"listen_bind_address_str"`     // Item 73: bind address string for HTTP tunnel
	ListenBindPortNumber     int      `json:"listen_bind_port_number"`     // Item 74: port number HTTP tunnel listens on
	TlsEnabledForHttp        bool     `json:"tls_enabled_for_http"`        // Item 75: toggle HTTP tunnel over TLS option
	TlsServerNameString      string   `json:"tls_server_name_string"`      // Item 76: ServerName verified on TLS handshakes
	MaxConcurrentClients     int      `json:"max_concurrent_clients"`      // Item 77: ceiling limit of parallel client sessions
	SessionTimeoutSeconds    int      `json:"session_timeout_seconds"`     // Item 78: duration before closing idle client sessions
	KeepAliveProbeToggles    bool     `json:"keep_alive_probe_toggles"`    // Item 79: TCP keepalive enabled on HTTP sockets
	LingerCloseSecValue      int      `json:"linger_close_sec_value"`      // Item 80: linger close timeout for clients
	IpTOSClassBitsSetting    int      `json:"ip_tos_class_bits_setting"`   // Item 81: TOS configuration bytes for HTTP sockets
	BbrCongestionActive      bool     `json:"bbr_congestion_active"`       // Item 82: BBR socket congestion control toggle
	OutboundSocketMarkVal    int      `json:"outbound_socket_mark_val"`    // Item 83: packet mark value applied on outbound dials
	BindInterfaceNameStr     string   `json:"bind_interface_name_str"`     // Item 84: targeted network bind interface name
	PreferIpv6DialsOption    bool     `json:"prefer_ipv6_dials_option"`    // Item 85: priority targeting IPv6 route lookups
	PROXYProtocolHeadersOk   bool     `json:"proxy_protocol_headers_ok"`   // Item 86: toggle parsing PROXY protocol headers
	BypassSubnetsRegistry    []string `json:"bypass_subnets_registry"`     // Item 87: local subnet CIDR blocks bypassing tunnel
	DynamicHostsOverride     []string `json:"dynamic_hosts_override"`      // Item 88: custom DNS hostname mappings list
	LatenciesTargetMaps      []int64  `json:"latencies_target_maps"`       // Item 89: tracked latencies for outbound endpoints
	MetricsCompilationOk     bool     `json:"metrics_compilation_ok"`      // Item 90: toggle metrics collection for tunnel
	ResolverAddressString    string   `json:"resolver_address_string"`     // Item 91: custom resolver server target IP
	SubdomainMatchToggles    bool     `json:"subdomain_match_toggles"`     // Item 92: toggle subdomain wildcard blocking
	TotalFailedDialsCount    uint64   `json:"total_failed_dials_count"`    // Item 93: total failed dial attempts from tunnel
	TotalSuccessfulDials     uint64   `json:"total_successful_dials"`      // Item 94: total successful dials from tunnel
	ActiveClientSessions     int32    `json:"active_client_sessions"`      // Item 95: active count of connected tunnel clients
	StatsDumpDirectoryPath   string   `json:"stats_dump_directory_path"`   // Item 96: folder path saving stats logs
	StatsDumpIntervalMinutes int      `json:"stats_dump_interval_minutes"` // Item 97: interval writing stats to file paths
	DisconnectTimerSeconds   int      `json:"disconnect_timer_seconds"`    // Item 98: time duration before disconnecting slow HTTP
	AlertsActiveIndicator    bool     `json:"alerts_active_indicator"`     // Item 99: toggle alerts notification channel
	HttpTunnelActiveState    bool     `json:"http_tunnel_active_state"`    // Item 100: toggle active status of HTTP tunnel
}

// AcquiredTokens verifies and retrieves tokens from the bucket rate shaper
func (s *MitmFrontingBandwidthShaper) AcquiredTokens(count int64) bool {
	if count <= 0 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.ShaperActiveToggles || s.LimitBytesPerSec <= 0 || s.BurstBytesLimit <= 0 {
		return false
	}
	now := time.Now()
	if s.LastRefillTimestamp.IsZero() {
		s.LastRefillTimestamp = now
	}
	elapsed := now.Sub(s.LastRefillTimestamp).Seconds()
	refill := int64(elapsed * float64(s.LimitBytesPerSec))
	if refill > 0 {
		s.AvailableTokens += refill
		if s.AvailableTokens > s.BurstBytesLimit {
			s.AvailableTokens = s.BurstBytesLimit
		}
		s.LastRefillTimestamp = now
	}

	if s.AvailableTokens >= count {
		s.AvailableTokens -= count
		return true
	}

	atomic.AddUint64(&s.TotalDelayedPackets, 1)
	return false
}

// Wait acquires count bytes or returns when ctx is cancelled. It is intended
// for data-plane call sites that must shape traffic rather than drop it.
func (s *MitmFrontingBandwidthShaper) Wait(ctx context.Context, count int64) error {
	if count <= 0 {
		return fmt.Errorf("bandwidth shaper token count must be positive")
	}
	for {
		if s.AcquiredTokens(count) {
			return nil
		}
		s.mu.RLock()
		rate := s.LimitBytesPerSec
		s.mu.RUnlock()
		if rate <= 0 {
			return fmt.Errorf("bandwidth shaper is inactive")
		}
		wait := time.Duration((count*int64(time.Second) + rate - 1) / rate)
		if wait < time.Millisecond {
			wait = time.Millisecond
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}
