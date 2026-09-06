package mitm

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// MitmFrontingRouteOptimizer manages CDN edge selections, weight balancers, and ping intervals (Items 1-35)
type MitmFrontingRouteOptimizer struct {
	mu                     sync.RWMutex
	RouteCheckIntervalSec  int            `json:"route_check_interval_sec"` // Item 1: RTT verification scan frequency
	AlphaWeightFactorVal   float64        `json:"alpha_weight_factor_val"`  // Item 2: EWMA decay multiplier for latencies
	MaxAllowedLatencyMs    int            `json:"max_allowed_latency_ms"`   // Item 3: threshold warning for slow routes
	PacketLossLimitRatio   float64        `json:"packet_loss_limit_ratio"`  // Item 4: trigger warning threshold for packet drops
	OutboundInterfaceName  string         `json:"outbound_interface_name"`  // Item 5: interface device bind target string
	MetricDefaultScoreVal  int            `json:"metric_default_score_val"` // Item 6: initial priority score assigned
	WeightBalancerRatio    int            `json:"weight_balancer_ratio"`    // Item 7: balancing divisor for target weight
	AvailabilityScoresMap  map[string]int // Item 8: dynamic scoring table of target addresses
	MaxConcurrentCheckers  int            `json:"max_concurrent_checkers"`    // Item 9: parallel checkers execution limit
	SubnetFilterIPv4Block  string         `json:"subnet_filter_ipv4_block"`   // Item 10: IPv4 prefix filter used in checks
	SubnetFilterIPv6Block  string         `json:"subnet_filter_ipv6_block"`   // Item 11: IPv6 prefix filter used in checks
	EnableDeviceBindingOk  bool           `json:"enable_device_binding_ok"`   // Item 12: toggle binding sockets to specific interfaces
	IpTOSClassBitsSetting  int            `json:"ip_tos_class_bits_setting"`  // Item 13: Type of Service class bits applied
	TtlCheckProbeInterval  int            `json:"ttl_check_probe_interval"`   // Item 14: interval executing TTL diagnostic scans
	VerifySniHostAgainstCA bool           `json:"verify_sni_host_against_ca"` // Item 15: assert SNI hostname matches signed certs
	MaxRetriesBeforeBlack  int            `json:"max_retries_before_black"`   // Item 16: failures before blacklisting target edge host
	ProbeConnectionPathUrl string         `json:"probe_connection_path_url"`  // Item 17: URL path used during latency scans
	BandwidthScanLimitBps  int64          `json:"bandwidth_scan_limit_bps"`   // Item 18: speed limit ceiling during test runs
	PreferredIPVersionTag  string         `json:"preferred_ip_version_tag"`   // Item 19: priority version setting (IPv4, IPv6)
	FailuresBeforeBlockage int            `json:"failures_before_blockage"`   // Item 20: count of dial failures triggering blacklist
	BlacklistDurationSecs  int            `json:"blacklist_duration_secs"`    // Item 21: duration targets remain blacklisted
	LastPingVerification   time.Time      `json:"last_ping_verification"`     // Item 22: timestamp of most recent ping validation
	ActiveDiagnosticProbes int32          `json:"active_diagnostic_probes"`   // Item 23: count of parallel checks in execution
	UseTCPFastOpenToggles  bool           `json:"use_tcp_fast_open_toggles"`  // Item 24: TCP Fast Open enabled on diagnostic checks
	SocketWriteTimeoutSecs int            `json:"socket_write_timeout_secs"`  // Item 25: write timeout for diagnostic check sockets
	SocketReadTimeoutSecs  int            `json:"socket_read_timeout_secs"`   // Item 26: read timeout for diagnostic check sockets
	IdleDisconnectTimeout  int            `json:"idle_disconnect_timeout"`    // Item 27: timeout before disconnecting idle sockets
	MetricsCompilationSec  int            `json:"metrics_compilation_sec"`    // Item 28: interval rate compiling dynamic stats
	LastSuccessfulRouteStr string         `json:"last_successful_route_str"`  // Item 29: latest endpoint string routed cleanly
	OptimizationSubState   bool           `json:"optimization_sub_state"`     // Item 30: toggle status of optimizer checks
	TotalScansAttempted    uint64         `json:"total_scans_attempted"`      // Item 31: cumulative count of route scans run
	TotalScansSucceeded    uint64         `json:"total_scans_succeeded"`      // Item 32: count of scans completing successfully
	AverageResponseTimeMs  int64          `json:"average_response_time_ms"`   // Item 33: EWMA value of response speeds
	JitterVarianceTimeMs   int64          `json:"jitter_variance_time_ms"`    // Item 34: variance in latencies recorded
	OptimizerSubsystemName string         `json:"optimizer_subsystem_name"`   // Item 35: string identifier of the optimizer
}

// MitmFrontingRouteHealth stats tracking connection errors and failures (Items 36-70)
type MitmFrontingRouteHealth struct {
	mu                      sync.Mutex
	UploadBytesTotalCount   uint64        `json:"upload_bytes_total_count"`   // Item 36: total bytes uploaded through route
	DownloadBytesTotalCount uint64        `json:"download_bytes_total_count"` // Item 37: total bytes downloaded through route
	LastActivityRecordTime  time.Time     `json:"last_activity_record_time"`  // Item 38: latest timestamp of user activity
	HourlyUploadRateArray   []uint64      `json:"hourly_upload_rate_array"`   // Item 39: stats logging uploaded rates hourly
	HourlyDownloadRateArr   []uint64      `json:"hourly_download_rate_arr"`   // Item 40: stats logging downloaded rates hourly
	PeakTransferSpeedValue  uint64        `json:"peak_transfer_speed_value"`  // Item 41: maximum recorded transfer speed
	QuotaLimitBytesCeiling  uint64        `json:"quota_limit_bytes_ceiling"`  // Item 42: limit of transfer quota before block
	QuotaExpirationReached  bool          `json:"quota_expiration_reached"`   // Item 43: flag triggered on quota violations
	ConnectionErrorsTally   uint64        `json:"connection_errors_tally"`    // Item 44: total connection failures recorded
	ActiveSocketsRegistry   []net.Conn    // Item 45: registry holding active net connection streams
	AvgSessionDurationSec   time.Duration // Item 46: rolling average duration of connections
	ActiveClientsTally      int32         // Item 47: count of active clients using route
	SlowDisconnectTimerSec  int           // Item 48: disconnect timer threshold for idle connections
	EnableAlertsChannel     bool          `json:"enable_alerts_channel"`      // Item 49: toggle alerts notification channel
	AlertWebhookPathUrl     string        `json:"alerts_webhook_path_url"`    // Item 50: target URL receiving alerts
	MetricDumpDirectory     string        `json:"metric_dump_directory"`      // Item 51: folder saving diagnostics data
	DumpIntervalMinutesVal  int           `json:"dump_interval_minutes_val"`  // Item 52: interval writing stats to file paths
	WarningUsagePercentVal  float64       `json:"warning_usage_percent_val"`  // Item 53: usage percentage triggering alerts
	BytesWarningAlertedOk   bool          `json:"bytes_warning_alerted_ok"`   // Item 54: warning sent flag indicator
	MaxFailureSwapsAllowed  int           `json:"max_failure_swaps_allowed"`  // Item 55: failures allowed before swapping route
	SwapTargetServerList    []string      `json:"swap_target_server_list"`    // Item 56: server pool routed on swaps
	ActiveServerTargetHost  string        `json:"active_server_target_host"`  // Item 57: server host currently targeted
	TotalServerSwapsTally   uint64        `json:"total_server_swaps_tally"`   // Item 58: total count of route swaps
	LastSwapRecordTime      time.Time     `json:"last_swap_record_time"`      // Item 59: timestamp tracking latest route modification
	ProxyProtocolVerValue   int           `json:"proxy_protocol_ver_value"`   // Item 60: PROXY protocol version parameter
	TlsHandshakeSuccess     uint64        `json:"tls_handshake_success"`      // Item 61: successful TLS handshakes counter
	TlsHandshakeFailure     uint64        `json:"tls_handshake_failure"`      // Item 62: failed TLS handshakes counter
	DiagnosticsStatusState  bool          `json:"diagnostics_status_state"`   // Item 63: toggle status of health check subsystem
	LastDiagnosticsMsgStr   string        `json:"last_diagnostics_msg_str"`   // Item 64: latest status text logged
	UploadSpeedLimitBps     int64         `json:"upload_speed_limit_bps"`     // Item 65: upload speed rate limit shaper
	DownloadSpeedLimitBps   int64         `json:"download_speed_limit_bps"`   // Item 66: download speed rate limit shaper
	QueueDelayLimitMsValue  int           `json:"queue_delay_limit_ms_value"` // Item 67: max queuing duration in ms
	MaxQueuedFramesCount    int           `json:"max_queued_frames_count"`    // Item 68: frame queue size limit
	ActiveQueuedFramesNum   int32         `json:"active_queued_frames_num"`   // Item 69: frames count inside queue
	HealthSubsystemState    bool          `json:"health_subsystem_state"`     // Item 70: health checks active indicator
}

// MitmFrontingRouteRegistry maps domains, hosts, and specific routes (Items 71-100)
type MitmFrontingRouteRegistry struct {
	mu                      sync.RWMutex
	TargetHostHeaderString  string            `json:"target_host_header_string"`  // Item 71: host header matching rules
	UserAgentVariantString  string            `json:"user_agent_variant_string"`  // Item 72: User-Agent header variant value
	CustomRequestPathString string            `json:"custom_request_path_string"` // Item 73: path override mapping rules
	QueryParametersMap      map[string]string `json:"query_parameters_map"`       // Item 74: custom request query parameters
	InjectedHeadersMapping  map[string]string `json:"injected_headers_mapping"`   // Item 75: custom injected headers block
	BodyInjectionsByteArr   []byte            `json:"body_injections_byte_arr"`   // Item 76: custom payload bytes injected
	EnablePayloadObfuscate  bool              `json:"enable_payload_obfuscate"`   // Item 77: toggle payload obfuscation
	PayloadObfsSaltBytes    []byte            `json:"payload_obfs_salt_bytes"`    // Item 78: custom salt bytes value
	ChunkedEncodingEnabled  bool              `json:"chunked_encoding_enabled"`   // Item 79: toggle chunked data routing
	MaxChunkLengthLimitVal  int               `json:"max_chunk_length_limit_val"` // Item 80: chunk length ceiling value
	TlsServerNameValue      string            `json:"tls_server_name_value"`      // Item 81: ServerName SNI identifier
	AlpnNegotiatedProtocols []string          `json:"alpn_negotiated_protocols"`  // Item 82: Negotiated ALPN strings list
	TlsSkipVerifyToggles    bool              `json:"tls_skip_verify_toggles"`    // Item 83: bypass validation of target certs
	OutboundProtocolType    string            `json:"outbound_protocol_type"`     // Item 84: transport name (http1, h2, ws)
	WebSocketEarlyDataOk    bool              `json:"web_socket_early_data_ok"`   // Item 85: early data writes on WebSockets
	GrpcServicePathName     string            `json:"grpc_service_path_name"`     // Item 86: gRPC service route identifier
	OutboundDialAddressStr  string            `json:"outbound_dial_address_str"`  // Item 87: target address dialed out
	DialTimeoutDurationVal  time.Duration     `json:"dial_timeout_duration_val"`  // Item 88: connection timeout value
	TcpKeepAliveIntervalMs  time.Duration     `json:"tcp_keep_alive_interval_ms"` // Item 89: TCP keepalive interval
	SocketWriteBufferSize   int               `json:"socket_write_buffer_size"`   // Item 90: write buffer size allocated
	SocketReadBufferSize    int               `json:"socket_read_buffer_size"`    // Item 91: read buffer size allocated
	LingerCloseSecValue     int               `json:"linger_close_sec_value"`     // Item 92: SO_LINGER duration configured
	IpTOSClassBitsSetting   int               `json:"ip_tos_class_bits_setting"`  // Item 93: Type of Service bits class value
	BbrCongestionActive     bool              `json:"bbr_congestion_active"`      // Item 94: BBR socket congestion control
	SocketMarkIdentifier    int               `json:"socket_mark_identifier"`     // Item 95: packet mark value for routing
	HaProxyProtocolVerNum   int               `json:"ha_proxy_protocol_ver_num"`  // Item 96: HAProxy protocol version parameter
	ProxyCredentialsUser    string            `json:"proxy_credentials_user"`     // Item 97: proxy username credentials
	ProxyCredentialsPass    string            `json:"proxy_credentials_pass"`     // Item 98: proxy password credentials
	MaxStreamsPerSocketVal  int               `json:"max_streams_per_socket_val"` // Item 99: concurrent streams multiplex limit
	RegistryActiveState     bool              `json:"registry_active_state"`      // Item 100: toggle active status of route registry
}

// DialRoute executes raw dial attempts while keeping latency statistics
func (d *MitmFrontingRouteOptimizer) DialRoute(ctx context.Context, addr string) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	atomic.AddInt32(&d.ActiveDiagnosticProbes, 1)
	defer atomic.AddInt32(&d.ActiveDiagnosticProbes, -1)

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	d.LastPingVerification = time.Now()
	return conn, nil
}
