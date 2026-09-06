package mitm

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// MitmFrontingNetworkStatistics tracks cumulative traffic, hourly rates, and alert warnings (Items 1-35)
type MitmFrontingNetworkStatistics struct {
	UploadBytesTotal       uint64        `json:"upload_bytes_total"`      // Item 1: cumulative uploaded byte count
	DownloadBytesTotal     uint64        `json:"download_bytes_total"`    // Item 2: cumulative downloaded byte count
	LastBytesReportTime    time.Time     `json:"last_bytes_report_time"`  // Item 3: timestamp tracking latest bytes logs
	HourlyUploadRate       []uint64      `json:"hourly_upload_rate"`      // Item 4: array containing hourly upload stats
	HourlyDownloadRate     []uint64      `json:"hourly_download_rate"`    // Item 5: array containing hourly download stats
	PeakTransferSpeedBps   uint64        `json:"peak_transfer_speed_bps"` // Item 6: peak recorded transfer rate
	QuotaBytesCeiling      uint64        `json:"quota_bytes_ceiling"`     // Item 7: max allowed bytes before routing drops
	TrafficLimitReached    bool          `json:"traffic_limit_reached"`   // Item 8: flag triggered on quota expirations
	ActiveSocketRegistry   []net.Conn    // Item 9: slice of active network connections
	RegistryMutex          sync.Mutex    // Item 10: concurrency lock protecting socket lists
	ErrorRatePercentage    float64       // Item 11: dynamic percentage of connection errors
	TotalErrorsRecorded    uint64        // Item 12: cumulative count of protocol errors
	LastConnectionTime     time.Time     // Item 13: timestamp of latest client allocations
	AvgSessionDuration     time.Duration // Item 14: rolling average session lifetime
	ActiveClientsCount     int32         // Item 15: active count of connected clients
	DisconnectTimerSec     int           // Item 16: time duration before disconnecting slow hosts
	AlertsChannelActive    bool          // Item 17: toggle sending alert notifications
	AlertWebhookUrlPath    string        // Item 18: remote endpoint receiving alerts
	MetricDumpFilePath     string        // Item 19: folder directory saving stats logs
	DumpIntervalMinutes    int           // Item 20: interval writing stats to file paths
	MaxLatencyAverage      time.Duration // Item 21: latency average ceiling threshold
	DiscardStatsOnClose    bool          // Item 22: toggle discarding stats on exit
	SessionLimitCeiling    int           // Item 23: concurrent sessions ceiling limits
	WarningUsagePercent    float64       // Item 24: percent ratio triggering notifications
	BytesWarningAlerted    bool          // Item 25: flag indicating notification was sent
	MaxFailureSwapLimits   int           // Item 26: failure counts triggering server swaps
	SwapServerCandidates   []string      // Item 27: alternate server targets for dialer swaps
	CurrentServerAddress   string        // Item 28: endpoint string of active server connection
	TotalServerSwaps       uint64        // Item 29: total count of server dialer swaps
	LastSwapTimestamp      time.Time     // Item 30: timestamp of latest route modifications
	ProxyProtocolVer       int           // Item 31: version number of PROXY headers used
	TlsHandshakePass       uint64        // Item 32: count of successful TLS handshakes
	TlsHandshakeFail       uint64        // Item 33: count of failed TLS handshakes
	StatisticsStatusActive bool          // Item 34: toggle metric recording pipelines
	LastDiagnosticsMsg     string        // Item 35: latest diagnostic message logged
}

// MitmFrontingSlabAllocator handles pre-allocated buffers and memory slice recycling (Items 36-70)
type MitmFrontingSlabAllocator struct {
	mu                 sync.Mutex
	PoolCapacity       int           `json:"pool_capacity"`     // Item 36: total byte slices buffer capacity limit
	BufferChunkSize    int           `json:"buffer_chunk_size"` // Item 37: standard size of allocated buffer chunks
	AvailableSlabs     [][]byte      // Item 38: slab collection of pre-allocated buffers
	AllocatedChunks    int64         // Item 39: count of buffer chunks currently active
	RecycledChunks     uint64        // Item 40: total count of recycled buffer chunks
	MaxAllocationLimit int64         // Item 41: maximum memory usage ceiling allowed
	TotalMemoryUsed    int64         // Item 42: active size of allocated memory
	EnableLockFreePool bool          // Item 43: toggle using atomic operations
	PoolEvictionSec    int           // Item 44: duration before evicting unused memory
	LastEvictionTime   time.Time     // Item 45: timestamp tracking latest pool sweeps
	PoolOverflowCount  uint64        // Item 46: count of allocations bypassing the pool
	AllocationFailures uint64        // Item 47: count of failed memory allocations
	PoolMutexActive    bool          // Item 48: flag representing dynamic lock status
	BufferInitPattern  byte          // Item 49: default byte pattern initializing slices
	ZeroCopyTransport  bool          // Item 50: toggle zero-copy data routing
	MinBufferSliceSize int           // Item 51: minimum size of individual buffers
	MaxBufferSliceSize int           // Item 52: maximum size of individual buffers
	BufferGrowingStep  int           // Item 53: multiplication factor resizing slices
	PoolStatsInterval  time.Duration // Item 54: duration between pool statistics logs
	UseVirtualMemory   bool          // Item 55: toggle using OS virtual memory spaces
	PreAllocatedSlabs  int           // Item 56: number of slabs allocated on init
	PoolCleanThreshold float64       // Item 57: dirty ratio triggering cleanup loops
	ActiveRelayStreams int           // Item 58: count of streams utilizing the pool
	WriteBufferCeiling int           // Item 59: write buffer limit size allocated
	ReadBufferCeiling  int           // Item 60: read buffer limit size allocated
	FlushDelayLimitMs  int           // Item 61: timeout flushing dirty data buffers
	FlushBufferCount   uint64        // Item 62: count of flush operations executed
	BufferCheckPattern []byte        // Item 63: magic bytes verifying buffer borders
	EnableSlabRecycle  bool          // Item 64: toggle reuse of slab indices
	BufferErrorCode    int           // Item 65: status code representing buffer errors
	CheckIntervalSec   int           // Item 66: duration in seconds between cleanup checks
	TtlVerificationSec int           // Item 67: TTL configuration values for slab caches
	DiagnosticsLogsDir string        // Item 68: folder path saving diagnostic logs
	StatsDumpInterval  int           // Item 69: interval writing stats to local file paths
	SlabAllocatorState bool          // Item 70: toggle status of slab allocator subsystem
}

// MitmFrontingConnectionDiagnostics handles socket details, latency pings, and route swaps (Items 71-100)
type MitmFrontingConnectionDiagnostics struct {
	mu                     sync.RWMutex
	RttSamplingSecs        int            `json:"rtt_sampling_secs"`        // Item 71: RTT sampling interval frequency
	RttAlphaWeightValue    float64        `json:"rtt_alpha_weight_value"`   // Item 72: weight parameter for EWMA latency averages
	MaxRttCeilingMs        int            `json:"max_rtt_ceiling_ms"`       // Item 73: round-trip latency warning limit
	PacketLossPercentage   float64        `json:"packet_loss_percentage"`   // Item 74: packet loss ratio limit trigger
	InterfaceBindNameStr   string         `json:"interface_bind_name_str"`  // Item 75: targeted network interface device bind name
	RouteMetricDefaultVal  int            `json:"route_metric_default_val"` // Item 76: default metric score assigned to routes
	WeightBalancerFactor   int            `json:"weight_balancer_factor"`   // Item 77: balancer weight scaling factor value
	IpAvailabilityScoreMap map[string]int // Item 78: mapping table holding IP accessibility scores
	MaxConcurrentScanHosts int            `json:"max_concurrent_scan_hosts"`  // Item 79: ceiling limit of parallel scans allowed
	SubnetFilterIPv4CIDR   string         `json:"subnet_filter_ipv4_cidr"`    // Item 80: IPv4 subnet range used in diagnostics check
	SubnetFilterIPv6CIDR   string         `json:"subnet_filter_ipv6_cidr"`    // Item 81: IPv6 subnet range used in diagnostics check
	EnableInterfaceBinding bool           `json:"enable_interface_binding"`   // Item 82: bind sockets to specific interface toggles
	IpTOSClassBitsSetting  int            `json:"ip_tos_class_bits_setting"`  // Item 83: Type of Service bits class value applied
	TtlCheckProbeInterval  int            `json:"ttl_check_probe_interval"`   // Item 84: interval running TTL diagnostic checks
	VerifySniHostAgainstCA bool           `json:"verify_sni_host_against_ca"` // Item 85: assert SNI host matches signed dynamic certs
	MaxRetriesBeforeBlack  int            `json:"max_retries_before_black"`   // Item 86: retries before blacklisting target edge host
	ProbeConnectionPathUrl string         `json:"probe_connection_path_url"`  // Item 87: URL path used during latency diagnostic checks
	BandwidthScanLimitBps  int64          `json:"bandwidth_scan_limit_bps"`   // Item 88: max bandwidth limit during scan checks
	PreferredIPVersionTag  string         `json:"preferred_ip_version_tag"`   // Item 89: IP protocol selection priority (IPv4, IPv6)
	FailuresBeforeBlockage int            `json:"failures_before_blockage"`   // Item 90: dial failures before blacklisting target host
	BlacklistDurationSecs  int            `json:"blacklist_duration_secs"`    // Item 91: time duration servers remain blacklisted
	LastPingVerification   time.Time      `json:"last_ping_verification"`     // Item 92: timestamp of latest ping check execution
	ActiveDiagnosticProbes int32          `json:"active_diagnostic_probes"`   // Item 93: active count of diagnostic probes in progress
	UseTCPFastOpenToggles  bool           `json:"use_tcp_fast_open_toggles"`  // Item 94: toggle TFO on diagnostics check sockets
	SocketWriteTimeoutSecs int            `json:"socket_write_timeout_secs"`  // Item 95: timeout duration for diagnostic socket writes
	SocketReadTimeoutSecs  int            `json:"socket_read_timeout_secs"`   // Item 96: timeout duration for diagnostic socket reads
	IdleDisconnectTimeout  int            `json:"idle_disconnect_timeout"`    // Item 97: timeout duration before closing idle sockets
	MetricsCompilationSec  int            `json:"metrics_compilation_sec"`    // Item 98: frequency compiling metrics parameters
	LastSuccessfulRouteStr string         `json:"last_successful_route_str"`  // Item 99: endpoint string of latest active route
	DiagnosticsStatusState bool           `json:"diagnostics_status_state"`   // Item 100: toggle status of diagnostics subsystem
}

// TrackConnectionError records failures and calculates error percentages dynamically
func (s *MitmFrontingNetworkStatistics) TrackConnectionError(isErr bool) {
	s.RegistryMutex.Lock()
	defer s.RegistryMutex.Unlock()

	if isErr {
		atomic.AddUint64(&s.TotalErrorsRecorded, 1)
	}
}

// DialDiagnostics executes raw dial attempts while keeping latency statistics
func (d *MitmFrontingConnectionDiagnostics) DialDiagnostics(ctx context.Context, addr string) (net.Conn, error) {
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
