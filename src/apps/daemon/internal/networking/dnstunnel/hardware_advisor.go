package dnstunnel

import "math"

// NetworkConnection represents the physical transport medium of the client.
type NetworkConnection string

const (
	ConnMobile4g5g NetworkConnection = "4g"
	ConnWifi       NetworkConnection = "wifi"
	ConnDsl        NetworkConnection = "dsl"
	ConnFiber      NetworkConnection = "fiber"
)

// NetworkQuality represents link reliability and jitter profile.
type NetworkQuality string

const (
	QualityExcellent NetworkQuality = "excellent"
	QualityGood      NetworkQuality = "good"
	QualityMedium    NetworkQuality = "medium"
	QualityPoor      NetworkQuality = "poor"
)

// ReliabilityFactor returns a float factor in [0.3, 1.0] representing link quality.
func (q NetworkQuality) ReliabilityFactor() float64 {
	switch q {
	case QualityExcellent:
		return 1.0
	case QualityGood:
		return 0.8
	case QualityMedium:
		return 0.5
	case QualityPoor:
		return 0.3
	default:
		return 0.5
	}
}

// IsLossy returns true if packet loss is expected to be high.
func (q NetworkQuality) IsLossy() bool {
	return q.ReliabilityFactor() <= 0.5
}

// ResolverCensus represents the count bracket of upstream/public DNS resolvers available.
type ResolverCensus string

const (
	CensusFew    ResolverCensus = "few"    // < 10
	CensusMedium ResolverCensus = "medium" // 10 - 50
	CensusMany   ResolverCensus = "many"   // > 50
)

// MtuPreference dictates client preference for MTU negotiation.
type MtuPreference string

const (
	MtuPrefStable   MtuPreference = "stable"
	MtuPrefBalanced MtuPreference = "balanced"
	MtuPrefSpeed    MtuPreference = "speed"
)

// UseCase specifies primary workload characteristics.
type UseCase string

const (
	UseCaseBrowse   UseCase = "browse"
	UseCaseChat     UseCase = "chat"
	UseCaseStream   UseCase = "stream"
	UseCaseDownload UseCase = "download"
	UseCaseMixed    UseCase = "mixed"
)

// EncryptionPreference specifies security vs CPU overhead preference.
type EncryptionPreference string

const (
	EncLight    EncryptionPreference = "light"    // XOR (1)
	EncBalanced EncryptionPreference = "balanced" // ChaCha20 (2)
	EncStrong   EncryptionPreference = "strong"   // AES-256-GCM (5)
)

// ClientHardwareProfile holds device specification and environment metrics.
type ClientHardwareProfile struct {
	Connection           NetworkConnection    `json:"connection"`
	Quality              NetworkQuality       `json:"quality"`
	CPUCores             int                  `json:"cpu_cores"`
	RAMMB                int                  `json:"ram_mb"`
	ResolverCensus       ResolverCensus       `json:"resolver_census"`
	MtuPreference        MtuPreference        `json:"mtu_preference"`
	UseCase              UseCase              `json:"use_case"`
	EncryptionPreference EncryptionPreference `json:"encryption_preference"`
}

// ClientRecommendation holds calculated parameters for client daemon operation.
type ClientRecommendation struct {
	DataEncryptionMethod                 uint8   `json:"data_encryption_method"`
	PacketDuplicationCount               uint8   `json:"packet_duplication_count"`
	SetupPacketDuplicationCount          uint8   `json:"setup_packet_duplication_count"`
	ResolverBalancingStrategy            uint8   `json:"resolver_balancing_strategy"` // 0: RR, 1: Rand, 3: LowestLoss, 4: LowestLatency
	StreamResolverFailoverThreshold      uint32  `json:"stream_resolver_failover_resend_threshold"`
	StreamResolverFailoverCooldownSec    uint32  `json:"stream_resolver_failover_cooldown_sec"`
	MinUploadMTU                         uint16  `json:"min_upload_mtu"`
	MinDownloadMTU                       uint16  `json:"min_download_mtu"`
	MaxUploadMTU                         uint16  `json:"max_upload_mtu"`
	MaxDownloadMTU                       uint16  `json:"max_download_mtu"`
	MtuTestParallelism                   int     `json:"mtu_test_parallelism"`
	MtuTestRetries                       uint32  `json:"mtu_test_retries"`
	MtuTestTimeoutSec                    uint32  `json:"mtu_test_timeout_sec"`
	TunnelReaderWorkers                  int     `json:"tunnel_reader_workers"`
	TunnelWriterWorkers                  int     `json:"tunnel_writer_workers"`
	TunnelProcessWorkers                 int     `json:"tunnel_process_workers"`
	TxChannelSize                        int     `json:"tx_channel_size"`
	RxChannelSize                        int     `json:"rx_channel_size"`
	ResolverUDPConnectionPoolSize        int     `json:"resolver_udp_connection_pool_size"`
	UploadCompressionType                uint8   `json:"upload_compression_type"`   // 0: None, 1: ZSTD, 2: LZ4
	DownloadCompressionType              uint8   `json:"download_compression_type"` // 0: None, 1: ZSTD, 2: LZ4
	ArqWindowSize                        int     `json:"arq_window_size"`
	ArqDataNackMaxGap                    int     `json:"arq_data_nack_max_gap"`
	ArqMaxDataRetries                    int     `json:"arq_max_data_retries"`
	ArqMaxRtoSec                         float64 `json:"arq_max_rto_sec"`
	PingAggressiveIntervalSec            float64 `json:"ping_aggressive_interval_sec"`
	PingLazyIntervalSec                  float64 `json:"ping_lazy_interval_sec"`
	PingCooldownIntervalSec              float64 `json:"ping_cooldown_interval_sec"`
	DispatcherIdlePollIntervalSec        float64 `json:"dispatcher_idle_poll_interval_sec"`
}

// ServerTraffic defines expected client traffic density on the server.
type ServerTraffic string

const (
	TrafficLight    ServerTraffic = "light"
	TrafficModerate ServerTraffic = "moderate"
	TrafficHeavy    ServerTraffic = "heavy"
)

// ServerDnsUpstream specifies upstream recursive DNS.
type ServerDnsUpstream string

const (
	UpstreamCloudflare ServerDnsUpstream = "cf"
	UpstreamGoogle     ServerDnsUpstream = "google"
	UpstreamCombined   ServerDnsUpstream = "both"
)

// ServerHardwareProfile holds server capacity and operational configuration.
type ServerHardwareProfile struct {
	CPUCores             int                  `json:"cpu_cores"`
	RAMMB                int                  `json:"ram_mb"`
	NetworkMbps          int                  `json:"network_mbps"`
	ConcurrentUserCount  int                  `json:"concurrent_user_count"`
	Traffic              ServerTraffic        `json:"traffic"`
	EncryptionPreference EncryptionPreference `json:"encryption_preference"`
	UpstreamDNS          ServerDnsUpstream    `json:"upstream_dns"`
	LossyClients         bool                 `json:"lossy_clients"`
}

// ServerRecommendation holds calculated parameters for server daemon operation.
type ServerRecommendation struct {
	DataEncryptionMethod            uint8    `json:"data_encryption_method"`
	DNSUpstreamServers              []string `json:"dns_upstream_servers"`
	UDPReaders                      int      `json:"udp_readers"`
	DNSRequestWorkers               int      `json:"dns_request_workers"`
	DeferredSessionWorkers          int      `json:"deferred_session_workers"`
	MaxConcurrentRequests           int      `json:"max_concurrent_requests"`
	DeferredSessionQueueLimit       int      `json:"deferred_session_queue_limit"`
	SocketBufferSizeBytes           int      `json:"socket_buffer_size_bytes"`
	SessionTimeoutSeconds           uint32   `json:"session_timeout_seconds"`
	DNSCacheMaxRecords              int      `json:"dns_cache_max_records"`
	PacketBlockControlDuplication   uint8    `json:"packet_block_control_duplication"`
	MaxPacketsPerBatch              int      `json:"max_packets_per_batch"`
	ArqWindowSize                   int      `json:"arq_window_size"`
	ArqDataNackMaxGap               int      `json:"arq_data_nack_max_gap"`
	ArqMaxDataRetries               int      `json:"arq_max_data_retries"`
	SocksConnectTimeoutSeconds      uint32   `json:"socks_connect_timeout_seconds"`
	Socks5FragmentStoreCapacity     int      `json:"socks5_fragment_store_capacity"`
	DNSFragmentStoreCapacity        int      `json:"dns_fragment_store_capacity"`
	SessionCleanupIntervalSeconds   uint32   `json:"session_cleanup_interval_seconds"`
	ClosedSessionRetentionSeconds   uint32   `json:"closed_session_retention_seconds"`
}

// AdviseClient produces optimized client tunnel recommendations.
func AdviseClient(p ClientHardwareProfile) ClientRecommendation {
	q := p.Quality.ReliabilityFactor()
	isLossy := p.Quality.IsLossy()
	isMobile := p.Connection == ConnMobile4g5g
	isStream := p.UseCase == UseCaseStream
	isDownload := p.UseCase == UseCaseDownload
	isMixed := p.UseCase == UseCaseMixed
	isChat := p.UseCase == UseCaseChat

	// 1. Encryption
	var encMethod uint8 = 1
	switch p.EncryptionPreference {
	case EncLight:
		encMethod = 1
	case EncBalanced:
		encMethod = 2
	case EncStrong:
		encMethod = 5
	}

	// 2. Duplication
	var dup uint8 = 1
	if isLossy {
		dup = 4
	} else if q <= 0.8 {
		dup = 2
	}
	if isMobile && dup < 3 {
		dup = 3
	}
	setupDup := dup + 1
	if setupDup > 8 {
		setupDup = 8
	}

	// 3. Strategy
	var strat uint8 = 0
	if isLossy {
		strat = 3
	} else {
		switch p.ResolverCensus {
		case CensusMany:
			strat = 4
		case CensusMedium:
			strat = 3
		default:
			strat = 0
		}
	}

	// 4. Failover
	var failoverThresh, failoverCool uint32 = 3, 8
	if isLossy {
		failoverThresh = 2
		failoverCool = 4
	}

	// 5. MTU
	var minUp, minDn, maxUp, maxDn uint16
	switch p.MtuPreference {
	case MtuPrefStable:
		minUp, minDn, maxUp, maxDn = 25, 50, 60, 200
	case MtuPrefSpeed:
		minUp, minDn, maxUp, maxDn = 60, 120, 220, 700
	default:
		minUp, minDn, maxUp, maxDn = 40, 100, 150, 500
	}

	// 6. MTU test parallelism
	para := 16
	switch p.ResolverCensus {
	case CensusMany:
		para = 64
	case CensusMedium:
		para = 32
	}
	if p.CPUCores <= 2 && para > 16 {
		para = 16
	}
	if p.CPUCores <= 1 && para > 8 {
		para = 8
	}

	var mtuRetries, mtuTimeout uint32 = 2, 2
	if isLossy {
		mtuRetries = 3
		mtuTimeout = 3
	}

	// 7. Workers
	maxWorkers := p.CPUCores - 1
	if maxWorkers < 1 {
		maxWorkers = 1
	}
	rw := 2
	switch p.ResolverCensus {
	case CensusMany:
		rw = int(math.Min(float64(maxWorkers), 4))
	case CensusMedium:
		rw = int(math.Min(float64(maxWorkers), 3))
	default:
		rw = int(math.Min(float64(maxWorkers), 2))
	}
	if rw < 2 {
		rw = 2
	}
	if isStream || isDownload {
		if rw < 3 {
			rw = 3
		}
		if rw > maxWorkers+1 {
			rw = maxWorkers + 1
		}
	}
	procWorkers := rw - 1
	if procWorkers < 2 {
		procWorkers = 2
	}

	// 8. Buffers and Channels
	txSz, rxSz := 8192, 12288
	if p.RAMMB <= 512 {
		txSz, rxSz = 4096, 4096
	} else if p.RAMMB <= 2048 {
		txSz, rxSz = 8192, 8192
	}
	if (isStream || isDownload || isMixed) && p.RAMMB >= 2048 {
		txSz, rxSz = 16384, 16384
	}
	if isChat && p.RAMMB <= 2048 {
		txSz, rxSz = 4096, 4096
	}

	// 9. UDP Pool
	poolSz := 256
	switch p.ResolverCensus {
	case CensusMany:
		poolSz = 64
	case CensusMedium:
		poolSz = 128
	}
	if p.RAMMB <= 512 && poolSz > 32 {
		poolSz = 32
	} else if p.RAMMB <= 2048 && poolSz > 64 {
		poolSz = 64
	}

	// 10. Compression
	var upComp, dnComp uint8 = 0, 0
	if isStream || isDownload || isMixed {
		upComp, dnComp = 2, 2
	} else if isLossy || isMobile {
		upComp, dnComp = 1, 1
	}

	// 11. ARQ
	arqWin, arqGap, arqRetries, arqRto := 600, 32, 1000, 3.0
	if isLossy {
		arqWin, arqGap, arqRetries, arqRto = 1000, 64, 1500, 6.0
	} else if isStream || isDownload {
		arqWin, arqGap, arqRetries, arqRto = 800, 48, 1200, 4.0
	}

	// 12. Ping
	pingAggr, pingLazy, pingCool := 0.25, 0.80, 2.0
	if isStream {
		pingAggr, pingLazy, pingCool = 0.15, 0.5, 1.5
	} else if isChat {
		pingAggr, pingLazy, pingCool = 0.30, 1.0, 3.0
	} else if isLossy {
		pingAggr, pingLazy, pingCool = 0.20, 0.75, 2.0
	}

	// 13. Dispatcher Idle Poll
	dispInterval := 0.020
	if p.CPUCores <= 1 {
		dispInterval = 0.050
	} else if p.CPUCores <= 2 {
		dispInterval = 0.030
	} else if isStream || isDownload {
		dispInterval = 0.010
	}

	return ClientRecommendation{
		DataEncryptionMethod:              encMethod,
		PacketDuplicationCount:            dup,
		SetupPacketDuplicationCount:       setupDup,
		ResolverBalancingStrategy:         strat,
		StreamResolverFailoverThreshold:   failoverThresh,
		StreamResolverFailoverCooldownSec: failoverCool,
		MinUploadMTU:                      minUp,
		MinDownloadMTU:                    minDn,
		MaxUploadMTU:                      maxUp,
		MaxDownloadMTU:                    maxDn,
		MtuTestParallelism:                para,
		MtuTestRetries:                    mtuRetries,
		MtuTestTimeoutSec:                 mtuTimeout,
		TunnelReaderWorkers:               rw,
		TunnelWriterWorkers:               rw,
		TunnelProcessWorkers:              procWorkers,
		TxChannelSize:                     txSz,
		RxChannelSize:                     rxSz,
		ResolverUDPConnectionPoolSize:     poolSz,
		UploadCompressionType:             upComp,
		DownloadCompressionType:           dnComp,
		ArqWindowSize:                     arqWin,
		ArqDataNackMaxGap:                 arqGap,
		ArqMaxDataRetries:                 arqRetries,
		ArqMaxRtoSec:                      arqRto,
		PingAggressiveIntervalSec:         pingAggr,
		PingLazyIntervalSec:               pingLazy,
		PingCooldownIntervalSec:           pingCool,
		DispatcherIdlePollIntervalSec:     dispInterval,
	}
}

// AdviseServer produces optimized server tunnel recommendations.
func AdviseServer(p ServerHardwareProfile) ServerRecommendation {
	cpuFactor := 1
	if p.CPUCores >= 8 {
		cpuFactor = 4
	} else if p.CPUCores >= 4 {
		cpuFactor = 2
	}

	ramFactor := 1
	if p.RAMMB >= 4096 {
		ramFactor = 4
	} else if p.RAMMB >= 2048 {
		ramFactor = 2
	}

	isHeavy := p.Traffic == TrafficHeavy
	isMultiUser := p.ConcurrentUserCount >= 5
	isLossy := p.LossyClients

	// 1. Encryption
	var encMethod uint8 = 1
	switch p.EncryptionPreference {
	case EncLight:
		encMethod = 1
	case EncBalanced:
		encMethod = 2
	case EncStrong:
		encMethod = 5
	}

	// 2. Upstream DNS
	var upstreams []string
	switch p.UpstreamDNS {
	case UpstreamGoogle:
		upstreams = []string{"8.8.8.8:53", "8.8.4.4:53"}
	case UpstreamCombined:
		upstreams = []string{"1.1.1.1:53", "1.0.0.1:53", "8.8.8.8:53", "8.8.4.4:53"}
	default:
		upstreams = []string{"1.1.1.1:53", "1.0.0.1:53"}
	}

	// 3. Readers and workers
	udpReaders := 2
	if cpuFactor > udpReaders {
		udpReaders = cpuFactor
	}
	dnsWorkers := 4
	if cpuFactor*2 > dnsWorkers {
		dnsWorkers = cpuFactor * 2
	}
	if isMultiUser {
		if udpReaders < 3 {
			udpReaders = 3
		}
		if dnsWorkers < 6 {
			dnsWorkers = 6
		}
	}
	if isHeavy {
		if udpReaders < 4 {
			udpReaders = 4
		}
		if dnsWorkers < 8 {
			dnsWorkers = 8
		}
	}

	// 4. Deferred workers
	defWorkers := 2
	if cpuFactor > defWorkers {
		defWorkers = cpuFactor
	}
	if isMultiUser && defWorkers < 3 {
		defWorkers = 3
	}

	// 5. Max concurrent requests
	maxReq := 4096
	if ramFactor >= 2 {
		maxReq = 8192
	}
	if ramFactor >= 4 {
		maxReq = 16384
	}
	if isMultiUser && isHeavy {
		maxReq = maxReq * 2
		if maxReq > 32768 {
			maxReq = 32768
		}
	}

	// 6. Deferred queue limit
	defQueue := 2048
	if ramFactor >= 2 {
		defQueue = 4096
	}
	if isMultiUser {
		defQueue = defQueue * 2
		if defQueue > 14336 {
			defQueue = 14336
		}
	}

	// 7. Socket buffer
	sockBuf := 4 * 1024 * 1024
	if p.RAMMB >= 2048 {
		sockBuf = 8 * 1024 * 1024
	}
	if p.RAMMB >= 4096 && isHeavy {
		sockBuf = 16 * 1024 * 1024
	}

	// 8. Session timeout
	var sesTimeout uint32 = 300
	if p.ConcurrentUserCount >= 15 {
		sesTimeout = 180
	}

	// 9. DNS cache
	dnsCache := 10000
	if ramFactor >= 4 {
		dnsCache = 100000
	} else if ramFactor >= 2 {
		dnsCache = 50000
	}

	// 10. Lossy control duplication
	var ctrlDup uint8 = 1
	batchPackets := 10
	if isLossy {
		ctrlDup = 3
		batchPackets = 12
	}

	// 11. ARQ
	arqWin, arqGap, arqRetries := 600, 32, 1000
	if isLossy || isHeavy {
		arqWin, arqGap, arqRetries = 1000, 64, 1500
	}

	// 12. SOCKS connect timeout
	var connectTimeout uint32 = 120
	if p.ConcurrentUserCount >= 15 {
		connectTimeout = 60
	}

	// 13. Fragment store capacity
	socks5Frag, dnsFrag := 1024, 512
	if isMultiUser {
		socks5Frag, dnsFrag = 2048, 1024
	}

	// 14. Session cleanup & retention
	var cleanupInterval, retention uint32 = 30, 600
	if p.ConcurrentUserCount >= 15 {
		cleanupInterval, retention = 15, 300
	}

	return ServerRecommendation{
		DataEncryptionMethod:          encMethod,
		DNSUpstreamServers:            upstreams,
		UDPReaders:                    udpReaders,
		DNSRequestWorkers:             dnsWorkers,
		DeferredSessionWorkers:        defWorkers,
		MaxConcurrentRequests:         maxReq,
		DeferredSessionQueueLimit:     defQueue,
		SocketBufferSizeBytes:         sockBuf,
		SessionTimeoutSeconds:         sesTimeout,
		DNSCacheMaxRecords:            dnsCache,
		PacketBlockControlDuplication: ctrlDup,
		MaxPacketsPerBatch:            batchPackets,
		ArqWindowSize:                 arqWin,
		ArqDataNackMaxGap:             arqGap,
		ArqMaxDataRetries:             arqRetries,
		SocksConnectTimeoutSeconds:    connectTimeout,
		Socks5FragmentStoreCapacity:   socks5Frag,
		DNSFragmentStoreCapacity:      dnsFrag,
		SessionCleanupIntervalSeconds: cleanupInterval,
		ClosedSessionRetentionSeconds: retention,
	}
}
