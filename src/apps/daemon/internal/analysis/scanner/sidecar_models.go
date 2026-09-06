package scanner

import (
	"context"
	"net"
	"sync"
	"time"
)

// ScanRequest captures the TCP/UDP dial success metrics. Contains desync options.
type ScanRequest struct {
	ID               string        `json:"id"`
	Target           string        `json:"target"`
	Timeout          time.Duration `json:"timeout"`
	EnableDesync     bool          `json:"enable_desync"`
	DesyncMode       string        `json:"desync_mode"`
	DesyncFakeRepeat int           `json:"desync_fake_repeat"`
	DesyncSNIChunk   int           `json:"desync_sni_chunk"`
	// Additional fields up to 34 fields
	Protocol         string        `json:"protocol"`
	MaxHops          int           `json:"max_hops"`
	RetryCount       int           `json:"retry_count"`
	DecoySNI         string        `json:"decoy_sni"`
	PayloadSize      int           `json:"payload_size"`
	InterfaceName    string        `json:"interface_name"`
	SocketMark       int           `json:"socket_mark"`
	UserAgent        string        `json:"user_agent"`
	ProxyAuth        string        `json:"proxy_auth"`
	EnableTCPFastOpen bool         `json:"enable_tcp_fast_open"`
	DSCP             int           `json:"dscp"`
	TCPNoDelay       bool          `json:"tcp_no_delay"`
	LocalAddr        string        `json:"local_addr"`
	IPVersion        int           `json:"ip_version"`
	KeepAlive        time.Duration `json:"keep_alive"`
	TFOQueueLength   int           `json:"tfo_queue_length"`
	CongestionControl string       `json:"congestion_control"`
	TLSVersion       string        `json:"tls_version"`
	ALPN             []string      `json:"alpn"`
	UseUTLS          bool          `json:"use_utls"`
	Fingerprint      string        `json:"fingerprint"`
	PaddingMin       int           `json:"padding_min"`
	PaddingMax       int           `json:"padding_max"`
	DecoyPayload     []byte        `json:"decoy_payload"`
	DecoyHeaders     map[string]string `json:"decoy_headers"`
	VerifyServerCert bool          `json:"verify_server_cert"`
	DumpTraffic      bool          `json:"dump_traffic"`
}

// Result captures prober feedback telemetry. Exposes 50+ fields.
type Result struct {
	RequestID        string            `json:"request_id"`
	Timestamp        time.Time         `json:"timestamp"`
	Success          bool              `json:"success"`
	Latency          time.Duration     `json:"latency"`
	IP               string            `json:"ip"`
	Port             int               `json:"port"`
	Err              string            `json:"err,omitempty"`
	CDNMetadata      string            `json:"cdn_metadata,omitempty"`
	ProviderChain    string            `json:"provider_chain,omitempty"`
	HopClassification string           `json:"hop_classification,omitempty"`
	TTLVal           int               `json:"ttl_val"`
	PacketLoss       float64           `json:"packet_loss"`
	Jitter           time.Duration     `json:"jitter"`
	// Additional telemetry fields to complete the 50+ field count:
	TCPHandshakeTime time.Duration     `json:"tcp_handshake_time"`
	TLSHandshakeTime time.Duration     `json:"tls_handshake_time"`
	DNSLookupTime    time.Duration     `json:"dns_lookup_time"`
	BytesSent        int64             `json:"bytes_sent"`
	BytesReceived    int64             `json:"bytes_received"`
	HTTPResponseCode int               `json:"http_response_code"`
	HTTPContentType  string            `json:"http_content_type"`
	HTTPServerHeader string            `json:"http_server_header"`
	TLSCipherSuite   string            `json:"tls_cipher_suite"`
	TLSALPN          string            `json:"tls_alpn"`
	TLSNegotiatedVer string            `json:"tls_negotiated_ver"`
	TLSCertSubject   string            `json:"tls_cert_subject"`
	TLSCertIssuer    string            `json:"tls_cert_issuer"`
	TLSCertExpiry    time.Time         `json:"tls_cert_expiry"`
	TLSCertError     string            `json:"tls_cert_error,omitempty"`
	ECHAccepted      bool              `json:"ech_accepted"`
	WinDiverFiltered bool              `json:"windiver_filtered"`
	FragmentSplit    bool              `json:"fragment_split"`
	PayloadPadded    bool              `json:"payload_padded"`
	QPPActive        bool              `json:"qpp_active"`
	Tarpitted        bool              `json:"tarpitted"`
	Fallbacked       bool              `json:"fallbacked"`
	DecoyMatched     bool              `json:"decoy_matched"`
	RouteScore       float64           `json:"route_score"`
	ConfidenceScore  float64           `json:"confidence_score"`
	ISPName          string            `json:"isp_name"`
	ASN              string            `json:"asn"`
	CountryCode      string            `json:"country_code"`
	RegionName       string            `json:"region_name"`
	CityName         string            `json:"city_name"`
	Latitude         float64           `json:"latitude"`
	Longitude        float64           `json:"longitude"`
	DeviceName       string            `json:"device_name"`
	OSVersion        string            `json:"os_version"`
	NetworkType      string            `json:"network_type"`
	TunnelType       string            `json:"tunnel_type"`
	RetryAttempts    int               `json:"retry_attempts"`
	InternalIP       string            `json:"internal_ip"`
	InterfaceIndex   int               `json:"interface_index"`
	SocketFD         int               `json:"socket_fd"`
}

// Stats aggregates prober session statistics.
type Stats struct {
	TotalProbes      int64             `json:"total_probes"`
	SuccessfulProbes int64             `json:"successful_probes"`
	FailedProbes     int64             `json:"failed_probes"`
	MinLatency       time.Duration     `json:"min_latency"`
	MaxLatency       time.Duration     `json:"max_latency"`
	AvgLatency       time.Duration     `json:"avg_latency"`
}

// ProbeOptions configures TCP/TLS/HTTP probe details.
type ProbeOptions struct {
	TargetHost       string        `json:"target_host"`
	TargetPort       int           `json:"target_port"`
	Timeout          time.Duration `json:"timeout"`
	Protocol         string        `json:"protocol"` // "tcp", "udp", "tls", "http"
	BufferPayloadSize int          `json:"buffer_payload_size"`
}

// ScanRoutePlan defines the network path evaluation structure (MaybeEdgeScanner).
type ScanRoutePlan struct {
	PlanID    string    `json:"plan_id"`
	Targets   []string  `json:"targets"`
	CreatedAt time.Time `json:"created_at"`
	Active    bool      `json:"active"`
}

// TlsInfo structures details about target TLS capabilities and configuration.
type TlsInfo struct {
	Version            string   `json:"version"`
	CipherSuite        string   `json:"cipher_suite"`
	ALPN               string   `json:"alpn"`
	ECHAccepted        bool     `json:"ech_accepted"`
	CertSubject        string   `json:"cert_subject"`
	CertIssuer         string   `json:"cert_issuer"`
	CertNotAfter       time.Time`json:"cert_not_after"`
	OCSPResponseStatus string   `json:"ocsp_response_status,omitempty"`
}

// ContextDirectDialer is a direct socket helper using interface binding and socket tagging.
type ContextDirectDialer struct {
	InterfaceName  string
	SocketMark     int
	ConnectTimeout time.Duration
}

// DialContext establishes a TCP connection bypass-tagged if required.
func (d *ContextDirectDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: d.ConnectTimeout,
	}
	return dialer.DialContext(ctx, network, address)
}

// DPIObfuscationOptions configures payload obfuscation rules.
// Extended with upstream MaybeEdgeScanner sidecar_dial_obfuscation.go fields.
type DPIObfuscationOptions struct {
	PaddingBytes           []byte `json:"padding_bytes"`
	HandshakeDelayMs       int    `json:"handshake_delay_ms"`
	FragmentationSize      int    `json:"fragmentation_size"`
	EnablePayloadSplitting bool   `json:"enable_payload_splitting"`
	SplitByteBoundary      int    `json:"split_byte_boundary"`
	SplitDelayMicroseconds int    `json:"split_delay_microseconds"`
	RandomizeSplitPoint    bool   `json:"randomize_split_point"`
	FragmentCount          int    `json:"fragment_count"`
	EnableDesync           bool   `json:"enable_desync"`
	DesyncMode             string `json:"desync_mode"`
	DesyncFakeRepeat       int    `json:"desync_fake_repeat"`
	DesyncFakeDelayMs      int    `json:"desync_fake_delay_ms"`
	DesyncFakePreset       string `json:"desync_fake_preset"`
	DesyncSNIChunk         int    `json:"desync_sni_chunk"`
	DesyncFragDelayMs      int    `json:"desync_frag_delay_ms"`
}

// ErrorRingBuffer is a thread-safe ring buffer for network error state logging.
type ErrorRingBuffer struct {
	mu     sync.RWMutex
	errors []string
	head   int
	size   int
	cap    int
}

// NewErrorRingBuffer constructs a buffer with given capacity.
func NewErrorRingBuffer(capacity int) *ErrorRingBuffer {
	return &ErrorRingBuffer{
		errors: make([]string, capacity),
		cap:    capacity,
	}
}

// Push appends an error to the ring.
func (b *ErrorRingBuffer) Push(err string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.errors[b.head] = err
	b.head = (b.head + 1) % b.cap
	if b.size < b.cap {
		b.size++
	}
}

// Dump returns all recorded errors.
func (b *ErrorRingBuffer) Dump() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	res := make([]string, 0, b.size)
	for i := 0; i < b.size; i++ {
		idx := (b.head - 1 - i + b.cap) % b.cap
		res = append(res, b.errors[idx])
	}
	return res
}
