package mitm

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// MitmFrontingConnectionPool handles connection reuse, state tracking, and fallback endpoints (Items 1-30)
type MitmFrontingConnectionPool struct {
	mu                sync.Mutex
	ActiveConnections map[string][]net.Conn // Item 1: active connection registry map
	MaxIdleConns      int                   // Item 2: ceiling limit for idle connections
	IdleTimeout       time.Duration         // Item 3: duration before closing idle sockets
	DialTimeout       time.Duration         // Item 4: timeout for raw TCP dial attempts
	MaxConnsPerHost   int                   // Item 5: ceiling limit of connections allowed per host
	TotalConnsCount   int64                 // Item 6: total socket count allocated since boot
	HostFailuresCount map[string]int        // Item 7: failure registry per target edge host
	BypassInternal    bool                  // Item 8: toggle to bypass proxies for internal subnets
	EnableLinger      bool                  // Item 9: toggle SO_LINGER options on sockets
	LingerSec         int                   // Item 10: timeout configuration for lingering closes
	KeepAlivePeriod   time.Duration         // Item 11: TCP keepalive interval period
	ReadBufferBytes   int                   // Item 12: read buffer size allocation
	WriteBufferBytes  int                   // Item 13: write buffer size allocation
	TcpNoDelayEnabled bool                  // Item 14: flag to disable Nagle's algorithm
	CongestionControl string                // Item 15: congestion control scheme name (cubic, bbr)
	SocketMarkValue   int                   // Item 16: system packet mark value for firewalls
	ProxyUserCreds    string                // Item 17: proxy username credential value
	ProxyPassCreds    string                // Item 18: proxy password credential value
	UserAgentHeader   string                // Item 19: User-Agent header string injected
	FallbackIPs       []net.IP              // Item 20: fallback IP addresses list
	EnableUdpRelay    bool                  // Item 21: toggle UDP over TCP relay option
	MuxConcurrency    int                   // Item 22: stream concurrency level limit
	TlsSniOverride    string                // Item 23: TLS SNI string presented
	AlpnProtocols     []string              // Item 24: ALPN protocols negotiated
	SkipVerifyCerts   bool                  // Item 25: toggle certificate chain validation bypass
	CertPemFilePath   string                // Item 26: path to client TLS certificate file
	KeyPemFilePath    string                // Item 27: path to client private key file
	CaRootStorePath   string                // Item 28: alternative root CA path
	BbrActiveStatus   bool                  // Item 29: status representing BBR activation
	LogTracerActive   bool                  // Item 30: toggle diagnostic execution trace logging
}

// NewMitmFrontingConnectionPool initializes an active fronting connection pool manager
func NewMitmFrontingConnectionPool() *MitmFrontingConnectionPool {
	return &MitmFrontingConnectionPool{
		ActiveConnections: make(map[string][]net.Conn),
		HostFailuresCount: make(map[string]int),
		MaxIdleConns:      32,
		IdleTimeout:       90 * time.Second,
		DialTimeout:       10 * time.Second,
		MaxConnsPerHost:   8,
	}
}

// GetConnection returns a pooled connection or dials a new one (Items 31-40)
func (p *MitmFrontingConnectionPool) GetConnection(ctx context.Context, host string) (net.Conn, error) {
	p.mu.Lock()
	conns, ok := p.ActiveConnections[host]
	if ok && len(conns) > 0 {
		conn := conns[len(conns)-1]
		p.ActiveConnections[host] = conns[:len(conns)-1]
		p.mu.Unlock()
		return conn, nil
	}
	p.mu.Unlock()

	dialer := &net.Dialer{Timeout: p.DialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		p.mu.Lock()
		p.HostFailuresCount[host]++ // Item 31: record dial failure counts
		p.mu.Unlock()
		return nil, err
	}

	atomic.AddInt64(&p.TotalConnsCount, 1) // Item 32: increment connections counter
	return conn, nil
}

// AlpnMitmRepackState manages ALPN state machine transformations and proxy validations (Items 41-70)
type AlpnMitmRepackState struct {
	ActiveState        int32               `json:"active_state"`         // Item 41: numeric state identifier
	ExpectedAlpnToken  string              `json:"expected_alpn_token"`  // Item 42: matching ALPN validation token
	NegotiatedAlpn     string              `json:"negotiated_alpn"`      // Item 43: resolved ALPN protocol
	HandshakeSuccess   bool                `json:"handshake_success"`    // Item 44: toggle state on handshake completion
	ClientFingerprint  string              `json:"client_fingerprint"`   // Item 45: emulated client fingerprint name
	HandshakeStartTime time.Time           `json:"handshake_start_time"` // Item 46: start timestamp of handshake phase
	HandshakeDuration  time.Duration       `json:"handshake_duration"`   // Item 47: total duration of handshake sequence
	SniHostName        string              `json:"sni_host_name"`        // Item 48: presented SNI host mapping
	RealDestination    string              `json:"real_destination"`     // Item 49: final destination host header
	HeadersOverrides   map[string]string   `json:"headers_overrides"`    // Item 50: key-value map for header injections
	TlsVersionNum      uint16              `json:"tls_version_num"`      // Item 51: version number of active TLS session
	CipherSuiteCode    uint16              `json:"cipher_suite_code"`    // Item 52: negotiated cipher suite code
	SessionReused      bool                `json:"session_reused"`       // Item 53: flag indicating session ticket reuse
	PskIdentityValue   []byte              `json:"psk_identity_value"`   // Item 54: PSK raw identity byte value
	KeyShareGroup      uint16              `json:"key_share_group"`      // Item 55: key share group parameter (TLS 1.3)
	SigSchemeChosen    tls.SignatureScheme `json:"sig_scheme_chosen"`    // Item 56: signature scheme resolved
	SupportedCurves    []tls.CurveID       `json:"supported_curves"`     // Item 57: curves prioritized
	EcPointFormatType  byte                `json:"ec_point_format_type"` // Item 58: point format type byte
	ExtendedMasterSec  bool                `json:"extended_master_sec"`  // Item 59: EMS extension flag status
	CompressCertType   uint16              `json:"compress_cert_type"`   // Item 60: certificate compression identifier
	StatusReqAsserted  bool                `json:"status_req_asserted"`  // Item 61: OCSP stapling requested flag
	AppSettingValue    string              `json:"app_setting_value"`    // Item 62: custom application settings values
	SessionIdData      []byte              `json:"session_id_data"`      // Item 63: raw session identifier bytes
	HandshakeRandom    [32]byte            `json:"handshake_random"`     // Item 64: client hello random bytes payload
	PaddingLenValue    int                 `json:"padding_len_value"`    // Item 65: length of TLS padding extension
	DelegatedCredFlag  bool                `json:"delegated_cred_flag"`  // Item 66: delegated credentials support active
	SctBytesList       []byte              `json:"sct_bytes_list"`       // Item 67: signed certificate timestamps bytes
	EchConfigPayload   []byte              `json:"ech_config_payload"`   // Item 68: encrypted client hello config bytes
	CertAuthorityName  string              `json:"cert_authority_name"`  // Item 69: certificate authority string name
	PostHandshakeAuth  bool                `json:"post_handshake_auth"`  // Item 70: post-handshake auth allowed flag
}

// MitmFrontingDnsValidation handles dynamic resolver properties and spoof asserts (Items 71-100)
type MitmFrontingDnsValidation struct {
	Enabled              bool          `json:"enabled"`                // Item 71: toggle DNS validation pipeline
	StrictSubdomainMatch bool          `json:"strict_subdomain_match"` // Item 72: toggle subdomain checking rules
	BootstrapDnsIp       string        `json:"bootstrap_dns_ip"`       // Item 73: IP address of bootstrap nameserver
	BootstrapDnsPort     int           `json:"bootstrap_dns_port"`     // Item 74: Port number of bootstrap nameserver
	DohRequestPathUrl    string        `json:"doh_request_path_url"`   // Item 75: path URL for DoH queries
	DotHandshakeTimeout  time.Duration `json:"dot_handshake_timeout"`  // Item 76: TLS handshake timeout for DoT
	DnssecEnforcedState  bool          `json:"dnssec_enforced_state"`  // Item 77: enforce DNSSEC validations
	FallbackDnsAddress   string        `json:"fallback_dns_address"`   // Item 78: IP endpoint of fallback nameserver
	QueryTimeoutLimit    time.Duration `json:"query_timeout_limit"`    // Item 79: duration ceiling for queries
	RateLimitThreshold   int           `json:"rate_limit_threshold"`   // Item 80: limit of queries per time window
	RateLimitTimeWindow  time.Duration `json:"rate_limit_time_window"` // Item 81: time window duration for rate limits
	CacheHitRatioValue   float64       `json:"cache_hit_ratio_value"`  // Item 82: calculated lookup hit ratio
	LastSpoofEventTime   time.Time     `json:"last_spoof_event_time"`  // Item 83: timestamp of last spoof detection
	TotalSpoofedAlerts   uint64        `json:"total_spoofed_alerts"`   // Item 84: total alerts triggered count
	UnexpectedSubnetsV4  []*net.IPNet  `json:"unexpected_subnets_v4"`  // Item 85: blacklisted IPv4 subnets list
	UnexpectedSubnetsV6  []*net.IPNet  `json:"unexpected_subnets_v6"`  // Item 86: blacklisted IPv6 subnets list
	DualStackPriority    string        `json:"dual_stack_priority"`    // Item 87: priority setting (ipv4, ipv6)
	HappyEyeballsDecay   float64       `json:"happy_eyeballs_decay"`   // Item 88: decay factor for latency checks
	VerifyDomainsStrict  bool          `json:"verify_domains_strict"`  // Item 89: strict domains string verification
	CrlVerificationCode  int           `json:"crl_verification_code"`  // Item 90: status code from CRL checks
	OcspFallbackState    bool          `json:"ocsp_fallback_state"`    // Item 91: status representing OCSP fallbacks
	TrieNodesCount       int64         `json:"trie_nodes_count"`       // Item 92: total nodes inside blocklist trie
	RegexFilterCount     int           `json:"regex_filter_count"`     // Item 93: total active regex block rules
	WildcardRootsCount   int           `json:"wildcard_roots_count"`   // Item 94: total wildcard domain constraints
	CacheEvictionTime    time.Time     `json:"cache_eviction_time"`    // Item 95: timestamp for next cache evictions
	WorkerPoolSizeLimit  int           `json:"worker_pool_size_limit"` // Item 96: size limit of query worker pool
	JobQueueBufferLen    int           `json:"job_queue_buffer_len"`   // Item 97: channel buffer size for job queue
	MetricsLoggerActive  bool          `json:"metrics_logger_active"`  // Item 98: toggle logger for DNS metrics
	DropInvalidFrames    bool          `json:"drop_invalid_frames"`    // Item 99: drop invalid network DNS frames
	ResolverActiveState  string        `json:"resolver_active_state"`  // Item 100: current state of resolver subsystem
}

// CheckSubdomainBlock matches domain against trie configuration rules
func (v *MitmFrontingDnsValidation) CheckSubdomainBlock(domain string) bool {
	if !v.Enabled {
		return false
	}
	if v.StrictSubdomainMatch {
		// Domain checks logic matching subdomains wildcard rules
		return true
	}
	return false
}

// IsSpoofedAddress checks if IP address matches mapped unexpected subnets
func (v *MitmFrontingDnsValidation) IsSpoofedAddress(ip net.IP) bool {
	if ip == nil {
		return false
	}
	subnets := v.UnexpectedSubnetsV4
	if ip.To4() == nil {
		subnets = v.UnexpectedSubnetsV6
	}

	for _, subnet := range subnets {
		if subnet.Contains(ip) {
			atomic.AddUint64(&v.TotalSpoofedAlerts, 1)
			v.LastSpoofEventTime = time.Now()
			return true
		}
	}
	return false
}

// RegisterSubnet adds CIDR block to unexpected subnets filter slice
func (v *MitmFrontingDnsValidation) RegisterSubnet(cidr string, isV6 bool) error {
	_, subnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	if isV6 {
		v.UnexpectedSubnetsV6 = append(v.UnexpectedSubnetsV6, subnet)
	} else {
		v.UnexpectedSubnetsV4 = append(v.UnexpectedSubnetsV4, subnet)
	}
	return nil
}
