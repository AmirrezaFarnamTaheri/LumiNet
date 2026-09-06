package mitm

import (
	"crypto/x509"
	"net"
	"sync"
	"time"
)

// MitmFrontingRepackerOptions configures Host headers, HTTP request repacking, and body injections (Items 1-35)
type MitmFrontingRepackerOptions struct {
	mu                    sync.RWMutex
	TargetHostHeader      string            `json:"target_host_header"`       // Item 1: target Host header value
	UserAgentVariant      string            `json:"user_agent_variant"`       // Item 2: User-Agent variant identifier
	CustomRequestPath     string            `json:"custom_request_path"`      // Item 3: custom request path override
	QueryParameters       map[string]string `json:"query_parameters"`         // Item 4: custom query parameters map
	HeaderInjections      map[string]string `json:"header_injections"`        // Item 5: map of custom headers injected
	BodyInjectionPattern  []byte            `json:"body_injection_pattern"`   // Item 6: raw bytes injected into request bodies
	EnablePayloadObfs     bool              `json:"enable_payload_obfs"`      // Item 7: toggle payload obfuscation option
	PayloadObfsSalt       []byte            `json:"payload_obfs_salt"`        // Item 8: custom salt for payload obfuscator
	ChunkedEncoding       bool              `json:"chunked_encoding"`         // Item 9: toggle HTTP chunked encoding
	MaxChunkLength        int               `json:"max_chunk_length"`         // Item 10: limit of individual HTTP chunk lengths
	TlsServerName         string            `json:"tls_server_name"`          // Item 11: ServerName override for TLS Hello
	AlpnNegotiatedProtos  []string          `json:"alpn_negotiated_protos"`   // Item 12: ALPN protocol strings
	TlsSkipVerify         bool              `json:"tls_skip_verify"`          // Item 13: bypass target endpoint TLS checks
	OutboundProtocolType  string            `json:"outbound_protocol_type"`   // Item 14: outbound transport (h2, http1, ws)
	WebSocketEarlyData    bool              `json:"web_socket_early_data"`    // Item 15: enable WebSocket early data writes
	GrpcServicePath       string            `json:"grpc_service_path"`        // Item 16: service path namespace for gRPC
	OutboundDialAddress   string            `json:"outbound_dial_address"`    // Item 17: real target IP dial destination
	DialTimeoutDuration   time.Duration     `json:"dial_timeout_duration"`    // Item 18: connection dial timeout limit
	TcpKeepAliveInterval  time.Duration     `json:"tcp_keep_alive_interval"`  // Item 19: keepalive probe interval on sockets
	SocketWriteBufferSize int               `json:"socket_write_buffer_size"` // Item 20: buffer size allocated for writes
	SocketReadBufferSize  int               `json:"socket_read_buffer_size"`  // Item 21: buffer size allocated for reads
	LingerCloseTimeout    int               `json:"linger_close_timeout"`     // Item 22: SO_LINGER duration configured
	IpTOSClassValue       int               `json:"ip_tos_class_value"`       // Item 23: IP TOS bits class value
	EnableBbrCongestion   bool              `json:"enable_bbr_congestion"`    // Item 24: toggle BBR socket congestion control
	SocketMarkIdentifier  int               `json:"socket_mark_identifier"`   // Item 25: packet mark value for routing
	HaProxyProtocolVer    int               `json:"ha_proxy_protocol_ver"`    // Item 26: PROXY protocol version override
	ProxyCredentialsUser  string            `json:"proxy_credentials_user"`   // Item 27: proxy auth username override
	ProxyCredentialsPass  string            `json:"proxy_credentials_pass"`   // Item 28: proxy auth password override
	MaxStreamsPerSocket   int               `json:"max_streams_per_socket"`   // Item 29: concurrent streams multiplex limits
	FallbackRedirectUrl   string            `json:"fallback_redirect_url"`    // Item 30: fallback redirection URL
	StrictHostChecking    bool              `json:"strict_host_checking"`     // Item 31: toggle strict host match checking
	MaxDelayJitterMs      int               `json:"max_delay_jitter_ms"`      // Item 32: delay jitter padding threshold
	NetworkInterfaceBind  string            `json:"network_interface_bind"`   // Item 33: targeted bind interface name
	PreferIpv6Routes      bool              `json:"prefer_ipv6_routes"`       // Item 34: priority setting targeting IPv6 routes
	ConfigStateSignature  string            `json:"config_state_signature"`   // Item 35: hash signature of options block
}

// MitmFrontingTLSCertStore manages certificate files, root CAs, and target cert cache mappings (Items 36-70)
type MitmFrontingTLSCertStore struct {
	mu                     sync.RWMutex
	ParentCaCertBytes      []byte                    `json:"parent_ca_cert_bytes"`    // Item 36: raw root CA cert bytes
	ParentCaKeyBytes       []byte                    `json:"parent_ca_key_bytes"`     // Item 37: raw root CA private key bytes
	CertCacheDirectory     string                    `json:"cert_cache_directory"`    // Item 38: file path containing cached cert files
	MaxCacheEntryLimit     int                       `json:"max_cache_entry_limit"`   // Item 39: ceiling cap on cache memory size
	CertExpiryDuration     time.Duration             `json:"cert_expiry_duration"`    // Item 40: validity duration of dynamic certs
	CertificateVerifyPEM   string                    `json:"certificate_verify_pem"`  // Item 41: PEM certificate chain verify anchor
	PrivateKeyVerifyPEM    string                    `json:"private_key_verify_pem"`  // Item 42: PEM private key verify anchor
	SerialNumberCounter    int64                     `json:"serial_number_counter"`   // Item 43: incremental serial number for new certs
	OrganizationName       string                    `json:"organization_name"`       // Item 44: CN Organization name parameter
	OrganizationUnitName   string                    `json:"organization_unit_name"`  // Item 45: CN Organizational Unit name parameter
	CountryCodeString      string                    `json:"country_code_string"`     // Item 46: CN Country code parameter
	ProvinceStateString    string                    `json:"province_state_string"`   // Item 47: CN Province/State parameter
	LocalityCityString     string                    `json:"locality_city_string"`    // Item 48: CN Locality/City parameter
	ValidityOffsetHours    int                       `json:"validity_offset_hours"`   // Item 49: padding hours adjusting cert not_before
	AuthorityKeyIdBytes    []byte                    `json:"authority_key_id_bytes"`  // Item 50: authority key identifier byte slice
	SubjectKeyIdBytes      []byte                    `json:"subject_key_id_bytes"`    // Item 51: subject key identifier byte slice
	OcspResponderUrlPath   string                    `json:"ocsp_responder_url_path"` // Item 52: OCSP responder target URL
	CrlDistributionPath    string                    `json:"crl_distribution_path"`   // Item 53: revocation list distribution path
	StrictCaValidations    bool                      `json:"strict_ca_validations"`   // Item 54: toggle validation of signing root CAs
	TlsVersionMaxAllowed   uint16                    `json:"tls_version_max_allowed"` // Item 55: maximum TLS protocol version supported
	TlsVersionMinAllowed   uint16                    `json:"tls_version_min_allowed"` // Item 56: minimum TLS protocol version supported
	CurveIdPreferences     []x509.PublicKeyAlgorithm // Item 57: priority signature algorithm types
	MaxPathLenConstraint   int                       `json:"max_path_len_constraint"` // Item 58: intermediate path depth constraint limit
	PermittedDnsWildcard   []string                  `json:"permitted_dns_wildcard"`  // Item 59: allowed wildcard domains in SAN
	ExcludedDnsWildcard    []string                  `json:"excluded_dns_wildcard"`   // Item 60: excluded wildcard domains in SAN
	PermittedIPSubnets     []*net.IPNet              `json:"permitted_ip_subnets"`    // Item 61: allowed IP subnets in SAN
	ExcludedIPSubnets      []*net.IPNet              `json:"excluded_ip_subnets"`     // Item 62: excluded IP subnets in SAN
	CertKeyUsageMask       x509.KeyUsage             // Item 63: key usage mask flags
	CertExtKeyUsageMask    []x509.ExtKeyUsage        // Item 64: extended key usage flags slice
	BasicConstraintsFlag   bool                      `json:"basic_constraints_flag"` // Item 65: basic constraints extension flag
	CertSignatureAlgorithm x509.SignatureAlgorithm   // Item 66: signature algorithm resolver
	IssuerDistinguished    []byte                    `json:"issuer_distinguished"`     // Item 67: issuer DN byte data
	SubjectDistinguished   []byte                    `json:"subject_distinguished"`    // Item 68: subject DN byte data
	DynamicCertCacheMap    map[string]string         `json:"dynamic_cert_cache_map"`   // Item 69: cache map matching hosts to files
	CertStoreStatusActive  bool                      `json:"cert_store_status_active"` // Item 70: toggle status of TLS certificate store
}

// MitmFrontingCongestionConfig configures BBR congestion, write delays, and socket parameters (Items 71-100)
type MitmFrontingCongestionConfig struct {
	BbrEnabledToggles     bool          `json:"bbr_enabled_toggles"` // Item 71: toggle BBR socket options
	WriteDelayLimitMs     int           // Item 72: duration in ms before flushing socket writes
	SocketLingerDuration  time.Duration // Item 73: linger time options applied to sockets
	TcpProbeKeepAliveFreq time.Duration // Item 74: TCP keepalive probe frequency parameters
	MtuPaddingBytesCount  int           // Item 75: padding bytes count matching MTU limits
	MaxWriteMarginLimit   int64         // Item 76: ceiling margin bytes allocated for writes
	CongestionControlName string        // Item 77: active congestion name tag
	SocketMarkRouteTag    int           // Item 78: firewall routing identifier mark
	IpTOSClassBits        int           // Item 79: IP Type of Service bit configuration
	TCPFastOpenQueueSize  int           // Item 80: queue size limit for Fast Open connections
	OutboundBufferCeiling int           // Item 81: outbound socket buffer size ceiling limit
	InboundBufferCeiling  int           // Item 82: inbound socket buffer size ceiling limit
	FlushIntervalDuration time.Duration // Item 83: flush interval limit duration
	ZeroCopyTransferMode  bool          // Item 84: toggle zero-copy data operations
	SocketIdleTimeoutSec  int           // Item 85: timeout duration before closing idle sockets
	RetryAttemptsCeiling  int           // Item 86: dial attempt retry limits
	BaseBackoffIntervalMs int           // Item 87: base multiplier for exponential backoffs
	TotalSocketFailCounts uint64        // Item 88: dynamic count of socket failures recorded
	LastFailureRecordTime time.Time     // Item 89: timestamp tracking most recent socket failure
	MetricsLoggingActive  bool          // Item 90: toggle stats metrics collection
	Socks5UsernameAuth    string        // Item 91: username for SOCKS5 proxy authentications
	Socks5PasswordAuth    string        // Item 92: password for SOCKS5 proxy authentications
	HttpProxyUsernameAuth string        // Item 93: username for HTTP proxy authentications
	HttpProxyPasswordAuth string        // Item 94: password for HTTP proxy authentications
	DialTimeoutThreshold  time.Duration // Item 95: timeout threshold on dialer allocations
	HandshakeTimeoutLimit time.Duration // Item 96: timeout limit on TLS handshakes
	NetworkRoutingTag     string        // Item 97: routing tags mapped to network outbounds
	TrafficLimitBytes     uint64        // Item 98: byte limit of transfer quotas per socket
	WarningUsageThreshold float64       // Item 99: usage percentage threshold for alerts
	StatusActiveIndicator bool          // Item 100: toggle status of congestion subsystem
}
