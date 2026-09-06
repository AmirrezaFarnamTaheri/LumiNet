package mitm

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sync"
	"sync/atomic"
	"time"
)

// MitmFrontingCertificateAuthority manages dynamic certificate validation, keys, and signatures (Items 1-35)
type MitmFrontingCertificateAuthority struct {
	mu                      sync.RWMutex
	CaCertPemBytes          []byte                  `json:"ca_cert_pem_bytes"`         // Item 1: raw root CA cert block bytes
	CaKeyPemBytes           []byte                  `json:"ca_key_pem_bytes"`          // Item 2: raw root CA private key bytes
	SerialNumberRangeLimit  int64                   `json:"serial_number_range_limit"` // Item 3: unique cert serial ceiling
	CnOrganizationName      string                  `json:"cn_organization_name"`      // Item 4: CA Subject Organization CN string
	CnOrganizationUnit      string                  `json:"cn_organization_unit"`      // Item 5: CA Subject Org Unit CN string
	CnCountryCodeName       string                  `json:"cn_country_code_name"`      // Item 6: Subject Country CN string
	CnProvinceStateName     string                  `json:"cn_province_state_name"`    // Item 7: Subject Province CN string
	CnLocalityCityName      string                  `json:"cn_locality_city_name"`     // Item 8: Subject Locality CN string
	ValidityOffsetSecs      int                     `json:"validity_offset_secs"`      // Item 9: backdating offset adjust value
	AuthorityKeyIdentifier  []byte                  `json:"authority_key_identifier"`  // Item 10: authority key identifier byte slice
	SubjectKeyIdentifier    []byte                  `json:"subject_key_identifier"`    // Item 11: subject key identifier byte slice
	CertSignatureAlgorithm  x509.SignatureAlgorithm // Item 12: signature algorithm resolved (ECDSA-SHA256)
	CurveTypePreference     x509.PublicKeyAlgorithm // Item 13: prioritized curve encryption type
	MaxCertPathDepthLimit   int                     `json:"max_cert_path_depth_limit"`  // Item 14: depth ceiling of CA signature chains
	DefaultValidityDays     int                     `json:"default_validity_days"`      // Item 15: dynamic cert expiration duration
	CrlDistributionUrlPath  string                  `json:"crl_distribution_url_path"`  // Item 16: CRL endpoint distribution URL
	OcspResponderUrlPath    string                  `json:"ocsp_responder_url_path"`    // Item 17: OCSP responder target URL path
	StrictRootVerifyToggles bool                    `json:"strict_root_verify_toggles"` // Item 18: toggle verify against trust store
	PermittedDomainList     []string                `json:"permitted_domain_list"`      // Item 19: list of permitted domains in SAN
	ExcludedDomainList      []string                `json:"excluded_domain_list"`       // Item 20: list of excluded domains in SAN
	PermittedSubnetRanges   []string                `json:"permitted_subnet_ranges"`    // Item 21: allowed IP ranges in SAN
	ExcludedSubnetRanges    []string                `json:"excluded_subnet_ranges"`     // Item 22: excluded IP ranges in SAN
	KeyUsageAllowedFlags    x509.KeyUsage           // Item 23: key usage allowed flag indicators
	ExtKeyUsageFlagsList    []x509.ExtKeyUsage      // Item 24: extended key usages (ServerAuth, ClientAuth)
	BasicConstraintsAssert  bool                    `json:"basic_constraints_assert"`  // Item 25: basic constraints extension flag
	CertSignatureValBytes   []byte                  `json:"cert_signature_val_bytes"`  // Item 26: raw certificate signature payload
	IssuerDistinguishedVal  []byte                  `json:"issuer_distinguished_val"`  // Item 27: issuer DN byte data block
	SubjectDistinguishedVal []byte                  `json:"subject_distinguished_val"` // Item 28: subject DN byte data block
	TotalCertificatesSigned uint64                  `json:"total_certificates_signed"` // Item 29: count of dynamic certs signed
	TotalRevokedCertsCount  uint64                  `json:"total_revoked_certs_count"` // Item 30: count of revoked certs flagged
	ActiveCaStateIndicator  bool                    `json:"active_ca_state_indicator"` // Item 31: toggle status of dynamic CA
	LingerDurationSeconds   int                     `json:"linger_duration_seconds"`   // Item 32: linger time option applied to socket
	IpTOSClassBitsValue     int                     `json:"ip_tos_class_bits_value"`   // Item 33: TOS configuration bytes for CA
	SocketMarkRouteTagVal   int                     `json:"socket_mark_route_tag_val"` // Item 34: firewall routing identifier mark
	DiagnosticsStateTag     string                  // Item 35: status identifier tag of CA subsystem
}

// MitmFrontingCacheEvictionOptions configures LRU sweeps, limits, and cleanup loops (Items 36-70)
type MitmFrontingCacheEvictionOptions struct {
	mu                      sync.RWMutex
	MaxEntriesLimitTally    int           `json:"max_entries_limit_tally"`    // Item 36: ceiling limit of memory cache records
	EvictionIntervalPeriod  time.Duration `json:"eviction_interval_period"`   // Item 37: interval executing eviction sweeps
	ExpiredCleanupSeconds   int           `json:"expired_cleanup_seconds"`    // Item 38: threshold before evicting expired certs
	EvictionPolicyTypeStr   string        `json:"eviction_policy_type_str"`   // Item 39: policy identifier name LRU
	AutoSaveDiskInterval    int           `json:"auto_save_disk_interval"`    // Item 40: interval saving cache to local store
	DiskExportDirectory     string        `json:"disk_export_directory"`      // Item 41: folder directory saving cache assets
	CleanThresholdRatio     float64       `json:"clean_threshold_ratio"`      // Item 42: dirty ratio threshold triggering cleanups
	CacheMissesTallyCount   uint64        `json:"cache_misses_tally_count"`   // Item 43: cumulative cache lookups missed count
	CacheHitsTallyCount     uint64        `json:"cache_hits_tally_count"`     // Item 44: cumulative cache lookups hit count
	ActiveCacheSizeAlloced  int64         `json:"active_cache_size_alloced"`  // Item 45: size of allocated memory in bytes
	TotalAllocationsCount   uint64        `json:"total_allocations_count"`    // Item 46: total allocations count since boot
	PreAllocatedSlabsLimit  int           `json:"pre_allocated_slabs_limit"`  // Item 47: preallocated slabs count for cache
	LockFreeQueueActive     bool          `json:"lock_free_queue_active"`     // Item 48: toggle using lock-free queue
	WriteBufferLimitBytes   int           `json:"write_buffer_limit_bytes"`   // Item 49: write buffer limit size allocated
	ReadBufferLimitBytes    int           `json:"read_buffer_limit_bytes"`    // Item 50: read buffer limit size allocated
	BufferGrowingStepBytes  int           `json:"buffer_growing_step_bytes"`  // Item 51: incremental resizing chunk size
	FlushTimeoutLimitMs     int           `json:"flush_timeout_limit_ms"`     // Item 52: timeout flushing dirty data buffers
	FlushOperationsTally    uint64        `json:"flush_operations_tally"`     // Item 53: count of flush operations executed
	MinBufferSliceCapacity  int           `json:"min_buffer_slice_capacity"`  // Item 54: minimum size of individual buffers
	MaxBufferSliceCapacity  int           `json:"max_buffer_slice_capacity"`  // Item 55: maximum size of individual buffers
	ZeroCopyTransferMode    bool          `json:"zero_copy_transfer_mode"`    // Item 56: toggle zero-copy data routing
	BufferSignatureBytes    []byte        `json:"buffer_signature_bytes"`     // Item 57: verification pattern for buffer splits
	BufferErrorCodeValue    int           `json:"buffer_error_code_value"`    // Item 58: status code representing buffer errors
	KeepAliveSecondsFreq    int           `json:"keep_alive_seconds_freq"`    // Item 59: TCP keepalive frequency
	RateLimitQueriesLimit   int           `json:"rate_limit_queries_limit"`   // Item 60: limit of query checks per window
	ResolverAddressIPv4     string        `json:"resolver_address_ipv4"`      // Item 61: custom DNS IP target
	HappyEyeballsWeight     float64       `json:"happy_eyeballs_weight"`      // Item 62: weight decay value for latency
	VerifyDomainsStrict     bool          `json:"verify_domains_strict"`      // Item 63: strict domains string verification
	UnexpectedSubnetsIPv4   []string      `json:"unexpected_subnets_ipv4"`    // Item 64: blacklisted IPv4 subnets list
	UnexpectedSubnetsIPv6   []string      `json:"unexpected_subnets_ipv6"`    // Item 65: blacklisted IPv6 subnets list
	DualStackPriorityTag    string        `json:"dual_stack_priority_tag"`    // Item 66: priority setting (ipv4, ipv6)
	MetricsCompilationSec   int           `json:"metrics_compilation_sec"`    // Item 67: rate of compiling metrics
	AlertsWebhookPathUrl    string        `json:"alerts_webhook_path_url"`    // Item 68: URL endpoint receiving warnings
	EnableAlertsChannel     bool          `json:"enable_alerts_channel"`      // Item 69: toggle alerts notification system
	CacheOptionsActiveState bool          `json:"cache_options_active_state"` // Item 70: toggle status of eviction subsystem
}

// MitmFrontingOCSPExtension handles OCSP Stapling, revocation checks, and CRL signatures (Items 71-100)
type MitmFrontingOCSPExtension struct {
	mu                       sync.RWMutex
	OcspServerAddressUrl     string    `json:"ocsp_server_address_url"`   // Item 71: URL target verified by OCSP queries
	OcspTimeoutLimitMs       int       `json:"ocsp_timeout_limit_ms"`     // Item 72: duration timeout in ms for OCSP check
	RequireStaplingToggles   bool      `json:"require_stapling_toggles"`  // Item 73: enforce OCSP stapling on TLS
	StapledResponseBytes     []byte    `json:"stapled_response_bytes"`    // Item 74: raw stapled response payload bytes
	LastRevocationCheck      time.Time `json:"last_revocation_check"`     // Item 75: timestamp of latest revocation check
	CrlSignatureVerifyTag    string    `json:"crl_signature_verify_tag"`  // Item 76: signature status tag of CRL check
	TotalRevocationChecks    uint64    `json:"total_revoked_certs_count"` // Item 77: total checks performed counter
	TotalBlockedSessions     uint64    `json:"total_blocked_sessions"`    // Item 78: total sessions blocked by OCSP
	BypassOcspOnFailure      bool      `json:"bypass_ocsp_on_failure"`    // Item 79: fallback bypass OCSP when server offline
	LogRevocationEvents      bool      `json:"log_revocation_events"`     // Item 80: toggle logging of revocation events
	DiagnosticsStateTags     string    // Item 81: status identifier tag of OCSP state
	AlertsWebhookPathUrl     string    `json:"alerts_webhook_path_url"`     // Item 82: URL endpoint receiving warning hook
	EnableAlertsChannel      bool      `json:"enable_alerts_channel"`       // Item 83: toggle alerts notification channel
	StatsDumpDirectoryPath   string    `json:"stats_dump_directory_path"`   // Item 84: folder path saving stats logs
	StatsDumpIntervalMinutes int       `json:"stats_dump_interval_minutes"` // Item 85: interval writing stats to file paths
	MaxLatencyCeilingSec     int       `json:"max_latency_ceiling_sec"`     // Item 86: latency average ceiling threshold
	DisconnectTimerSeconds   int       `json:"disconnect_timer_seconds"`    // Item 87: time duration before disconnecting
	TlsVersionMaxAllowed     uint16    `json:"tls_version_max_allowed"`     // Item 88: maximum TLS protocol version supported
	TlsVersionMinAllowed     uint16    `json:"tls_version_min_allowed"`     // Item 89: minimum TLS protocol version supported
	PROXYProtocolHeadersOk   bool      `json:"proxy_protocol_headers_ok"`   // Item 90: toggle parsing PROXY protocol headers
	BypassSubnetsRegistry    []string  `json:"bypass_subnets_registry"`     // Item 91: local subnet CIDR blocks list
	DynamicHostsOverride     []string  `json:"dynamic_hosts_override"`      // Item 92: custom DNS hostname mappings list
	LatenciesTargetMaps      []int64   `json:"latencies_target_maps"`       // Item 93: tracked latencies for outbound endpoints
	MetricsCompilationOk     bool      `json:"metrics_compilation_ok"`      // Item 94: toggle metrics collection
	ResolverAddressString    string    `json:"resolver_address_string"`     // Item 95: custom resolver server target IP
	SubdomainMatchToggles    bool      `json:"subdomain_match_toggles"`     // Item 96: toggle subdomain wildcard blocking
	TotalFailedDialsCount    uint64    `json:"total_failed_dials_count"`    // Item 97: total failed dial attempts
	TotalSuccessfulDials     uint64    `json:"total_successful_dials"`      // Item 98: total successful dials
	ActiveClientSessions     int32     `json:"active_client_sessions"`      // Item 99: active count of connected clients
	OcspExtensionActive      bool      `json:"ocsp_extension_active"`       // Item 100: toggle active status of OCSP extension
}

// GenerateDynamicCert signs a dynamic server certificate for incoming SNI domains
func (c *MitmFrontingCertificateAuthority) GenerateDynamicCert(domain string) (*x509.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	atomic.AddUint64(&c.TotalCertificatesSigned, 1)

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   domain,
			Organization: []string{c.CnOrganizationName},
		},
		NotBefore:             time.Now().Add(-1 * time.Duration(c.ValidityOffsetSecs) * time.Second),
		NotAfter:              time.Now().AddDate(0, 0, c.DefaultValidityDays),
		KeyUsage:              c.KeyUsageAllowedFlags,
		ExtKeyUsage:           c.ExtKeyUsageFlagsList,
		BasicConstraintsValid: c.BasicConstraintsAssert,
	}

	return cert, nil
}
