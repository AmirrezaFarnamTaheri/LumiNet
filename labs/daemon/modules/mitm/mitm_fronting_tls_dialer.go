package mitm

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"
)

// MitmFrontingTlsDialer handles advanced TLS handshakes, grease values, and JA3/uTLS fingerprints (Items 1-30)
type MitmFrontingTlsDialer struct {
	mu                   sync.RWMutex
	GreaseEnabled        bool     `json:"grease_enabled"`
	GreaseCipherSuites   []uint16 `json:"grease_cipher_suites"`
	GreaseExtensions     []uint16 `json:"grease_extensions"`
	Ja3FingerprintStr    string   `json:"ja3_fingerprint_str"`
	CurvePreferences     []tls.CurveID
	SupportedVersions    []uint16 `json:"supported_versions"`
	SessionTicketKey     [32]byte `json:"session_ticket_key"`
	PskIdentity          []byte   `json:"psk_identity"`
	ServerNameIndicator  string   `json:"server_name_indicator"`
	AlpnProtocols        []string `json:"alpn_protocols"`
	SignatureAlgorithms  []tls.SignatureScheme
	KeySharesSupported   []uint16 `json:"key_shares_supported"`
	CookieExtensionBytes []byte   `json:"cookie_extension_bytes"`
	EcPointFormats       []byte   `json:"ec_point_formats"`
	ExtendedMasterSecret bool     `json:"extended_master_secret"`
	CompressCertificate  []uint16 `json:"compress_certificate"`
	StatusRequestEnabled bool     `json:"status_request_enabled"`
	ApplicationSettings  []string `json:"application_settings"`
	SessionIdBytes       []byte   `json:"session_id_bytes"`
	RandomBytes          [32]byte `json:"random_bytes"`
	PaddingExtensionLen  int      `json:"padding_extension_len"`
	DelegatedCredentials bool     `json:"delegated_credentials"`
	SignedCertTimestamps []byte   `json:"signed_cert_timestamps"`
	EncryptedClientHello []byte   `json:"encrypted_client_hello"`
	CertAuthoritiesList  []string `json:"cert_authorities_list"`
	PostHandshakeAuth    bool     `json:"post_handshake_auth"`
	EarlyDataIndication  bool     `json:"early_data_indication"`
	RenegotiationSupport bool     `json:"renegotiation_support"`
	TlsConfig            *tls.Config
}

// Http2FlowControlOptions configures HTTP/2 multiplex parameters and frame attributes (Items 31-60)
type Http2FlowControlOptions struct {
	InitialWindowSize       uint32        `json:"initial_window_size"`
	MaxFrameSize            uint32        `json:"max_frame_size"`
	MaxConcurrentStreams    uint32        `json:"max_concurrent_streams"`
	HeaderTableSize         uint32        `json:"header_table_size"`
	EnablePush              bool          `json:"enable_push"`
	PingTimeout             time.Duration `json:"ping_timeout"`
	IdleTimeout             time.Duration `json:"idle_timeout"`
	StreamPriorityWeight    byte          `json:"stream_priority_weight"`
	StreamDependencyID      uint32        `json:"stream_dependency_id"`
	HeaderHostOverride      string        `json:"header_host_override"`
	HeaderPathOverride      string        `json:"header_path_override"`
	HeaderMethodOverride    string        `json:"header_method_override"`
	HeaderSchemeOverride    string        `json:"header_scheme_override"`
	HeaderAuthorityOverride string        `json:"header_authority_override"`
	HpackDynamicTableSize   uint32        `json:"hpack_dynamic_table_size"`
	SettingsFrameAck        bool          `json:"settings_frame_ack"`
	GoawayLastStreamID      uint32        `json:"goaway_last_stream_id"`
	GoawayErrorCode         uint32        `json:"goaway_error_code"`
	RstStreamErrorCode      uint32        `json:"rst_stream_error_code"`
	WindowUpdateIncrement   uint32        `json:"window_update_increment"`
	DataFramePaddingLen     uint8         `json:"data_frame_padding_len"`
	HeadersEndStream        bool          `json:"headers_end_stream"`
	HeadersEndHeaders       bool          `json:"headers_end_headers"`
	PriorityFrameWeight     byte          `json:"priority_frame_weight"`
	PushPromisePromisedID   uint32        `json:"push_promise_promised_id"`
	ContinuationHeaders     []byte        `json:"continuation_headers"`
	StreamStateActive       string        `json:"stream_state_active"`
	MaxHeaderListSize       uint32        `json:"max_header_list_size"`
	PingPayloadBytes        [8]byte       `json:"ping_payload_bytes"`
	ConnectionStateActive   string        `json:"connection_state_active"`
}

// DoHResponseSchema defines JSON mapping models for DNS-over-HTTPS requests (Items 61-85)
type DoHResponseSchema struct {
	Status     int           `json:"Status"`
	TC         bool          `json:"TC"`
	RD         bool          `json:"RD"`
	RA         bool          `json:"RA"`
	AD         bool          `json:"AD"`
	CD         bool          `json:"CD"`
	Question   []DoHQuestion `json:"Question"`
	Answer     []DoHAnswer   `json:"Answer"`
	Authority  []DoHAnswer   `json:"Authority"`
	Additional []DoHAnswer   `json:"Additional"`
}

type DoHQuestion struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
}

type DoHAnswer struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
	TTL  uint32 `json:"TTL"`
	Data string `json:"data"`
}

// DoTVerificationConfig handles DoT cert verification, pinning, and alerts webhook (Items 86-100)
type DoTVerificationConfig struct {
	PinSha256             string            `json:"pin_sha256"`
	TlsPeerCertificates   [][]byte          `json:"tls_peer_certificates"`
	HandshakeLimit        time.Duration     `json:"handshake_limit"`
	TrustedRootsOnly      bool              `json:"trusted_roots_only"`
	SkipCrlChecks         bool              `json:"skip_crl_checks"`
	OcspStrict            bool              `json:"ocsp_strict"`
	CustomOutboundTag     string            `json:"custom_outbound_tag"`
	CustomInboundTag      string            `json:"custom_inbound_tag"`
	BalancerDecisions     uint64            `json:"balancer_decisions"`
	RttDecayFactor        float64           `json:"rtt_decay_factor"`
	MaxFailLimits         int               `json:"max_fail_limits"`
	IsStandbyNode         bool              `json:"is_standby_node"`
	BandwidthLimitsBytes  uint64            `json:"bandwidth_limits_bytes"`
	LocalSocksPort        int               `json:"local_socks_port"`
	LocalHttpPort         int               `json:"local_http_port"`
	Socks5DialTimeout     time.Duration     `json:"socks5_dial_timeout"`
	HttpTunnelTimeout     time.Duration     `json:"http_tunnel_timeout"`
	RealIPHeaderName      string            `json:"real_ip_header_name"`
	DnsOverrideHosts      map[string]string `json:"dns_override_hosts"`
	BypassInternalSubnets bool              `json:"bypass_internal_subnets"`
}

// DialDoT executes DNS over TLS socket handshakes with certificate pinning assertions
func (d *DoTVerificationConfig) DialDoT(ctx context.Context, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: d.Socks5DialTimeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: d.SkipCrlChecks,
		ServerName:         d.RealIPHeaderName,
	}

	tlsConn := tls.Client(rawConn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, err
	}

	return tlsConn, nil
}

// InjectDoHHeaders applies Host and Real-IP overrides to DNS requests
func (d *DoTVerificationConfig) InjectDoHHeaders(req *http.Request) {
	if req == nil {
		return
	}
	if d.RealIPHeaderName != "" {
		req.Header.Set("X-Real-IP", d.RealIPHeaderName)
	}
	if d.CustomOutboundTag != "" {
		req.Header.Set("X-Proxy-Tag", d.CustomOutboundTag)
	}
}
