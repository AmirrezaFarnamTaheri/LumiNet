package api

import (
	"net/http"
	"sort"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/platform/system"
	"github.com/maybeknott/luminet/internal/runtime/proxy"
)

type EvasionTunnelStatusResponse struct {
	Running                bool    `json:"running"`
	Port                   int     `json:"port"`
	SplitBytes             int     `json:"split_bytes"`
	DelayMs                int     `json:"delay_ms"`
	MutateHost             bool    `json:"mutate_host"`
	MutateHeaderSpace      bool    `json:"mutate_header_space"`
	AutoSni                bool    `json:"auto_sni"`
	PrecisionSniSplits     bool    `json:"precision_sni_splits"`
	SniSplitOffset         int     `json:"sni_split_offset"`
	Packets                string  `json:"packets"`
	MinLength              int     `json:"min_length"`
	MaxLength              int     `json:"max_length"`
	TlsRecordSplit         bool    `json:"tls_record_split"`
	DnsResolver            string  `json:"dns_resolver"`
	DnsForwarderPort       int     `json:"dns_forwarder_port"`
	DnsForwarderEnabled    bool    `json:"dns_forwarder_enabled"`
	SystemProxyEnabled     bool    `json:"system_proxy_enabled"`
	SniSpoof               string  `json:"sni_spoof"`
	ClientHelloPadding     int     `json:"client_hello_padding"`
	DelayJitter            bool    `json:"delay_jitter"`
	TcpWindowClamp         int     `json:"tcp_window_clamp"`
	CustomUserAgent        string  `json:"custom_user_agent"`
	CovertMode             string  `json:"covert_mode"`
	CovertServerlessUrl    string  `json:"covert_serverless_url"`
	CovertDnsDomain        string  `json:"covert_dns_domain"`
	CovertGsaUrl           string  `json:"covert_gsa_url"`
	CovertGsaKey           string  `json:"covert_gsa_key"`
	CovertGdocsFolderId    string  `json:"covert_gdocs_folder_id"`
	CovertGdocsAccessToken string  `json:"covert_gdocs_access_token"`
	FakePacketInject       bool    `json:"fake_packet_inject"`
	FakePacketTtl          int     `json:"fake_packet_ttl"`
	MutateSniCase          bool    `json:"mutate_sni_case"`
	MutateMethod           bool    `json:"mutate_method"`
	MutateAbsoluteUri      bool    `json:"mutate_absolute_uri"`
	HttpPadding            int     `json:"http_padding"`
	PreflightSignature     string  `json:"preflight_signature"`
	PreflightDelayMs       int     `json:"preflight_delay_ms"`
	SessionFrag            bool    `json:"session_frag"`
	SessionFragProb        float64 `json:"session_frag_prob"`
	SessionFragMinTotal    int     `json:"session_frag_min_total"`
	SessionFragMaxTotal    int     `json:"session_frag_max_total"`
	SessionFragMinChunk    int     `json:"session_frag_min_chunk"`
	SessionFragMaxChunk    int     `json:"session_frag_max_chunk"`
	SessionFragMinDelayMs  int     `json:"session_frag_min_delay_ms"`
	SessionFragMaxDelayMs  int     `json:"session_frag_max_delay_ms"`
	IpSpoofingEnabled      bool    `json:"ip_spoofing_enabled"`
	IpSpoofingDecoyIP      string  `json:"ip_spoofing_decoy_ip"`
	IpSpoofingDstReal      string  `json:"ip_spoofing_dst_real"`
	OutOfWindowEnabled     bool    `json:"out_of_window_enabled"`
	OutOfWindowSeqOffset   int     `json:"out_of_window_seq_offset"`
	DecoySniPool           string  `json:"decoy_sni_pool"`
	OobEnabled             bool    `json:"oob_enabled"`
	OobexEnabled           bool    `json:"oobex_enabled"`

	// Mobile shielding settings
	CovertSocketProtectPath string `json:"covert_socket_protect_path"`
	MobileAssetsEnabled     bool   `json:"mobile_assets_enabled"`
	ZygiskHideEnabled       bool   `json:"zygisk_hide_enabled"`
	HardenedTlsEnabled      bool   `json:"hardened_tls_enabled"`

	// Session 6 Covert Transport settings
	WsEndpoint          string  `json:"ws_endpoint"`
	WsHeaders           string  `json:"ws_headers"`
	WsUseUtls           bool    `json:"ws_use_utls"`
	WsFingerprint       string  `json:"ws_fingerprint"`
	WsPadding           bool    `json:"ws_padding"`
	WsTunnelType        int     `json:"ws_tunnel_type"`
	SshHost             string  `json:"ssh_host"`
	SshUser             string  `json:"ssh_user"`
	SshPass             string  `json:"ssh_pass"`
	SshKey              string  `json:"ssh_key"`
	SshKeyPassphrase    string  `json:"ssh_key_passphrase"`
	SshHostKeySHA256    string  `json:"ssh_host_key_sha256"`
	KCPNoDelay          int     `json:"kcp_nodelay"`
	KCPInterval         int     `json:"kcp_interval"`
	KCPResend           int     `json:"kcp_resend"`
	KCPNoCongestion     int     `json:"kcp_nocongestion"`
	KCPSendWindow       int     `json:"kcp_sndwnd"`
	KCPReceiveWindow    int     `json:"kcp_rcvwnd"`
	KCPMTU              int     `json:"kcp_mtu"`
	TuicUuid            string  `json:"tuic_uuid"`
	TuicToken           string  `json:"tuic_token"`
	AsyncReactorEnabled bool    `json:"async_reactor_enabled"`
	LossRate            float64 `json:"loss_rate"`
	EmulatedLatency     int     `json:"emulated_latency"`
	EmulatedJitter      int     `json:"emulated_jitter"`
	CircularCacheCap    int     `json:"circular_cache_cap"`
	ShaperReadRate      int64   `json:"shaper_read_rate"`
	ShaperWriteRate     int64   `json:"shaper_write_rate"`

	UpgenObfuscationEnabled     bool   `json:"upgen_obfuscation_enabled"`
	UpgenSeedHex                string `json:"upgen_seed_hex"`
	UpgenEntropyMatch           bool   `json:"upgen_entropy_match"`
	UpgenQuicExhaustionRate     int    `json:"upgen_quic_exhaustion_rate"`
	SteganographyEnabled        bool   `json:"steganography_enabled"`
	SteganographyMode           string `json:"steganography_mode"`
	SteganographyDecoyImagePath string `json:"steganography_decoy_image_path"`
	SteganographyWebRTCSDPSpoof bool   `json:"steganography_webrtc_sdp_spoof"`
	ResidentialCloaking         bool   `json:"residential_cloaking"`
	ResidentialEgressNode       string `json:"residential_egress_node"`
	MssClampingValue            int    `json:"mss_clamping_value"`
	DnsLeaksShield              bool   `json:"dns_leaks_shield"`
	MssPreset                   string `json:"mss_preset"`
}

type SetEvasionTunnelRequest struct {
	Enabled                bool    `json:"enabled"`
	Port                   int     `json:"port"`
	SplitBytes             int     `json:"split_bytes"`
	DelayMs                int     `json:"delay_ms"`
	MutateHost             bool    `json:"mutate_host"`
	MutateHeaderSpace      bool    `json:"mutate_header_space"`
	AutoSni                bool    `json:"auto_sni"`
	PrecisionSniSplits     bool    `json:"precision_sni_splits"`
	SniSplitOffset         int     `json:"sni_split_offset"`
	Packets                string  `json:"packets"`
	MinLength              int     `json:"min_length"`
	MaxLength              int     `json:"max_length"`
	TlsRecordSplit         bool    `json:"tls_record_split"`
	DnsResolver            string  `json:"dns_resolver"`
	DnsForwarderPort       int     `json:"dns_forwarder_port"`
	DnsForwarderEnabled    bool    `json:"dns_forwarder_enabled"`
	SystemProxyEnabled     bool    `json:"system_proxy_enabled"`
	SniSpoof               string  `json:"sni_spoof"`
	ClientHelloPadding     int     `json:"client_hello_padding"`
	DelayJitter            bool    `json:"delay_jitter"`
	TcpWindowClamp         int     `json:"tcp_window_clamp"`
	CustomUserAgent        string  `json:"custom_user_agent"`
	CovertMode             string  `json:"covert_mode"`
	CovertServerlessUrl    string  `json:"covert_serverless_url"`
	CovertDnsDomain        string  `json:"covert_dns_domain"`
	CovertGsaUrl           string  `json:"covert_gsa_url"`
	CovertGsaKey           string  `json:"covert_gsa_key"`
	CovertGdocsFolderId    string  `json:"covert_gdocs_folder_id"`
	CovertGdocsAccessToken string  `json:"covert_gdocs_access_token"`
	FakePacketInject       bool    `json:"fake_packet_inject"`
	FakePacketTtl          int     `json:"fake_packet_ttl"`
	MutateSniCase          bool    `json:"mutate_sni_case"`
	MutateMethod           bool    `json:"mutate_method"`
	MutateAbsoluteUri      bool    `json:"mutate_absolute_uri"`
	HttpPadding            int     `json:"http_padding"`
	PreflightSignature     string  `json:"preflight_signature"`
	PreflightDelayMs       int     `json:"preflight_delay_ms"`
	SessionFrag            bool    `json:"session_frag"`
	SessionFragProb        float64 `json:"session_frag_prob"`
	SessionFragMinTotal    int     `json:"session_frag_min_total"`
	SessionFragMaxTotal    int     `json:"session_frag_max_total"`
	SessionFragMinChunk    int     `json:"session_frag_min_chunk"`
	SessionFragMaxChunk    int     `json:"session_frag_max_chunk"`
	SessionFragMinDelayMs  int     `json:"session_frag_min_delay_ms"`
	SessionFragMaxDelayMs  int     `json:"session_frag_max_delay_ms"`
	IpSpoofingEnabled      bool    `json:"ip_spoofing_enabled"`
	IpSpoofingDecoyIP      string  `json:"ip_spoofing_decoy_ip"`
	IpSpoofingDstReal      string  `json:"ip_spoofing_dst_real"`
	OutOfWindowEnabled     bool    `json:"out_of_window_enabled"`
	OutOfWindowSeqOffset   int     `json:"out_of_window_seq_offset"`
	DecoySniPool           string  `json:"decoy_sni_pool"`
	OobEnabled             bool    `json:"oob_enabled"`
	OobexEnabled           bool    `json:"oobex_enabled"`

	// Mobile shielding settings
	CovertSocketProtectPath string `json:"covert_socket_protect_path"`
	MobileAssetsEnabled     bool   `json:"mobile_assets_enabled"`
	ZygiskHideEnabled       bool   `json:"zygisk_hide_enabled"`
	HardenedTlsEnabled      bool   `json:"hardened_tls_enabled"`

	// Session 6 Covert Transport settings
	WsEndpoint          string  `json:"ws_endpoint"`
	WsHeaders           string  `json:"ws_headers"`
	WsUseUtls           bool    `json:"ws_use_utls"`
	WsFingerprint       string  `json:"ws_fingerprint"`
	WsPadding           bool    `json:"ws_padding"`
	WsTunnelType        int     `json:"ws_tunnel_type"`
	SshHost             string  `json:"ssh_host"`
	SshUser             string  `json:"ssh_user"`
	SshPass             string  `json:"ssh_pass"`
	SshKey              string  `json:"ssh_key"`
	SshKeyPassphrase    string  `json:"ssh_key_passphrase"`
	SshHostKeySHA256    string  `json:"ssh_host_key_sha256"`
	KCPNoDelay          int     `json:"kcp_nodelay"`
	KCPInterval         int     `json:"kcp_interval"`
	KCPResend           int     `json:"kcp_resend"`
	KCPNoCongestion     int     `json:"kcp_nocongestion"`
	KCPSendWindow       int     `json:"kcp_sndwnd"`
	KCPReceiveWindow    int     `json:"kcp_rcvwnd"`
	KCPMTU              int     `json:"kcp_mtu"`
	TuicUuid            string  `json:"tuic_uuid"`
	TuicToken           string  `json:"tuic_token"`
	AsyncReactorEnabled bool    `json:"async_reactor_enabled"`
	LossRate            float64 `json:"loss_rate"`
	EmulatedLatency     int     `json:"emulated_latency"`
	EmulatedJitter      int     `json:"emulated_jitter"`
	CircularCacheCap    int     `json:"circular_cache_cap"`
	ShaperReadRate      int64   `json:"shaper_read_rate"`
	ShaperWriteRate     int64   `json:"shaper_write_rate"`

	UpgenObfuscationEnabled     bool   `json:"upgen_obfuscation_enabled"`
	UpgenSeedHex                string `json:"upgen_seed_hex"`
	UpgenEntropyMatch           bool   `json:"upgen_entropy_match"`
	UpgenQuicExhaustionRate     int    `json:"upgen_quic_exhaustion_rate"`
	SteganographyEnabled        bool   `json:"steganography_enabled"`
	SteganographyMode           string `json:"steganography_mode"`
	SteganographyDecoyImagePath string `json:"steganography_decoy_image_path"`
	SteganographyWebRTCSDPSpoof bool   `json:"steganography_webrtc_sdp_spoof"`
	ResidentialCloaking         bool   `json:"residential_cloaking"`
	ResidentialEgressNode       string `json:"residential_egress_node"`
	MssClampingValue            int    `json:"mss_clamping_value"`
	DnsLeaksShield              bool   `json:"dns_leaks_shield"`
	MssPreset                   string `json:"mss_preset"`
}

// GetEvasionTunnelStatus handles GET /api/system/evasion-tunnel
func (s *Server) GetEvasionTunnelStatus(c *gin.Context) {
	mgr := proxy.GetEvasionManager()
	status := mgr.Status()
	cfg := mgr.GetRedactedConfig()
	port := cfg.Port
	splitBytes := cfg.SplitBytes
	delayMs := cfg.DelayMs
	mutateHost := cfg.MutateHost
	mutateHeaderSpace := cfg.MutateHeaderSpace
	autoSni := cfg.AutoSni
	sniSplitOffset := cfg.SniSplitOffset
	packets := cfg.Packets
	minLen := cfg.MinLength
	maxLen := cfg.MaxLength
	tlsRecSplit := cfg.TlsRecordSplit
	dnsResolver := cfg.DnsResolver
	dnsFwdPort := cfg.DnsForwarderPort
	dnsFwdEnabled := cfg.DnsForwarderEnabled
	systemProxyEnabled := cfg.SystemProxyEnabled
	sniSpoof := cfg.SniSpoof
	clientHelloPadding := cfg.ClientHelloPadding
	delayJitter := cfg.DelayJitter
	tcpWindowClamp := cfg.TcpWindowClamp
	customUserAgent := cfg.CustomUserAgent
	covertMode := cfg.CovertMode
	covertServerlessUrl := cfg.CovertServerlessUrl
	covertDnsDomain := cfg.CovertDnsDomain
	covertGsaUrl := cfg.CovertGsaUrl
	covertGsaKey := cfg.CovertGsaKey
	covertGdocsFolderId := cfg.CovertGdocsFolderId
	covertGdocsAccessToken := cfg.CovertGdocsAccessToken
	fakePacketInject := cfg.FakePacketInject
	fakePacketTtl := cfg.FakePacketTtl
	mutateSniCase := cfg.MutateSniCase
	mutateMethod := cfg.MutateMethod
	mutateAbsoluteUri := cfg.MutateAbsoluteUri
	httpPadding := cfg.HttpPadding
	preflightSignature := cfg.PreflightSignature
	preflightDelayMs := cfg.PreflightDelayMs
	sessionFrag := cfg.SessionFrag
	sessionFragProb := cfg.SessionFragProb
	sessionFragMinTotal := cfg.SessionFragMinTotal
	sessionFragMaxTotal := cfg.SessionFragMaxTotal
	sessionFragMinChunk := cfg.SessionFragMinChunk
	sessionFragMaxChunk := cfg.SessionFragMaxChunk
	sessionFragMinDelayMs := cfg.SessionFragMinDelayMs
	sessionFragMaxDelayMs := cfg.SessionFragMaxDelayMs
	ipSpoofingEnabled := cfg.IpSpoofingEnabled
	ipSpoofingDecoyIP := cfg.IpSpoofingDecoyIP
	ipSpoofingDstReal := cfg.IpSpoofingDstReal
	outOfWindowEnabled := cfg.OutOfWindowEnabled
	outOfWindowSeqOffset := cfg.OutOfWindowSeqOffset
	decoySniPool := cfg.DecoySniPool
	oobEnabled := cfg.OobEnabled
	oobexEnabled := cfg.OobexEnabled
	asyncReactorEnabled := cfg.AsyncReactorEnabled
	lossRate := cfg.LossRate
	emulatedLatency := cfg.EmulatedLatency
	emulatedJitter := cfg.EmulatedJitter
	circularCacheCap := cfg.CircularCacheCap
	shaperReadRate := cfg.ShaperReadRate
	shaperWriteRate := cfg.ShaperWriteRate
	covertSocketProtectPath := cfg.CovertSocketProtectPath
	mobileAssetsEnabled := cfg.MobileAssetsEnabled
	zygiskHideEnabled := cfg.ZygiskHideEnabled
	hardenedTlsEnabled := cfg.HardenedTlsEnabled
	upgenEnabled := cfg.UpgenEnabled
	upgenSeedHex := cfg.UpgenSeedHex
	upgenEntropyMatch := cfg.UpgenEntropyMatch
	upgenQuicExhaustionRate := cfg.UpgenQuicExhaustionRate
	stegoEnabled := cfg.StegoEnabled
	stegoMode := cfg.StegoMode
	stegoDecoyImagePath := cfg.StegoDecoyImagePath
	stegoWebRTCSDPSpoof := cfg.StegoWebRTCSDPSpoof
	residentialCloaking := cfg.ResidentialCloaking
	residentialEgressNode := cfg.ResidentialEgressNode
	mssClampingValue := cfg.MssClampingValue
	dnsLeaksShield := cfg.DnsLeaksShield
	mssPreset := cfg.MssPreset

	covertCfg := cfg.CovertCfg

	c.JSON(http.StatusOK, EvasionTunnelStatusResponse{
		Running:                     status.Running,
		Port:                        port,
		SplitBytes:                  splitBytes,
		DelayMs:                     delayMs,
		MutateHost:                  mutateHost,
		MutateHeaderSpace:           mutateHeaderSpace,
		AutoSni:                     autoSni,
		PrecisionSniSplits:          mgr.GetPrecisionSniSplits(),
		SniSplitOffset:              sniSplitOffset,
		Packets:                     packets,
		MinLength:                   minLen,
		MaxLength:                   maxLen,
		TlsRecordSplit:              tlsRecSplit,
		DnsResolver:                 dnsResolver,
		DnsForwarderPort:            dnsFwdPort,
		DnsForwarderEnabled:         dnsFwdEnabled,
		SystemProxyEnabled:          systemProxyEnabled,
		SniSpoof:                    sniSpoof,
		ClientHelloPadding:          clientHelloPadding,
		DelayJitter:                 delayJitter,
		TcpWindowClamp:              tcpWindowClamp,
		CustomUserAgent:             customUserAgent,
		CovertMode:                  covertMode,
		CovertServerlessUrl:         covertServerlessUrl,
		CovertDnsDomain:             covertDnsDomain,
		CovertGsaUrl:                covertGsaUrl,
		CovertGsaKey:                covertGsaKey,
		CovertGdocsFolderId:         covertGdocsFolderId,
		CovertGdocsAccessToken:      covertGdocsAccessToken,
		FakePacketInject:            fakePacketInject,
		FakePacketTtl:               fakePacketTtl,
		MutateSniCase:               mutateSniCase,
		MutateMethod:                mutateMethod,
		MutateAbsoluteUri:           mutateAbsoluteUri,
		HttpPadding:                 httpPadding,
		PreflightSignature:          preflightSignature,
		PreflightDelayMs:            preflightDelayMs,
		SessionFrag:                 sessionFrag,
		SessionFragProb:             sessionFragProb,
		SessionFragMinTotal:         sessionFragMinTotal,
		SessionFragMaxTotal:         sessionFragMaxTotal,
		SessionFragMinChunk:         sessionFragMinChunk,
		SessionFragMaxChunk:         sessionFragMaxChunk,
		SessionFragMinDelayMs:       sessionFragMinDelayMs,
		SessionFragMaxDelayMs:       sessionFragMaxDelayMs,
		IpSpoofingEnabled:           ipSpoofingEnabled,
		IpSpoofingDecoyIP:           ipSpoofingDecoyIP,
		IpSpoofingDstReal:           ipSpoofingDstReal,
		OutOfWindowEnabled:          outOfWindowEnabled,
		OutOfWindowSeqOffset:        outOfWindowSeqOffset,
		DecoySniPool:                decoySniPool,
		OobEnabled:                  oobEnabled,
		OobexEnabled:                oobexEnabled,
		CovertSocketProtectPath:     covertSocketProtectPath,
		MobileAssetsEnabled:         mobileAssetsEnabled,
		ZygiskHideEnabled:           zygiskHideEnabled,
		HardenedTlsEnabled:          hardenedTlsEnabled,
		WsEndpoint:                  covertCfg.WsEndpoint,
		WsHeaders:                   covertCfg.WsHeaders,
		WsUseUtls:                   covertCfg.WsUseUtls,
		WsFingerprint:               covertCfg.WsFingerprint,
		WsPadding:                   covertCfg.WsPadding,
		WsTunnelType:                covertCfg.WsTunnelType,
		SshHost:                     covertCfg.SshHost,
		SshUser:                     covertCfg.SshUser,
		SshPass:                     covertCfg.SshPass,
		SshKey:                      covertCfg.SshKey,
		SshKeyPassphrase:            covertCfg.SshKeyPassphrase,
		SshHostKeySHA256:            covertCfg.SshHostKeySHA256,
		KCPNoDelay:                  covertCfg.KcpNoDelay,
		KCPInterval:                 covertCfg.KcpInterval,
		KCPResend:                   covertCfg.KcpResend,
		KCPNoCongestion:             covertCfg.KcpNoCongestion,
		KCPSendWindow:               covertCfg.KcpSendWnd,
		KCPReceiveWindow:            covertCfg.KcpRecvWnd,
		KCPMTU:                      covertCfg.KcpMtu,
		TuicUuid:                    covertCfg.TuicUuid,
		TuicToken:                   covertCfg.TuicToken,
		AsyncReactorEnabled:         asyncReactorEnabled,
		LossRate:                    lossRate,
		EmulatedLatency:             emulatedLatency,
		EmulatedJitter:              emulatedJitter,
		CircularCacheCap:            circularCacheCap,
		ShaperReadRate:              shaperReadRate,
		ShaperWriteRate:             shaperWriteRate,
		UpgenObfuscationEnabled:     upgenEnabled,
		UpgenSeedHex:                upgenSeedHex,
		UpgenEntropyMatch:           upgenEntropyMatch,
		UpgenQuicExhaustionRate:     upgenQuicExhaustionRate,
		SteganographyEnabled:        stegoEnabled,
		SteganographyMode:           stegoMode,
		SteganographyDecoyImagePath: stegoDecoyImagePath,
		SteganographyWebRTCSDPSpoof: stegoWebRTCSDPSpoof,
		ResidentialCloaking:         residentialCloaking,
		ResidentialEgressNode:       residentialEgressNode,
		MssClampingValue:            mssClampingValue,
		DnsLeaksShield:              dnsLeaksShield,
		MssPreset:                   mssPreset,
	})
}

// SetEvasionTunnel handles POST /api/system/evasion-tunnel
func (s *Server) SetEvasionTunnel(c *gin.Context) {
	var req SetEvasionTunnelRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	mgr := proxy.GetEvasionManager()

	mgr.SetPrecisionSniSplits(req.PrecisionSniSplits)

	// Setup WebSocket log forwarder on demand
	mgr.SetOnLog(func(msg string) {
		s.hub.BroadcastSystemEvent("evasion_log", msg)
	})

	if req.Enabled {
		defaults := proxy.DefaultEvasionConfig()
		if req.Port <= 0 || req.Port > 65535 {
			req.Port = defaults.Port
		}
		if req.SplitBytes < 0 {
			req.SplitBytes = defaults.SplitBytes
		}
		if req.DelayMs < 0 {
			req.DelayMs = defaults.DelayMs
		}
		if req.Packets == "" {
			req.Packets = defaults.Packets
		}
		if req.DnsForwarderPort <= 0 || req.DnsForwarderPort > 65535 {
			req.DnsForwarderPort = defaults.DnsForwarderPort
		}
		if req.CovertMode == "" {
			req.CovertMode = defaults.CovertMode
		}
		if req.FakePacketTtl <= 0 {
			req.FakePacketTtl = 4
		}
		if req.SessionFragProb <= 0 {
			req.SessionFragProb = defaults.SessionFragProb
		}
		if req.SessionFragMinTotal <= 0 {
			req.SessionFragMinTotal = defaults.SessionFragMinTotal
		}
		if req.SessionFragMaxTotal <= 0 {
			req.SessionFragMaxTotal = defaults.SessionFragMaxTotal
		}
		if req.SessionFragMinChunk <= 0 {
			req.SessionFragMinChunk = defaults.SessionFragMinChunk
		}
		if req.SessionFragMaxChunk <= 0 {
			req.SessionFragMaxChunk = defaults.SessionFragMaxChunk
		}
		if req.SessionFragMinDelayMs < 0 {
			req.SessionFragMinDelayMs = defaults.SessionFragMinDelayMs
		}
		if req.SessionFragMaxDelayMs < 0 {
			req.SessionFragMaxDelayMs = defaults.SessionFragMaxDelayMs
		}
		if req.CircularCacheCap <= 0 {
			req.CircularCacheCap = 500
		}

		evasionCfg := proxy.DefaultEvasionConfig()
		evasionCfg.Port = req.Port
		evasionCfg.SplitBytes = req.SplitBytes
		evasionCfg.DelayMs = req.DelayMs
		evasionCfg.MutateHost = req.MutateHost
		evasionCfg.MutateHeaderSpace = req.MutateHeaderSpace
		evasionCfg.AutoSni = req.AutoSni
		evasionCfg.PrecisionSniSplits = req.PrecisionSniSplits
		evasionCfg.SniSplitOffset = req.SniSplitOffset
		evasionCfg.Packets = req.Packets
		evasionCfg.MinLength = req.MinLength
		evasionCfg.MaxLength = req.MaxLength
		evasionCfg.TlsRecordSplit = req.TlsRecordSplit
		evasionCfg.DnsResolver = req.DnsResolver
		evasionCfg.DnsForwarderPort = req.DnsForwarderPort
		evasionCfg.DnsForwarderEnabled = req.DnsForwarderEnabled
		evasionCfg.SystemProxyEnabled = req.SystemProxyEnabled
		evasionCfg.SniSpoof = req.SniSpoof
		evasionCfg.ClientHelloPadding = req.ClientHelloPadding
		evasionCfg.DelayJitter = req.DelayJitter
		evasionCfg.TcpWindowClamp = req.TcpWindowClamp
		evasionCfg.CustomUserAgent = req.CustomUserAgent
		evasionCfg.CovertMode = req.CovertMode
		evasionCfg.CovertServerlessUrl = req.CovertServerlessUrl
		evasionCfg.CovertDnsDomain = req.CovertDnsDomain
		evasionCfg.CovertGsaUrl = req.CovertGsaUrl
		evasionCfg.CovertGsaKey = req.CovertGsaKey
		evasionCfg.CovertGdocsFolderId = req.CovertGdocsFolderId
		evasionCfg.CovertGdocsAccessToken = req.CovertGdocsAccessToken
		evasionCfg.FakePacketInject = req.FakePacketInject
		evasionCfg.FakePacketTtl = req.FakePacketTtl
		evasionCfg.MutateSniCase = req.MutateSniCase
		evasionCfg.MutateMethod = req.MutateMethod
		evasionCfg.MutateAbsoluteUri = req.MutateAbsoluteUri
		evasionCfg.HttpPadding = req.HttpPadding
		evasionCfg.PreflightSignature = req.PreflightSignature
		evasionCfg.PreflightDelayMs = req.PreflightDelayMs
		evasionCfg.SessionFrag = req.SessionFrag
		evasionCfg.SessionFragProb = req.SessionFragProb
		evasionCfg.SessionFragMinTotal = req.SessionFragMinTotal
		evasionCfg.SessionFragMaxTotal = req.SessionFragMaxTotal
		evasionCfg.SessionFragMinChunk = req.SessionFragMinChunk
		evasionCfg.SessionFragMaxChunk = req.SessionFragMaxChunk
		evasionCfg.SessionFragMinDelayMs = req.SessionFragMinDelayMs
		evasionCfg.SessionFragMaxDelayMs = req.SessionFragMaxDelayMs
		evasionCfg.IpSpoofingEnabled = req.IpSpoofingEnabled
		evasionCfg.IpSpoofingDecoyIP = req.IpSpoofingDecoyIP
		evasionCfg.IpSpoofingDstReal = req.IpSpoofingDstReal
		evasionCfg.OutOfWindowEnabled = req.OutOfWindowEnabled
		evasionCfg.OutOfWindowSeqOffset = req.OutOfWindowSeqOffset
		evasionCfg.DecoySniPool = req.DecoySniPool
		evasionCfg.OobEnabled = req.OobEnabled
		evasionCfg.OobexEnabled = req.OobexEnabled
		evasionCfg.AsyncReactorEnabled = req.AsyncReactorEnabled
		evasionCfg.LossRate = req.LossRate
		evasionCfg.EmulatedLatency = req.EmulatedLatency
		evasionCfg.EmulatedJitter = req.EmulatedJitter
		evasionCfg.CircularCacheCap = req.CircularCacheCap
		evasionCfg.ShaperReadRate = req.ShaperReadRate
		evasionCfg.ShaperWriteRate = req.ShaperWriteRate
		evasionCfg.CovertSocketProtectPath = req.CovertSocketProtectPath
		evasionCfg.MobileAssetsEnabled = req.MobileAssetsEnabled
		evasionCfg.ZygiskHideEnabled = req.ZygiskHideEnabled
		evasionCfg.HardenedTlsEnabled = req.HardenedTlsEnabled
		evasionCfg.UpgenEnabled = req.UpgenObfuscationEnabled
		evasionCfg.UpgenSeedHex = req.UpgenSeedHex
		evasionCfg.UpgenEntropyMatch = req.UpgenEntropyMatch
		evasionCfg.UpgenQuicExhaustionRate = req.UpgenQuicExhaustionRate
		evasionCfg.StegoEnabled = req.SteganographyEnabled
		evasionCfg.StegoMode = req.SteganographyMode
		evasionCfg.StegoDecoyImagePath = req.SteganographyDecoyImagePath
		evasionCfg.StegoWebRTCSDPSpoof = req.SteganographyWebRTCSDPSpoof
		evasionCfg.ResidentialCloaking = req.ResidentialCloaking
		evasionCfg.ResidentialEgressNode = req.ResidentialEgressNode
		evasionCfg.MssClampingValue = req.MssClampingValue
		evasionCfg.DnsLeaksShield = req.DnsLeaksShield
		evasionCfg.MssPreset = req.MssPreset
		evasionCfg.CovertCfg = proxy.CovertTransportConfig{
			WsEndpoint:       req.WsEndpoint,
			WsHeaders:        req.WsHeaders,
			WsUseUtls:        req.WsUseUtls,
			WsFingerprint:    req.WsFingerprint,
			WsPadding:        req.WsPadding,
			WsTunnelType:     req.WsTunnelType,
			SshHost:          req.SshHost,
			SshUser:          req.SshUser,
			SshPass:          req.SshPass,
			SshKey:           req.SshKey,
			SshKeyPassphrase: req.SshKeyPassphrase,
			SshHostKeySHA256: req.SshHostKeySHA256,
			KcpNoDelay:       req.KCPNoDelay,
			KcpInterval:      req.KCPInterval,
			KcpResend:        req.KCPResend,
			KcpNoCongestion:  req.KCPNoCongestion,
			KcpSendWnd:       req.KCPSendWindow,
			KcpRecvWnd:       req.KCPReceiveWindow,
			KcpMtu:           req.KCPMTU,
			TuicUuid:         req.TuicUuid,
			TuicToken:        req.TuicToken,
		}
		evasionCfg = mgr.RestoreRedactedSecrets(evasionCfg)
		err := mgr.Start(&evasionCfg)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	} else {
		mgr.Stop()
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "applied",
		"enabled": req.Enabled,
	})
}

// GetEvasionTunnelLogs handles GET /api/system/evasion-tunnel/logs
func (s *Server) GetEvasionTunnelLogs(c *gin.Context) {
	evasionMgr := proxy.GetEvasionManager()
	evasionLogs := evasionMgr.GetLogs()

	tunMgr := system.GetTunRouterManager()
	tunLogs := tunMgr.GetLogs()

	totalLen := len(evasionLogs) + len(tunLogs)
	mergedLogs := make([]string, 0, totalLen)
	mergedLogs = append(mergedLogs, evasionLogs...)
	mergedLogs = append(mergedLogs, tunLogs...)

	sort.SliceStable(mergedLogs, func(i, j int) bool {
		return mergedLogs[i] < mergedLogs[j]
	})

	if len(mergedLogs) > 200 {
		mergedLogs = mergedLogs[len(mergedLogs)-200:]
	}

	c.JSON(http.StatusOK, gin.H{
		"logs": mergedLogs,
	})
}
