package mobilecore

import "github.com/maybeknott/luminet/internal/runtime/proxy"

// MobileConfig represents the configuration passed from JVM/iOS client apps.
type MobileConfig struct {
	Port                    int                         `json:"port"`
	SplitBytes              int                         `json:"split_bytes"`
	DelayMs                 int                         `json:"delay_ms"`
	MutateHost              bool                        `json:"mutate_host"`
	MutateHeaderSpace       bool                        `json:"mutate_header_space"`
	AutoSni                 bool                        `json:"auto_sni"`
	PrecisionSniSplits      bool                        `json:"precision_sni_splits"`
	SniSplitOffset          int                         `json:"sni_split_offset"`
	Packets                 string                      `json:"packets"`
	MinLength               int                         `json:"min_length"`
	MaxLength               int                         `json:"max_length"`
	TlsRecordSplit          bool                        `json:"tls_record_split"`
	DnsResolver             string                      `json:"dns_resolver"`
	DnsForwarderPort        int                         `json:"dns_forwarder_port"`
	DnsForwarderEnabled     bool                        `json:"dns_forwarder_enabled"`
	SystemProxyEnabled      bool                        `json:"system_proxy_enabled"`
	SniSpoof                string                      `json:"sni_spoof"`
	ClientHelloPadding      int                         `json:"client_hello_padding"`
	DelayJitter             bool                        `json:"delay_jitter"`
	TcpWindowClamp          int                         `json:"tcp_window_clamp"`
	CustomUserAgent         string                      `json:"custom_user_agent"`
	CovertMode              string                      `json:"covert_mode"`
	CovertServerlessUrl     string                      `json:"covert_serverless_url"`
	CovertDnsDomain         string                      `json:"covert_dns_domain"`
	CovertGsaUrl            string                      `json:"covert_gsa_url"`
	CovertGsaKey            string                      `json:"covert_gsa_key"`
	CovertGdocsFolderId     string                      `json:"covert_gdocs_folder_id"`
	CovertGdocsAccessToken  string                      `json:"covert_gdocs_access_token"`
	CovertCfg               proxy.CovertTransportConfig `json:"covert_cfg"`
	FakePacketInject        bool                        `json:"fake_packet_inject"`
	FakePacketTtl           int                         `json:"fake_packet_ttl"`
	MutateSniCase           bool                        `json:"mutate_sni_case"`
	MutateMethod            bool                        `json:"mutate_method"`
	MutateAbsoluteUri       bool                        `json:"mutate_absolute_uri"`
	HttpPadding             int                         `json:"http_padding"`
	PreflightSignature      string                      `json:"preflight_signature"`
	PreflightDelayMs        int                         `json:"preflight_delay_ms"`
	SessionFrag             bool                        `json:"session_frag"`
	SessionFragProb         float64                     `json:"session_frag_prob"`
	SessionFragMinTotal     int                         `json:"session_frag_min_total"`
	SessionFragMaxTotal     int                         `json:"session_frag_max_total"`
	SessionFragMinChunk     int                         `json:"session_frag_min_chunk"`
	SessionFragMaxChunk     int                         `json:"session_frag_max_chunk"`
	SessionFragMinDelayMs   int                         `json:"session_frag_min_delay_ms"`
	SessionFragMaxDelayMs   int                         `json:"session_frag_max_delay_ms"`
	IpSpoofingEnabled       bool                        `json:"ip_spoofing_enabled"`
	IpSpoofingDecoyIP       string                      `json:"ip_spoofing_decoy_ip"`
	IpSpoofingDstReal       string                      `json:"ip_spoofing_dst_real"`
	OutOfWindowEnabled      bool                        `json:"out_of_window_enabled"`
	OutOfWindowSeqOffset    int                         `json:"out_of_window_seq_offset"`
	DecoySniPool            string                      `json:"decoy_sni_pool"`
	OobEnabled              bool                        `json:"oob_enabled"`
	OobexEnabled            bool                        `json:"oobex_enabled"`
	AsyncReactorEnabled     bool                        `json:"async_reactor_enabled"`
	LossRate                float64                     `json:"loss_rate"`
	EmulatedLatency         int                         `json:"emulated_latency"`
	EmulatedJitter          int                         `json:"emulated_jitter"`
	CircularCacheCap        int                         `json:"circular_cache_cap"`
	RandomMultiSplit        bool                        `json:"random_multi_split"`
	NumFragments            int                         `json:"num_fragments"`
	ShaperReadRate          int64                       `json:"shaper_read_rate"`
	ShaperWriteRate         int64                       `json:"shaper_write_rate"`
	CovertSocketProtectPath string                      `json:"covert_socket_protect_path"`
	MobileAssetsEnabled     bool                        `json:"mobile_assets_enabled"`
	ZygiskHideEnabled       bool                        `json:"zygisk_hide_enabled"`
	HardenedTlsEnabled      bool                        `json:"hardened_tls_enabled"`
	UpgenEnabled            bool                        `json:"upgen_enabled"`
	UpgenSeedHex            string                      `json:"upgen_seed_hex"`
	UpgenEntropyMatch       bool                        `json:"upgen_entropy_match"`
	UpgenQuicExhaustionRate int                         `json:"upgen_quic_exhaustion_rate"`
	StegoEnabled            bool                        `json:"stego_enabled"`
	StegoMode               string                      `json:"stego_mode"`
	StegoDecoyImagePath     string                      `json:"stego_decoy_image_path"`
	StegoWebRTCSDPSpoof     bool                        `json:"stego_webrtc_sdp_spoof"`
	HostsOverride           bool                        `json:"hosts_override"`
	ResidentialCloaking     bool                        `json:"residential_cloaking"`
	ResidentialEgressNode   string                      `json:"residential_egress_node"`
	MssClampingValue        int                         `json:"mss_clamping_value"`
	DnsLeaksShield          bool                        `json:"dns_leaks_shield"`
	MssPreset               string                      `json:"mss_preset"`
	ShadowsocksPrefix       string                      `json:"shadowsocks_prefix"`
	AutoReconnectEnabled    bool                        `json:"auto_reconnect_enabled"`
	AutoReconnectMaxTries   int                         `json:"auto_reconnect_max_tries"`
	AutoReconnectDelayMs    int                         `json:"auto_reconnect_delay_ms"`

	// Location and sensor spoofing
	FakeLocationEnabled   bool    `json:"fake_location_enabled"`
	FakeLocationLatitude  float64 `json:"fake_location_latitude"`
	FakeLocationLongitude float64 `json:"fake_location_longitude"`
	FakeLocationAltitude  float64 `json:"fake_location_altitude"`
	FakeLocationAccuracy  float64 `json:"fake_location_accuracy"`
	FakeLocationSpeed     float64 `json:"fake_location_speed"`
	FakeCellTowerSpoof    bool    `json:"fake_cell_tower_spoof"`
	FakeWifiSpoof         bool    `json:"fake_wifi_spoof"`

	// Outbound proxy settings parsed from Xray configs
	RemoteAddress  string `json:"remote_address"`
	RemotePort     int    `json:"remote_port"`
	RemoteProtocol string `json:"remote_protocol"`
	RemoteUUID     string `json:"remote_uuid"`
	RemotePassword string `json:"remote_password"`
}
