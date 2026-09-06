package proxy

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/maybeknott/luminet/internal/foundation/flowregistry"
	"github.com/maybeknott/luminet/internal/platform/system"
	"github.com/maybeknott/luminet/internal/protocols/asyncreactor"
)

type EvasionConfig struct {
	Port                    int
	SplitBytes              int
	DelayMs                 int
	MutateHost              bool
	MutateHeaderSpace       bool
	AutoSni                 bool
	PrecisionSniSplits      bool // Precise multi-segment SNI splits from ZRLYN
	SniSplitOffset          int  // Hostname-level split offset inside TLS ClientHello Server Name Indication
	Packets                 string
	MinLength               int
	MaxLength               int
	TlsRecordSplit          bool
	DnsResolver             string
	DnsForwarderPort        int
	DnsForwarderEnabled     bool
	SystemProxyEnabled      bool   // Route all OS system traffic through this proxy via system settings
	SniSpoof                string // SNI spoofing target (optional)
	ClientHelloPadding      int    // TLS ClientHello padding size in bytes (optional)
	DelayJitter             bool
	TcpWindowClamp          int
	CustomUserAgent         string
	CovertMode              string                // Covert tunnel mode: "direct", "serverless", "dnstunnel", "gsa"
	CovertServerlessUrl     string                // Covert serverless WebSocket URL
	CovertDnsDomain         string                // Covert DNS tunnel base domain
	CovertGsaUrl            string                // Covert GSA Web App URL
	CovertGsaKey            string                // Covert GSA Auth Key
	CovertGdocsFolderId     string                // Covert GDocs folder ID
	CovertGdocsAccessToken  string                // Covert GDocs access token
	CovertCfg               CovertTransportConfig // Session 6 client transport configurations
	FakePacketInject        bool
	FakePacketTtl           int
	MutateSniCase           bool
	MutateMethod            bool
	MutateAbsoluteUri       bool
	HttpPadding             int
	PreflightSignature      string
	PreflightDelayMs        int
	SessionFrag             bool
	SessionFragProb         float64
	SessionFragMinTotal     int
	SessionFragMaxTotal     int
	SessionFragMinChunk     int
	SessionFragMaxChunk     int
	SessionFragMinDelayMs   int
	SessionFragMaxDelayMs   int
	IpSpoofingEnabled       bool
	IpSpoofingDecoyIP       string
	IpSpoofingDstReal       string
	OutOfWindowEnabled      bool
	OutOfWindowSeqOffset    int
	DecoySniPool            string
	OobEnabled              bool
	OobexEnabled            bool
	AsyncReactorEnabled     bool
	LossRate                float64
	EmulatedLatency         int
	EmulatedJitter          int
	CircularCacheCap        int
	RandomMultiSplit        bool
	NumFragments            int
	ShaperReadRate          int64
	ShaperWriteRate         int64
	CovertSocketProtectPath string
	MobileAssetsEnabled     bool
	ZygiskHideEnabled       bool
	HardenedTlsEnabled      bool
	UpgenEnabled            bool
	UpgenSeedHex            string
	UpgenEntropyMatch       bool
	UpgenQuicExhaustionRate int
	StegoEnabled            bool
	StegoMode               string
	StegoDecoyImagePath     string
	StegoWebRTCSDPSpoof     bool
	HostsOverride           bool
	ResidentialCloaking     bool   `json:"residential_cloaking"`
	ResidentialEgressNode   string `json:"residential_egress_node"`
	MssClampingValue        int    `json:"mss_clamping_value"`
	DnsLeaksShield          bool   `json:"dns_leaks_shield"`
	MssPreset               string `json:"mss_preset"`
	ShadowsocksPrefix       string `json:"shadowsocks_prefix"`
	AutoReconnectEnabled    bool   `json:"auto_reconnect_enabled"`
	AutoReconnectMaxTries   int    `json:"auto_reconnect_max_tries"`
	AutoReconnectDelayMs    int    `json:"auto_reconnect_delay_ms"`
}

type EvasionTunnelManager struct {
	lifecycleMu       sync.Mutex
	mu                sync.Mutex
	listener          net.Listener
	running           bool
	cancel            context.CancelFunc
	config            atomic.Pointer[EvasionConfig]
	onLog             func(string)
	logs              []string
	logMu             sync.RWMutex
	reactor           *asyncreactor.AsyncReactor
	circularCache     *circularCache
	packetInjector    PacketInjector
	acceptWG          sync.WaitGroup
	backgroundWG      sync.WaitGroup
	sessionWG         sync.WaitGroup
	sessionMu         sync.Mutex
	activeSessions    map[net.Conn]struct{}
	systemProxyBridge *httpSOCKSBridge
	systemProxyRoute  *system.HostNetworkChange
}

const (
	DefaultEvasionPort                   = 10888
	DefaultEvasionSplitBytes             = 2
	DefaultEvasionDelayMs                = 20
	DefaultEvasionMutateHost             = true
	DefaultEvasionMutateHeaderSpace      = false
	DefaultEvasionAutoSni                = true
	DefaultEvasionSniSplitOffset         = 0
	DefaultEvasionPackets                = "tlshello"
	DefaultEvasionMinLength              = 0
	DefaultEvasionMaxLength              = 0
	DefaultEvasionTlsRecordSplit         = true
	DefaultEvasionDnsResolver            = "https://dns.quad9.net/dns-query"
	DefaultEvasionDnsForwarderPort       = 10053
	DefaultEvasionDnsForwarderEnabled    = true
	DefaultEvasionSystemProxyEnabled     = false
	DefaultEvasionSniSpoof               = ""
	DefaultEvasionClientHelloPadding     = 0
	DefaultEvasionDelayJitter            = false
	DefaultEvasionTcpWindowClamp         = 0
	DefaultEvasionCustomUserAgent        = ""
	DefaultEvasionCovertMode             = "direct"
	DefaultEvasionCovertServerlessURL    = ""
	DefaultEvasionCovertDNSDomain        = ""
	DefaultEvasionCovertGsaURL           = ""
	DefaultEvasionCovertGsaKey           = ""
	DefaultEvasionCovertGdocsFolderId    = ""
	DefaultEvasionCovertGdocsAccessToken = ""
	DefaultEvasionFakePacketInject       = false
	DefaultEvasionFakePacketTtl          = 4
	DefaultEvasionPrecisionSniSplits     = true
	DefaultEvasionRandomMultiSplit       = false
	DefaultEvasionNumFragments           = 5

	// New advanced evasion defaults
	DefaultEvasionMutateSniCase      = false
	DefaultEvasionMutateMethod       = false
	DefaultEvasionMutateAbsoluteUri  = false
	DefaultEvasionHttpPadding        = 0
	DefaultEvasionPreflightSignature = ""
	DefaultEvasionPreflightDelayMs   = 0

	DefaultEvasionSessionFrag           = false
	DefaultEvasionSessionFragProb       = 1.0
	DefaultEvasionSessionFragMinTotal   = 5000
	DefaultEvasionSessionFragMaxTotal   = 10000
	DefaultEvasionSessionFragMinChunk   = 100
	DefaultEvasionSessionFragMaxChunk   = 1000
	DefaultEvasionSessionFragMinDelayMs = 10
	DefaultEvasionSessionFragMaxDelayMs = 100

	DefaultEvasionIpSpoofingEnabled = false
	DefaultEvasionIpSpoofingDecoyIP = ""
	DefaultEvasionIpSpoofingDstReal = ""

	DefaultEvasionOutOfWindowEnabled   = false
	DefaultEvasionOutOfWindowSeqOffset = 0
	DefaultEvasionDecoySniPool         = ""

	DefaultEvasionOobEnabled   = false
	DefaultEvasionOobexEnabled = false

	DefaultEvasionAsyncReactorEnabled = false
	DefaultEvasionLossRate            = 0.0
	DefaultEvasionEmulatedLatency     = 0
	DefaultEvasionEmulatedJitter      = 0
	DefaultEvasionCircularCacheCap    = 500
	DefaultEvasionShaperReadRate      = int64(0)
	DefaultEvasionShaperWriteRate     = int64(0)

	DefaultEvasionCovertSocketProtectPath = ""
	DefaultEvasionMobileAssetsEnabled     = true
	DefaultEvasionZygiskHideEnabled       = false
	DefaultEvasionHardenedTlsEnabled      = true

	DefaultEvasionUpgenEnabled            = false
	DefaultEvasionUpgenSeedHex            = "4a7b9e02c1f8d4"
	DefaultEvasionUpgenEntropyMatch       = true
	DefaultEvasionUpgenQuicExhaustionRate = 0
	DefaultEvasionStegoEnabled            = false
	DefaultEvasionStegoMode               = "webrtc_voip"
	DefaultEvasionStegoDecoyImagePath     = "/var/lib/luminet/decoy.png"
	DefaultEvasionStegoWebRTCSDPSpoof     = true

	DefaultEvasionShadowsocksPrefix     = ""
	DefaultEvasionAutoReconnectEnabled  = false
	DefaultEvasionAutoReconnectMaxTries = 5
	DefaultEvasionAutoReconnectDelayMs  = 500
)

var globalEvasionManager *EvasionTunnelManager
var globalEvasionOnce sync.Once
var evasionFlowCoverageOnce sync.Once

func declareEvasionFlowCoverage() {
	evasionFlowCoverageOnce.Do(func() {
		_ = flowregistry.Default().DeclareOwner(flowregistry.OwnerCoverage{
			Owner:               "evasion-socks",
			Visible:             true,
			Closeable:           true,
			ByteCounters:        true,
			DestinationMetadata: true,
			ProcessAttribution:  false,
			Notes: []string{
				"covers SOCKS5 TCP CONNECT sessions accepted by the LumiNet evasion listener",
				"UDP ASSOCIATE and external Xray/sing-box core flows are not represented by this owner",
			},
		})
	})
}

// DefaultEvasionConfig returns the canonical evasion defaults as an independent value.
// Transport adapters should start from this snapshot instead of importing individual default constants.
func DefaultEvasionConfig() EvasionConfig {
	return EvasionConfig{
		Port:                    DefaultEvasionPort,
		SplitBytes:              DefaultEvasionSplitBytes,
		DelayMs:                 DefaultEvasionDelayMs,
		MutateHost:              DefaultEvasionMutateHost,
		MutateHeaderSpace:       DefaultEvasionMutateHeaderSpace,
		AutoSni:                 DefaultEvasionAutoSni,
		PrecisionSniSplits:      DefaultEvasionPrecisionSniSplits,
		SniSplitOffset:          DefaultEvasionSniSplitOffset,
		Packets:                 DefaultEvasionPackets,
		MinLength:               DefaultEvasionMinLength,
		MaxLength:               DefaultEvasionMaxLength,
		TlsRecordSplit:          DefaultEvasionTlsRecordSplit,
		DnsResolver:             DefaultEvasionDnsResolver,
		DnsForwarderPort:        DefaultEvasionDnsForwarderPort,
		DnsForwarderEnabled:     DefaultEvasionDnsForwarderEnabled,
		SystemProxyEnabled:      DefaultEvasionSystemProxyEnabled,
		SniSpoof:                DefaultEvasionSniSpoof,
		ClientHelloPadding:      DefaultEvasionClientHelloPadding,
		DelayJitter:             DefaultEvasionDelayJitter,
		TcpWindowClamp:          DefaultEvasionTcpWindowClamp,
		CustomUserAgent:         DefaultEvasionCustomUserAgent,
		CovertMode:              DefaultEvasionCovertMode,
		CovertServerlessUrl:     DefaultEvasionCovertServerlessURL,
		CovertDnsDomain:         DefaultEvasionCovertDNSDomain,
		CovertGsaUrl:            DefaultEvasionCovertGsaURL,
		CovertGsaKey:            DefaultEvasionCovertGsaKey,
		CovertGdocsFolderId:     DefaultEvasionCovertGdocsFolderId,
		CovertGdocsAccessToken:  DefaultEvasionCovertGdocsAccessToken,
		FakePacketInject:        DefaultEvasionFakePacketInject,
		FakePacketTtl:           DefaultEvasionFakePacketTtl,
		MutateSniCase:           DefaultEvasionMutateSniCase,
		MutateMethod:            DefaultEvasionMutateMethod,
		MutateAbsoluteUri:       DefaultEvasionMutateAbsoluteUri,
		HttpPadding:             DefaultEvasionHttpPadding,
		PreflightSignature:      DefaultEvasionPreflightSignature,
		PreflightDelayMs:        DefaultEvasionPreflightDelayMs,
		SessionFrag:             DefaultEvasionSessionFrag,
		SessionFragProb:         DefaultEvasionSessionFragProb,
		SessionFragMinTotal:     DefaultEvasionSessionFragMinTotal,
		SessionFragMaxTotal:     DefaultEvasionSessionFragMaxTotal,
		SessionFragMinChunk:     DefaultEvasionSessionFragMinChunk,
		SessionFragMaxChunk:     DefaultEvasionSessionFragMaxChunk,
		SessionFragMinDelayMs:   DefaultEvasionSessionFragMinDelayMs,
		SessionFragMaxDelayMs:   DefaultEvasionSessionFragMaxDelayMs,
		IpSpoofingEnabled:       DefaultEvasionIpSpoofingEnabled,
		IpSpoofingDecoyIP:       DefaultEvasionIpSpoofingDecoyIP,
		IpSpoofingDstReal:       DefaultEvasionIpSpoofingDstReal,
		OutOfWindowEnabled:      DefaultEvasionOutOfWindowEnabled,
		OutOfWindowSeqOffset:    DefaultEvasionOutOfWindowSeqOffset,
		DecoySniPool:            DefaultEvasionDecoySniPool,
		OobEnabled:              DefaultEvasionOobEnabled,
		OobexEnabled:            DefaultEvasionOobexEnabled,
		AsyncReactorEnabled:     DefaultEvasionAsyncReactorEnabled,
		LossRate:                DefaultEvasionLossRate,
		EmulatedLatency:         DefaultEvasionEmulatedLatency,
		EmulatedJitter:          DefaultEvasionEmulatedJitter,
		CircularCacheCap:        DefaultEvasionCircularCacheCap,
		RandomMultiSplit:        DefaultEvasionRandomMultiSplit,
		NumFragments:            DefaultEvasionNumFragments,
		ShaperReadRate:          DefaultEvasionShaperReadRate,
		ShaperWriteRate:         DefaultEvasionShaperWriteRate,
		CovertSocketProtectPath: DefaultEvasionCovertSocketProtectPath,
		MobileAssetsEnabled:     DefaultEvasionMobileAssetsEnabled,
		ZygiskHideEnabled:       DefaultEvasionZygiskHideEnabled,
		HardenedTlsEnabled:      DefaultEvasionHardenedTlsEnabled,

		UpgenEnabled:            DefaultEvasionUpgenEnabled,
		UpgenSeedHex:            DefaultEvasionUpgenSeedHex,
		UpgenEntropyMatch:       DefaultEvasionUpgenEntropyMatch,
		UpgenQuicExhaustionRate: DefaultEvasionUpgenQuicExhaustionRate,
		StegoEnabled:            DefaultEvasionStegoEnabled,
		StegoMode:               DefaultEvasionStegoMode,
		StegoDecoyImagePath:     DefaultEvasionStegoDecoyImagePath,
		StegoWebRTCSDPSpoof:     DefaultEvasionStegoWebRTCSDPSpoof,
		ShadowsocksPrefix:       DefaultEvasionShadowsocksPrefix,
		AutoReconnectEnabled:    DefaultEvasionAutoReconnectEnabled,
		AutoReconnectMaxTries:   DefaultEvasionAutoReconnectMaxTries,
		AutoReconnectDelayMs:    DefaultEvasionAutoReconnectDelayMs,
		HostsOverride:           true,
	}
}

func GetEvasionManager() *EvasionTunnelManager {
	globalEvasionOnce.Do(func() {
		globalEvasionManager = &EvasionTunnelManager{}
		cfg := DefaultEvasionConfig()
		globalEvasionManager.config.Store(&cfg)
		declareEvasionFlowCoverage()
	})
	return globalEvasionManager
}

// ApplyBypassMode configures the evasion manager based on predefined stealth profiles.
func (m *EvasionTunnelManager) ApplyBypassMode(mode string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	oldCfg := m.config.Load()
	newCfg := *oldCfg

	switch mode {
	case "Fast":
		newCfg.SplitBytes = 2
		newCfg.DelayMs = 10
		newCfg.AutoSni = true
		newCfg.TlsRecordSplit = false
		newCfg.DelayJitter = false
		newCfg.FakePacketInject = false
	case "Balanced":
		newCfg.SplitBytes = 5
		newCfg.DelayMs = 25
		newCfg.AutoSni = true
		newCfg.TlsRecordSplit = true
		newCfg.DelayJitter = true
		newCfg.FakePacketInject = false
	case "Stealth":
		newCfg.SplitBytes = 1
		newCfg.DelayMs = 40
		newCfg.AutoSni = true
		newCfg.TlsRecordSplit = true
		newCfg.DelayJitter = true
		newCfg.FakePacketInject = true
		newCfg.FakePacketTtl = 4
		newCfg.MutateSniCase = true
		newCfg.SessionFrag = true
		newCfg.SessionFragProb = 1.0
		newCfg.SessionFragMinChunk = 50
		newCfg.SessionFragMaxChunk = 200
		newCfg.OobEnabled = true
		newCfg.RandomMultiSplit = true
		newCfg.NumFragments = 6
	case "Custom":
		// Do nothing, respect user's explicit flags
	}

	m.config.Store(&newCfg)
}

func (m *EvasionTunnelManager) Start(cfg *EvasionConfig) error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()

	if cfg == nil {
		return fmt.Errorf("evasion config is required")
	}

	newCfg := normalizeEvasionConfig(*cfg)
	if err := validateEvasionConfig(newCfg); err != nil {
		return err
	}

	// A replacement start owns the full lifetime transition. Do not let the
	// previous listener, sessions, or background workers overlap the new run.
	m.stopAndWait()
	m.mu.Lock()
	unreleasedHostRoute := m.systemProxyRoute != nil || m.systemProxyBridge != nil
	m.mu.Unlock()
	if unreleasedHostRoute {
		return fmt.Errorf("previous system-proxy route could not be released; recovery ownership remains active")
	}

	addr := net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", newCfg.Port))
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	var packetInjector PacketInjector
	if newCfg.FakePacketInject {
		packetInjector = NewPacketInjector()
		if err := packetInjector.Start(ctx, l.Addr().(*net.TCPAddr).Port); err != nil {
			cancel()
			_ = l.Close()
			return fmt.Errorf("start requested packet injector: %w", err)
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.listener = l
	m.running = true
	m.cancel = cancel
	m.packetInjector = packetInjector

	oldCfg := m.config.Load()

	newCfg.Port = l.Addr().(*net.TCPAddr).Port
	newCfg.DnsResolver = GetSecureResolverURL(newCfg.DnsResolver)

	m.config.Store(&newCfg)

	if m.circularCache == nil || oldCfg.CircularCacheCap != newCfg.CircularCacheCap {
		if newCfg.CircularCacheCap > 0 {
			m.circularCache = newCircularCache(newCfg.CircularCacheCap)
		} else {
			m.circularCache = nil
		}
	}

	if newCfg.AsyncReactorEnabled {
		var err error
		m.reactor, err = asyncreactor.NewAsyncReactor()
		if err != nil {
			m.log("Failed to start AsyncReactor: %v", err)
		} else {
			m.log("AsyncReactor started successfully.")
		}
	} else {
		if m.reactor != nil {
			_ = m.reactor.Close()
			m.reactor = nil
		}
	}

	m.ClearLogs()
	m.log("SOCKS5 Evasion Tunnel started on 127.0.0.1:%d (Packets: %s, Split: %d bytes, Range: %d-%d bytes, Delay: %dms, Host Mutation: %v, Header Space: %v, Auto SNI: %v, SNI Split Offset: %d, TLS Record Split: %v, DNS: %s, DNS Fwd Port: %d, DNS Fwd: %v, System Proxy: %v, SNI Spoof: %q, Padding: %d, Jitter: %v, Clamp: %d, UA: %q, CovertMode: %s, CovertURL: %q, CovertDomain: %q, CovertGsaURL: %q, CovertGsaKey: %q, CovertGdocsFolderId: %q, FakeInject: %v, FakeTTL: %d, SNICaseMut: %v, MethodMut: %v, AbsURI: %v, HttpPadding: %d, PreflightSig: %q, PreflightDelay: %d, SessionFrag: %v, SessionFragProb: %.2f, SessionFragMinTotal: %d, SessionFragMaxTotal: %d, SessionFragMinChunk: %d, SessionFragMaxChunk: %d, SessionFragMinDelayMs: %d, SessionFragMaxDelayMs: %d, IPSpoofing: %v, DecoyIP: %q, DstReal: %v, OutOfWindow: %v, OutOfWindowOffset: %d, DecoyPool: %q, OOB: %v, OOBEx: %v, AsyncReactor: %v, LossRate: %.2f%%, Latency: %dms, Jitter: %dms, CircularCacheCap: %d, ShaperReadRate: %d, ShaperWriteRate: %d, ProtectPath: %q, Assets: %v, Zygisk: %v, HardenedTLS: %v, 	UPGen: %v, Stego: %v, SSPrefix: %q, AutoReconnect: %v, ReconMaxTries: %d, ReconDelayMs: %d)", newCfg.Port, newCfg.Packets, newCfg.SplitBytes, newCfg.MinLength, newCfg.MaxLength, newCfg.DelayMs, newCfg.MutateHost, newCfg.MutateHeaderSpace, newCfg.AutoSni, newCfg.SniSplitOffset, newCfg.TlsRecordSplit, newCfg.DnsResolver, newCfg.DnsForwarderPort, newCfg.DnsForwarderEnabled, newCfg.SystemProxyEnabled, newCfg.SniSpoof, newCfg.ClientHelloPadding, newCfg.DelayJitter, newCfg.TcpWindowClamp, newCfg.CustomUserAgent, newCfg.CovertMode, newCfg.CovertServerlessUrl, newCfg.CovertDnsDomain, newCfg.CovertGsaUrl, redactEvasionSecret(newCfg.CovertGsaKey), newCfg.CovertGdocsFolderId, newCfg.FakePacketInject, newCfg.FakePacketTtl, newCfg.MutateSniCase, newCfg.MutateMethod, newCfg.MutateAbsoluteUri, newCfg.HttpPadding, newCfg.PreflightSignature, newCfg.PreflightDelayMs, newCfg.SessionFrag, newCfg.SessionFragProb, newCfg.SessionFragMinTotal, newCfg.SessionFragMaxTotal, newCfg.SessionFragMinChunk, newCfg.SessionFragMaxChunk, newCfg.SessionFragMinDelayMs, newCfg.SessionFragMaxDelayMs, newCfg.IpSpoofingEnabled, newCfg.IpSpoofingDecoyIP, newCfg.IpSpoofingDstReal, newCfg.OutOfWindowEnabled, newCfg.OutOfWindowSeqOffset, newCfg.DecoySniPool, newCfg.OobEnabled, newCfg.OobexEnabled, newCfg.AsyncReactorEnabled, newCfg.LossRate, newCfg.EmulatedLatency, newCfg.EmulatedJitter, newCfg.CircularCacheCap, newCfg.ShaperReadRate, newCfg.ShaperWriteRate, newCfg.CovertSocketProtectPath, newCfg.MobileAssetsEnabled, newCfg.ZygiskHideEnabled, newCfg.HardenedTlsEnabled, newCfg.UpgenEnabled, newCfg.StegoEnabled, newCfg.ShadowsocksPrefix, newCfg.AutoReconnectEnabled, newCfg.AutoReconnectMaxTries, newCfg.AutoReconnectDelayMs)

	m.acceptWG.Add(1)
	go func() {
		defer m.acceptWG.Done()
		for {
			conn, err := l.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					m.log("Accept error: %v", err)
					time.Sleep(100 * time.Millisecond)
					continue
				}
			}
			current := m.config.Load()
			if current == nil {
				_ = conn.Close()
				continue
			}
			sessionCfg := *current
			m.trackSession(conn)
			m.sessionWG.Add(1)
			go func(client net.Conn, snapshot EvasionConfig) {
				defer m.sessionWG.Done()
				defer m.untrackSession(client)
				m.handleSocksConnection(ctx, client, snapshot)
			}(conn, sessionCfg)
		}
	}()

	if newCfg.DnsForwarderEnabled {
		m.backgroundWG.Add(1)
		go func() {
			defer m.backgroundWG.Done()
			m.startDNSForwarder(newCfg.DnsForwarderPort, newCfg.DnsResolver, ctx)
		}()
	}

	if newCfg.SystemProxyEnabled {
		bridge, bridgeErr := startHTTPSOCKSBridge(net.JoinHostPort("127.0.0.1", strconv.Itoa(newCfg.Port)))
		if bridgeErr != nil {
			m.log("Failed to start bounded HTTP-to-SOCKS system-proxy bridge: %v", bridgeErr)
			newCfg.SystemProxyEnabled = false
			m.config.Store(&newCfg)
		} else {
			server := bridge.Addr()
			if runtime.GOOS == "windows" {
				server = fmt.Sprintf("http=%s;https=%s", bridge.Addr(), bridge.Addr())
			}
			route := system.HostNetworkChange{
				Kind:      system.HostNetworkChangeRoute,
				RouteMode: system.HostRouteProxy,
				Proxy:     system.ProxySettings{Enabled: true, Server: server, Bypass: "<local>"},
			}
			if err := system.ApplyHostNetwork(context.Background(), route); err != nil {
				_ = bridge.Close()
				m.log("Failed to enable system-wide HTTP proxy bridge: %v", err)
				newCfg.SystemProxyEnabled = false
				m.config.Store(&newCfg)
			} else {
				m.systemProxyBridge = bridge
				routeCopy := route
				m.systemProxyRoute = &routeCopy
				m.log("System-wide HTTP proxy bridge configured on %s -> SOCKS5 127.0.0.1:%d", bridge.Addr(), newCfg.Port)
			}
		}
	}

	return nil
}

func (m *EvasionTunnelManager) Stop() {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	m.stopAndWait()
}

func (m *EvasionTunnelManager) stopAndWait() {
	m.mu.Lock()
	m.stopUnlocked()
	m.mu.Unlock()

	// The accept loop is the sole producer of sessionWG.Add calls. Joining it
	// first makes the subsequent session wait safe and deterministic.
	m.acceptWG.Wait()
	m.closeActiveSessions()
	m.sessionWG.Wait()
	m.backgroundWG.Wait()
}

func (m *EvasionTunnelManager) trackSession(conn net.Conn) {
	m.sessionMu.Lock()
	defer m.sessionMu.Unlock()
	if m.activeSessions == nil {
		m.activeSessions = make(map[net.Conn]struct{})
	}
	m.activeSessions[conn] = struct{}{}
}

func (m *EvasionTunnelManager) untrackSession(conn net.Conn) {
	m.sessionMu.Lock()
	delete(m.activeSessions, conn)
	m.sessionMu.Unlock()
}

func (m *EvasionTunnelManager) closeActiveSessions() {
	m.sessionMu.Lock()
	connections := make([]net.Conn, 0, len(m.activeSessions))
	for conn := range m.activeSessions {
		connections = append(connections, conn)
	}
	m.sessionMu.Unlock()
	for _, conn := range connections {
		_ = conn.Close()
	}
}

func (m *EvasionTunnelManager) stopUnlocked() {
	if m.running {
		m.running = false
		if m.systemProxyRoute != nil {
			if err := system.ReleaseHostNetworkRoute(context.Background(), *m.systemProxyRoute); err != nil {
				// Do not tear down the HTTP bridge or clear ownership evidence. The
				// underlying SOCKS listener will stop below, so host traffic fails
				// closed through the still-owned bridge until recovery succeeds.
				m.log("Failed to restore pre-LumiNet system proxy; keeping recovery ownership: %v", err)
			} else {
				m.log("Original system proxy configuration restored.")
				if m.systemProxyBridge != nil {
					_ = m.systemProxyBridge.Close()
				}
				m.systemProxyBridge = nil
				m.systemProxyRoute = nil
				for {
					old := m.config.Load()
					if old == nil {
						break
					}
					newCfg := *old
					newCfg.SystemProxyEnabled = false
					if m.config.CompareAndSwap(old, &newCfg) {
						break
					}
				}
			}
		} else if m.systemProxyBridge != nil {
			_ = m.systemProxyBridge.Close()
			m.systemProxyBridge = nil
		}
		if m.cancel != nil {
			m.cancel()
		}
		if m.listener != nil {
			_ = m.listener.Close()
		}
		if m.packetInjector != nil {
			_ = m.packetInjector.Stop()
			m.packetInjector = nil
		}
		if m.reactor != nil {
			_ = m.reactor.Close()
			m.reactor = nil
		}
		m.log("SOCKS5 Evasion Tunnel stopped.")
	}
}

// EvasionTunnelStatus is a read-only snapshot of tunnel status.
// Returned by Status() to prevent data races from exposing mutable config.
type EvasionTunnelStatus struct {
	Running     bool   `json:"running"`
	Port        int    `json:"port"`
	SplitBytes  int    `json:"split_bytes"`
	DelayMs     int    `json:"delay_ms"`
	MutateHost  bool   `json:"mutate_host"`
	AutoSni     bool   `json:"auto_sni"`
	DnsResolver string `json:"dns_resolver"`
	CovertMode  string `json:"covert_mode"`
}

func (m *EvasionTunnelManager) Status() EvasionTunnelStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg := m.config.Load()
	return EvasionTunnelStatus{
		Running:     m.running,
		Port:        cfg.Port,
		SplitBytes:  cfg.SplitBytes,
		DelayMs:     cfg.DelayMs,
		MutateHost:  cfg.MutateHost,
		AutoSni:     cfg.AutoSni,
		DnsResolver: cfg.DnsResolver,
		CovertMode:  cfg.CovertMode,
	}
}

func (m *EvasionTunnelManager) GetConfig() EvasionConfig {
	cfg := m.config.Load()
	if cfg == nil {
		return EvasionConfig{}
	}
	return *cfg
}

func (m *EvasionTunnelManager) IsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

func (m *EvasionTunnelManager) GetLogs() []string {
	m.logMu.RLock()
	defer m.logMu.RUnlock()
	res := make([]string, len(m.logs))
	copy(res, m.logs)
	return res
}

func (m *EvasionTunnelManager) ClearLogs() {
	m.logMu.Lock()
	defer m.logMu.Unlock()
	m.logs = nil
}

func (m *EvasionTunnelManager) SetOnLog(f func(string)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onLog = f
}

func (m *EvasionTunnelManager) log(format string, args ...interface{}) {
	msg := fmt.Sprintf("[%s] ", time.Now().Format("15:04:05")) + fmt.Sprintf(format, args...)
	m.logMu.Lock()
	m.logs = append(m.logs, msg)
	if len(m.logs) > 200 {
		m.logs = m.logs[1:]
	}
	onLog := m.onLog
	m.logMu.Unlock()
	if onLog != nil {
		onLog(msg)
	}
}

// CovertTransportConfig defines settings for Session 6 client transport layers.
type CovertTransportConfig struct {
	WsEndpoint    string `json:"ws_endpoint"`
	WsHeaders     string `json:"ws_headers"`
	WsUseUtls     bool   `json:"ws_use_utls"`
	WsFingerprint string `json:"ws_fingerprint"`
	WsPadding     bool   `json:"ws_padding"`
	WsTunnelType  int    `json:"ws_tunnel_type"` // 1 = WSTunnel (WebSocket), 2 = Stunnel (TCP/TLS)

	SshHost          string `json:"ssh_host"`
	SshUser          string `json:"ssh_user"`
	SshPass          string `json:"ssh_pass"`
	SshKey           string `json:"ssh_key"`
	SshKeyPassphrase string `json:"ssh_key_passphrase"`
	SshHostKeySHA256 string `json:"ssh_host_key_sha256"`

	KcpNoDelay      int `json:"kcp_nodelay"`
	KcpInterval     int `json:"kcp_interval"`
	KcpResend       int `json:"kcp_resend"`
	KcpNoCongestion int `json:"kcp_nocongestion"`
	KcpSendWnd      int `json:"kcp_sndwnd"`
	KcpRecvWnd      int `json:"kcp_rcvwnd"`
	KcpMtu          int `json:"kcp_mtu"`

	TuicUuid  string `json:"tuic_uuid"`
	TuicToken string `json:"tuic_token"`
}

func (m *EvasionTunnelManager) SetHostsOverride(val bool) {
	for {
		old := m.config.Load()
		newCfg := *old
		newCfg.HostsOverride = val
		if m.config.CompareAndSwap(old, &newCfg) {
			break
		}
	}
}

func (m *EvasionTunnelManager) GetHostsOverride() bool {
	return m.config.Load().HostsOverride
}

func (m *EvasionTunnelManager) GetPrecisionSniSplits() bool {
	return m.config.Load().PrecisionSniSplits
}

func (m *EvasionTunnelManager) SetPrecisionSniSplits(v bool) {
	for {
		old := m.config.Load()
		newCfg := *old
		newCfg.PrecisionSniSplits = v
		if m.config.CompareAndSwap(old, &newCfg) {
			break
		}
	}
}
