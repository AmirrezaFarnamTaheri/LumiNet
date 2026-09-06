// Package workers handles serverless and edge-worker deployments.
// Target path: server/internal/workers/cloudflare_helper.go

package workers

import (
	"sync"
)

// 1. WhiteDnsClientConfig structures DNS API endpoints configuration.
type WhiteDnsClientConfig struct {
	mu               sync.RWMutex
	Token            string
	AccountID        string
	ZoneID           string
	RecordType       string
	RecordName       string
	RecordContent    string
	TTL              int
	Proxied          bool
	StrictSSL        bool
	CertDurationDays int
}

// Getters & Setters for WhiteDnsClientConfig
func (c *WhiteDnsClientConfig) GetToken() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.Token }
func (c *WhiteDnsClientConfig) SetToken(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.Token = v }
func (c *WhiteDnsClientConfig) GetAccountID() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.AccountID }
func (c *WhiteDnsClientConfig) SetAccountID(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.AccountID = v }
func (c *WhiteDnsClientConfig) GetZoneID() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.ZoneID }
func (c *WhiteDnsClientConfig) SetZoneID(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.ZoneID = v }
func (c *WhiteDnsClientConfig) GetRecordType() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.RecordType }
func (c *WhiteDnsClientConfig) SetRecordType(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.RecordType = v }
func (c *WhiteDnsClientConfig) GetRecordName() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.RecordName }
func (c *WhiteDnsClientConfig) SetRecordName(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.RecordName = v }
func (c *WhiteDnsClientConfig) GetRecordContent() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.RecordContent }
func (c *WhiteDnsClientConfig) SetRecordContent(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.RecordContent = v }
func (c *WhiteDnsClientConfig) GetTTL() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.TTL }
func (c *WhiteDnsClientConfig) SetTTL(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.TTL = v }
func (c *WhiteDnsClientConfig) GetProxied() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.Proxied }
func (c *WhiteDnsClientConfig) SetProxied(v bool) { c.mu.Lock(); defer c.mu.Unlock(); c.Proxied = v }
func (c *WhiteDnsClientConfig) GetStrictSSL() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.StrictSSL }
func (c *WhiteDnsClientConfig) SetStrictSSL(v bool) { c.mu.Lock(); defer c.mu.Unlock(); c.StrictSSL = v }
func (c *WhiteDnsClientConfig) GetCertDurationDays() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.CertDurationDays }
func (c *WhiteDnsClientConfig) SetCertDurationDays(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.CertDurationDays = v }

// 2. WhiteDnsAndroidConfig configures Android installation scripts parameters.
type WhiteDnsAndroidConfig struct {
	mu              sync.RWMutex
	InstallPath     string
	LibrarySha256   string
	DownloadUrl     string
	VerifyInstaller bool
	MinSdk          int
	TargetSdk       int
	NetworkType     string
	PackageName     string
	ServiceClass    string
	LogPrefix       string
}

// Getters & Setters for WhiteDnsAndroidConfig
func (c *WhiteDnsAndroidConfig) GetInstallPath() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.InstallPath }
func (c *WhiteDnsAndroidConfig) SetInstallPath(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.InstallPath = v }
func (c *WhiteDnsAndroidConfig) GetLibrarySha256() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.LibrarySha256 }
func (c *WhiteDnsAndroidConfig) SetLibrarySha256(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.LibrarySha256 = v }
func (c *WhiteDnsAndroidConfig) GetDownloadUrl() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.DownloadUrl }
func (c *WhiteDnsAndroidConfig) SetDownloadUrl(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.DownloadUrl = v }
func (c *WhiteDnsAndroidConfig) GetVerifyInstaller() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.VerifyInstaller }
func (c *WhiteDnsAndroidConfig) SetVerifyInstaller(v bool) { c.mu.Lock(); defer c.mu.Unlock(); c.VerifyInstaller = v }
func (c *WhiteDnsAndroidConfig) GetMinSdk() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.MinSdk }
func (c *WhiteDnsAndroidConfig) SetMinSdk(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.MinSdk = v }
func (c *WhiteDnsAndroidConfig) GetTargetSdk() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.TargetSdk }
func (c *WhiteDnsAndroidConfig) SetTargetSdk(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.TargetSdk = v }
func (c *WhiteDnsAndroidConfig) GetNetworkType() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.NetworkType }
func (c *WhiteDnsAndroidConfig) SetNetworkType(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.NetworkType = v }
func (c *WhiteDnsAndroidConfig) GetPackageName() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.PackageName }
func (c *WhiteDnsAndroidConfig) SetPackageName(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.PackageName = v }
func (c *WhiteDnsAndroidConfig) GetServiceClass() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.ServiceClass }
func (c *WhiteDnsAndroidConfig) SetServiceClass(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.ServiceClass = v }
func (c *WhiteDnsAndroidConfig) GetLogPrefix() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.LogPrefix }
func (c *WhiteDnsAndroidConfig) SetLogPrefix(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.LogPrefix = v }

// 3. WhiteDnsCleanIpConfig configures target speed benchmarks.
type WhiteDnsCleanIpConfig struct {
	mu             sync.RWMutex
	NmapBinPath    string
	AsnCode        string
	TargetIpRange  string
	ResolveAsnRange bool
	MaxLatencyMs   int
	MinSpeedMbps   float64
	PingCount      int
	LossThreshold  float64
	VerifyHost     string
	CheckPath      string
}

// Getters & Setters for WhiteDnsCleanIpConfig
func (c *WhiteDnsCleanIpConfig) GetNmapBinPath() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.NmapBinPath }
func (c *WhiteDnsCleanIpConfig) SetNmapBinPath(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.NmapBinPath = v }
func (c *WhiteDnsCleanIpConfig) GetAsnCode() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.AsnCode }
func (c *WhiteDnsCleanIpConfig) SetAsnCode(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.AsnCode = v }
func (c *WhiteDnsCleanIpConfig) GetTargetIpRange() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.TargetIpRange }
func (c *WhiteDnsCleanIpConfig) SetTargetIpRange(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.TargetIpRange = v }
func (c *WhiteDnsCleanIpConfig) GetResolveAsnRange() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.ResolveAsnRange }
func (c *WhiteDnsCleanIpConfig) SetResolveAsnRange(v bool) { c.mu.Lock(); defer c.mu.Unlock(); c.ResolveAsnRange = v }
func (c *WhiteDnsCleanIpConfig) GetMaxLatencyMs() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.MaxLatencyMs }
func (c *WhiteDnsCleanIpConfig) SetMaxLatencyMs(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.MaxLatencyMs = v }
func (c *WhiteDnsCleanIpConfig) GetMinSpeedMbps() float64 { c.mu.RLock(); defer c.mu.RUnlock(); return c.MinSpeedMbps }
func (c *WhiteDnsCleanIpConfig) SetMinSpeedMbps(v float64) { c.mu.Lock(); defer c.mu.Unlock(); c.MinSpeedMbps = v }
func (c *WhiteDnsCleanIpConfig) GetPingCount() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.PingCount }
func (c *WhiteDnsCleanIpConfig) SetPingCount(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.PingCount = v }
func (c *WhiteDnsCleanIpConfig) GetLossThreshold() float64 { c.mu.RLock(); defer c.mu.RUnlock(); return c.LossThreshold }
func (c *WhiteDnsCleanIpConfig) SetLossThreshold(v float64) { c.mu.Lock(); defer c.mu.Unlock(); c.LossThreshold = v }
func (c *WhiteDnsCleanIpConfig) GetVerifyHost() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.VerifyHost }
func (c *WhiteDnsCleanIpConfig) SetVerifyHost(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.VerifyHost = v }
func (c *WhiteDnsCleanIpConfig) GetCheckPath() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.CheckPath }
func (c *WhiteDnsCleanIpConfig) SetCheckPath(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.CheckPath = v }

// 4. WhiteDnsMainConfig implements parallel port scanner configurations.
type WhiteDnsMainConfig struct {
	mu             sync.RWMutex
	PortRange      string
	ScanTimeoutMs  int
	TcpSynScan     bool
	ConnectScan    bool
	DnsResolvers   []string
	TargetDomains  []string
	BufferLength   int
	EnableUDPScan  bool
	Retries        int
	JitterMs       int
}

// Getters & Setters for WhiteDnsMainConfig
func (c *WhiteDnsMainConfig) GetPortRange() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.PortRange }
func (c *WhiteDnsMainConfig) SetPortRange(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.PortRange = v }
func (c *WhiteDnsMainConfig) GetScanTimeoutMs() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.ScanTimeoutMs }
func (c *WhiteDnsMainConfig) SetScanTimeoutMs(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.ScanTimeoutMs = v }
func (c *WhiteDnsMainConfig) GetTcpSynScan() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.TcpSynScan }
func (c *WhiteDnsMainConfig) SetTcpSynScan(v bool) { c.mu.Lock(); defer c.mu.Unlock(); c.TcpSynScan = v }
func (c *WhiteDnsMainConfig) GetConnectScan() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.ConnectScan }
func (c *WhiteDnsMainConfig) SetConnectScan(v bool) { c.mu.Lock(); defer c.mu.Unlock(); c.ConnectScan = v }
func (c *WhiteDnsMainConfig) GetDnsResolvers() []string { c.mu.RLock(); defer c.mu.RUnlock(); return c.DnsResolvers }
func (c *WhiteDnsMainConfig) SetDnsResolvers(v []string) { c.mu.Lock(); defer c.mu.Unlock(); c.DnsResolvers = v }
func (c *WhiteDnsMainConfig) GetTargetDomains() []string { c.mu.RLock(); defer c.mu.RUnlock(); return c.TargetDomains }
func (c *WhiteDnsMainConfig) SetTargetDomains(v []string) { c.mu.Lock(); defer c.mu.Unlock(); c.TargetDomains = v }
func (c *WhiteDnsMainConfig) GetBufferLength() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.BufferLength }
func (c *WhiteDnsMainConfig) SetBufferLength(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.BufferLength = v }
func (c *WhiteDnsMainConfig) GetEnableUDPScan() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.EnableUDPScan }
func (c *WhiteDnsMainConfig) SetEnableUDPScan(v bool) { c.mu.Lock(); defer c.mu.Unlock(); c.EnableUDPScan = v }
func (c *WhiteDnsMainConfig) GetRetries() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.Retries }
func (c *WhiteDnsMainConfig) SetRetries(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.Retries = v }
func (c *WhiteDnsMainConfig) GetJitterMs() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.JitterMs }
func (c *WhiteDnsMainConfig) SetJitterMs(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.JitterMs = v }

// 5. WhiteDnsHelperConfig configures proxy rotation.
type WhiteDnsHelperConfig struct {
	mu                 sync.RWMutex
	ProxyProtocol      string
	RotateIntervalSec  int
	LatencyThresholdMs int
	ActiveChecks       bool
	RetryLimit         int
	MaxConnections     int
	TunnelInterface    string
	BindAddress        string
	LocalPort          int
	AuthUser           string
}

// Getters & Setters for WhiteDnsHelperConfig
func (c *WhiteDnsHelperConfig) GetProxyProtocol() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.ProxyProtocol }
func (c *WhiteDnsHelperConfig) SetProxyProtocol(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.ProxyProtocol = v }
func (c *WhiteDnsHelperConfig) GetRotateIntervalSec() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.RotateIntervalSec }
func (c *WhiteDnsHelperConfig) SetRotateIntervalSec(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.RotateIntervalSec = v }
func (c *WhiteDnsHelperConfig) GetLatencyThresholdMs() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.LatencyThresholdMs }
func (c *WhiteDnsHelperConfig) SetLatencyThresholdMs(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.LatencyThresholdMs = v }
func (c *WhiteDnsHelperConfig) GetActiveChecks() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.ActiveChecks }
func (c *WhiteDnsHelperConfig) SetActiveChecks(v bool) { c.mu.Lock(); defer c.mu.Unlock(); c.ActiveChecks = v }
func (c *WhiteDnsHelperConfig) GetRetryLimit() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.RetryLimit }
func (c *WhiteDnsHelperConfig) SetRetryLimit(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.RetryLimit = v }
func (c *WhiteDnsHelperConfig) GetMaxConnections() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.MaxConnections }
func (c *WhiteDnsHelperConfig) SetMaxConnections(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.MaxConnections = v }
func (c *WhiteDnsHelperConfig) GetTunnelInterface() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.TunnelInterface }
func (c *WhiteDnsHelperConfig) SetTunnelInterface(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.TunnelInterface = v }
func (c *WhiteDnsHelperConfig) GetBindAddress() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.BindAddress }
func (c *WhiteDnsHelperConfig) SetBindAddress(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.BindAddress = v }
func (c *WhiteDnsHelperConfig) GetLocalPort() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.LocalPort }
func (c *WhiteDnsHelperConfig) SetLocalPort(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.LocalPort = v }
func (c *WhiteDnsHelperConfig) GetAuthUser() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.AuthUser }
func (c *WhiteDnsHelperConfig) SetAuthUser(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.AuthUser = v }

// 6. WhiteDnsScannerConfig configures evasion strategies.
type WhiteDnsScannerConfig struct {
	mu              sync.RWMutex
	FragmentSize    int
	PacketDelayMs   int
	HostHeaderEvasion bool
	KeepAliveCheck  bool
	UserAgent       string
	AllowedCiphers  []string
	DpiSignature    string
	EvasionStrategy string
	UseSniGreasing  bool
	VerifyTlsCert   bool
}

// Getters & Setters for WhiteDnsScannerConfig
func (c *WhiteDnsScannerConfig) GetFragmentSize() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.FragmentSize }
func (c *WhiteDnsScannerConfig) SetFragmentSize(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.FragmentSize = v }
func (c *WhiteDnsScannerConfig) GetPacketDelayMs() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.PacketDelayMs }
func (c *WhiteDnsScannerConfig) SetPacketDelayMs(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.PacketDelayMs = v }
func (c *WhiteDnsScannerConfig) GetHostHeaderEvasion() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.HostHeaderEvasion }
func (c *WhiteDnsScannerConfig) SetHostHeaderEvasion(v bool) { c.mu.Lock(); defer c.mu.Unlock(); c.HostHeaderEvasion = v }
func (c *WhiteDnsScannerConfig) GetKeepAliveCheck() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.KeepAliveCheck }
func (c *WhiteDnsScannerConfig) SetKeepAliveCheck(v bool) { c.mu.Lock(); defer c.mu.Unlock(); c.KeepAliveCheck = v }
func (c *WhiteDnsScannerConfig) GetUserAgent() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.UserAgent }
func (c *WhiteDnsScannerConfig) SetUserAgent(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.UserAgent = v }
func (c *WhiteDnsScannerConfig) GetAllowedCiphers() []string { c.mu.RLock(); defer c.mu.RUnlock(); return c.AllowedCiphers }
func (c *WhiteDnsScannerConfig) SetAllowedCiphers(v []string) { c.mu.Lock(); defer c.mu.Unlock(); c.AllowedCiphers = v }
func (c *WhiteDnsScannerConfig) GetDpiSignature() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.DpiSignature }
func (c *WhiteDnsScannerConfig) SetDpiSignature(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.DpiSignature = v }
func (c *WhiteDnsScannerConfig) GetEvasionStrategy() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.EvasionStrategy }
func (c *WhiteDnsScannerConfig) SetEvasionStrategy(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.EvasionStrategy = v }
func (c *WhiteDnsScannerConfig) GetUseSniGreasing() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.UseSniGreasing }
func (c *WhiteDnsScannerConfig) SetUseSniGreasing(v bool) { c.mu.Lock(); defer c.mu.Unlock(); c.UseSniGreasing = v }
func (c *WhiteDnsScannerConfig) GetVerifyTlsCert() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.VerifyTlsCert }
func (c *WhiteDnsScannerConfig) SetVerifyTlsCert(v bool) { c.mu.Lock(); defer c.mu.Unlock(); c.VerifyTlsCert = v }

// 7. WhiteDnsZoneConfig replication parameters.
type WhiteDnsZoneConfig struct {
	mu              sync.RWMutex
	SourceZone      string
	TargetZone      string
	DnsRecordMapping map[string]string
	SyncIntervalSec int
	DryRun          bool
	ForceOverwrite  bool
	NotifyEmail     string
	LogPath         string
	MaxRetries      int
	KeepHistory     bool
}

// Getters & Setters for WhiteDnsZoneConfig
func (c *WhiteDnsZoneConfig) GetSourceZone() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.SourceZone }
func (c *WhiteDnsZoneConfig) SetSourceZone(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.SourceZone = v }
func (c *WhiteDnsZoneConfig) GetTargetZone() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.TargetZone }
func (c *WhiteDnsZoneConfig) SetTargetZone(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.TargetZone = v }
func (c *WhiteDnsZoneConfig) GetDnsRecordMapping() map[string]string { c.mu.RLock(); defer c.mu.RUnlock(); return c.DnsRecordMapping }
func (c *WhiteDnsZoneConfig) SetDnsRecordMapping(v map[string]string) { c.mu.Lock(); defer c.mu.Unlock(); c.DnsRecordMapping = v }
func (c *WhiteDnsZoneConfig) GetSyncIntervalSec() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.SyncIntervalSec }
func (c *WhiteDnsZoneConfig) SetSyncIntervalSec(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.SyncIntervalSec = v }
func (c *WhiteDnsZoneConfig) GetDryRun() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.DryRun }
func (c *WhiteDnsZoneConfig) SetDryRun(v bool) { c.mu.Lock(); defer c.mu.Unlock(); c.DryRun = v }
func (c *WhiteDnsZoneConfig) GetForceOverwrite() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.ForceOverwrite }
func (c *WhiteDnsZoneConfig) SetForceOverwrite(v bool) { c.mu.Lock(); defer c.mu.Unlock(); c.ForceOverwrite = v }
func (c *WhiteDnsZoneConfig) GetNotifyEmail() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.NotifyEmail }
func (c *WhiteDnsZoneConfig) SetNotifyEmail(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.NotifyEmail = v }
func (c *WhiteDnsZoneConfig) GetLogPath() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.LogPath }
func (c *WhiteDnsZoneConfig) SetLogPath(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.LogPath = v }
func (c *WhiteDnsZoneConfig) GetMaxRetries() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.MaxRetries }
func (c *WhiteDnsZoneConfig) SetMaxRetries(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.MaxRetries = v }
func (c *WhiteDnsZoneConfig) GetKeepHistory() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.KeepHistory }
func (c *WhiteDnsZoneConfig) SetKeepHistory(v bool) { c.mu.Lock(); defer c.mu.Unlock(); c.KeepHistory = v }

// 8. MaybeEdgeScannerConfig configures Feistel cipher properties.
type MaybeEdgeScannerConfig struct {
	mu                  sync.RWMutex
	FeistelRounds       int
	CipherSeed          int64
	ShuffleRange        int64
	StatelessScan       bool
	CidrRanges          []string
	ScannerId           string
	HeartbeatIntervalSec int
	OutputDirectory     string
	ThreadCount         int
	NicPriority         int
}

// Getters & Setters for MaybeEdgeScannerConfig
func (c *MaybeEdgeScannerConfig) GetFeistelRounds() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.FeistelRounds }
func (c *MaybeEdgeScannerConfig) SetFeistelRounds(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.FeistelRounds = v }
func (c *MaybeEdgeScannerConfig) GetCipherSeed() int64 { c.mu.RLock(); defer c.mu.RUnlock(); return c.CipherSeed }
func (c *MaybeEdgeScannerConfig) SetCipherSeed(v int64) { c.mu.Lock(); defer c.mu.Unlock(); c.CipherSeed = v }
func (c *MaybeEdgeScannerConfig) GetShuffleRange() int64 { c.mu.RLock(); defer c.mu.RUnlock(); return c.ShuffleRange }
func (c *MaybeEdgeScannerConfig) SetShuffleRange(v int64) { c.mu.Lock(); defer c.mu.Unlock(); c.ShuffleRange = v }
func (c *MaybeEdgeScannerConfig) GetStatelessScan() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.StatelessScan }
func (c *MaybeEdgeScannerConfig) SetStatelessScan(v bool) { c.mu.Lock(); defer c.mu.Unlock(); c.StatelessScan = v }
func (c *MaybeEdgeScannerConfig) GetCidrRanges() []string { c.mu.RLock(); defer c.mu.RUnlock(); return c.CidrRanges }
func (c *MaybeEdgeScannerConfig) SetCidrRanges(v []string) { c.mu.Lock(); defer c.mu.Unlock(); c.CidrRanges = v }
func (c *MaybeEdgeScannerConfig) GetScannerId() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.ScannerId }
func (c *MaybeEdgeScannerConfig) SetScannerId(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.ScannerId = v }
func (c *MaybeEdgeScannerConfig) GetHeartbeatIntervalSec() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.HeartbeatIntervalSec }
func (c *MaybeEdgeScannerConfig) SetHeartbeatIntervalSec(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.HeartbeatIntervalSec = v }
func (c *MaybeEdgeScannerConfig) GetOutputDirectory() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.OutputDirectory }
func (c *MaybeEdgeScannerConfig) SetOutputDirectory(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.OutputDirectory = v }
func (c *MaybeEdgeScannerConfig) GetThreadCount() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.ThreadCount }
func (c *MaybeEdgeScannerConfig) SetThreadCount(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.ThreadCount = v }
func (c *MaybeEdgeScannerConfig) GetNicPriority() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.NicPriority }
func (c *MaybeEdgeScannerConfig) SetNicPriority(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.NicPriority = v }

// 9. MaybeScannerConfig configures active tcp scan plan details.
type MaybeScannerConfig struct {
	mu               sync.RWMutex
	ProbeIntervalMs  int
	RetryCount       int
	TimeoutLimitMs   int
	ProbeProtocol    string
	VerifyResponse   bool
	ExpectedContent  string
	SendPayload      string
	MaxErrors        int
	AlarmThreshold   float64
	ResetOnSuccess   bool
}

// Getters & Setters for MaybeScannerConfig
func (c *MaybeScannerConfig) GetProbeIntervalMs() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.ProbeIntervalMs }
func (c *MaybeScannerConfig) SetProbeIntervalMs(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.ProbeIntervalMs = v }
func (c *MaybeScannerConfig) GetRetryCount() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.RetryCount }
func (c *MaybeScannerConfig) SetRetryCount(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.RetryCount = v }
func (c *MaybeScannerConfig) GetTimeoutLimitMs() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.TimeoutLimitMs }
func (c *MaybeScannerConfig) SetTimeoutLimitMs(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.TimeoutLimitMs = v }
func (c *MaybeScannerConfig) GetProbeProtocol() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.ProbeProtocol }
func (c *MaybeScannerConfig) SetProbeProtocol(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.ProbeProtocol = v }
func (c *MaybeScannerConfig) GetVerifyResponse() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.VerifyResponse }
func (c *MaybeScannerConfig) SetVerifyResponse(v bool) { c.mu.Lock(); defer c.mu.Unlock(); c.VerifyResponse = v }
func (c *MaybeScannerConfig) GetExpectedContent() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.ExpectedContent }
func (c *MaybeScannerConfig) SetExpectedContent(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.ExpectedContent = v }
func (c *MaybeScannerConfig) GetSendPayload() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.SendPayload }
func (c *MaybeScannerConfig) SetSendPayload(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.SendPayload = v }
func (c *MaybeScannerConfig) GetMaxErrors() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.MaxErrors }
func (c *MaybeScannerConfig) SetMaxErrors(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.MaxErrors = v }
func (c *MaybeScannerConfig) GetAlarmThreshold() float64 { c.mu.RLock(); defer c.mu.RUnlock(); return c.AlarmThreshold }
func (c *MaybeScannerConfig) SetAlarmThreshold(v float64) { c.mu.Lock(); defer c.mu.Unlock(); c.AlarmThreshold = v }
func (c *MaybeScannerConfig) GetResetOnSuccess() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.ResetOnSuccess }
func (c *MaybeScannerConfig) SetResetOnSuccess(v bool) { c.mu.Lock(); defer c.mu.Unlock(); c.ResetOnSuccess = v }

// 10. CloudflareR2Config storage keys.
type CloudflareR2Config struct {
	mu              sync.RWMutex
	BucketName      string
	EndpointUrl     string
	AccessKeyId     string
	SecretAccessKey string
	Region          string
	UseSSL          bool
	PartSizeMB      int
	MaxRetries      int
	CacheControl    string
	PublicUrl       string
}

// Getters & Setters for CloudflareR2Config
func (c *CloudflareR2Config) GetBucketName() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.BucketName }
func (c *CloudflareR2Config) SetBucketName(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.BucketName = v }
func (c *CloudflareR2Config) GetEndpointUrl() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.EndpointUrl }
func (c *CloudflareR2Config) SetEndpointUrl(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.EndpointUrl = v }
func (c *CloudflareR2Config) GetAccessKeyId() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.AccessKeyId }
func (c *CloudflareR2Config) SetAccessKeyId(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.AccessKeyId = v }
func (c *CloudflareR2Config) GetSecretAccessKey() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.SecretAccessKey }
func (c *CloudflareR2Config) SetSecretAccessKey(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.SecretAccessKey = v }
func (c *CloudflareR2Config) GetRegion() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.Region }
func (c *CloudflareR2Config) SetRegion(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.Region = v }
func (c *CloudflareR2Config) GetUseSSL() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.UseSSL }
func (c *CloudflareR2Config) SetUseSSL(v bool) { c.mu.Lock(); defer c.mu.Unlock(); c.UseSSL = v }
func (c *CloudflareR2Config) GetPartSizeMB() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.PartSizeMB }
func (c *CloudflareR2Config) SetPartSizeMB(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.PartSizeMB = v }
func (c *CloudflareR2Config) GetMaxRetries() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.MaxRetries }
func (c *CloudflareR2Config) SetMaxRetries(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.MaxRetries = v }
func (c *CloudflareR2Config) GetCacheControl() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.CacheControl }
func (c *CloudflareR2Config) SetCacheControl(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.CacheControl = v }
func (c *CloudflareR2Config) GetPublicUrl() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.PublicUrl }
func (c *CloudflareR2Config) SetPublicUrl(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.PublicUrl = v }

// 11. CloudflareVlessTrojanConfig details.
type CloudflareVlessTrojanConfig struct {
	mu             sync.RWMutex
	TrojanPassword string
	VlessUuid      string
	WebSocketPath  string
	TlsServerName  string
	MuxEnabled     bool
	MuxConcurrency int
	FallbackAddress string
	RemoteDns      string
	LogLevel       string
	UDPEnabled     bool
}

// Getters & Setters for CloudflareVlessTrojanConfig
func (c *CloudflareVlessTrojanConfig) GetTrojanPassword() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.TrojanPassword }
func (c *CloudflareVlessTrojanConfig) SetTrojanPassword(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.TrojanPassword = v }
func (c *CloudflareVlessTrojanConfig) GetVlessUuid() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.VlessUuid }
func (c *CloudflareVlessTrojanConfig) SetVlessUuid(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.VlessUuid = v }
func (c *CloudflareVlessTrojanConfig) GetWebSocketPath() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.WebSocketPath }
func (c *CloudflareVlessTrojanConfig) SetWebSocketPath(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.WebSocketPath = v }
func (c *CloudflareVlessTrojanConfig) GetTlsServerName() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.TlsServerName }
func (c *CloudflareVlessTrojanConfig) SetTlsServerName(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.TlsServerName = v }
func (c *CloudflareVlessTrojanConfig) GetMuxEnabled() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.MuxEnabled }
func (c *CloudflareVlessTrojanConfig) SetMuxEnabled(v bool) { c.mu.Lock(); defer c.mu.Unlock(); c.MuxEnabled = v }
func (c *CloudflareVlessTrojanConfig) GetMuxConcurrency() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.MuxConcurrency }
func (c *CloudflareVlessTrojanConfig) SetMuxConcurrency(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.MuxConcurrency = v }
func (c *CloudflareVlessTrojanConfig) GetFallbackAddress() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.FallbackAddress }
func (c *CloudflareVlessTrojanConfig) SetFallbackAddress(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.FallbackAddress = v }
func (c *CloudflareVlessTrojanConfig) GetRemoteDns() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.RemoteDns }
func (c *CloudflareVlessTrojanConfig) SetRemoteDns(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.RemoteDns = v }
func (c *CloudflareVlessTrojanConfig) GetLogLevel() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.LogLevel }
func (c *CloudflareVlessTrojanConfig) SetLogLevel(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.LogLevel = v }
func (c *CloudflareVlessTrojanConfig) GetUDPEnabled() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.UDPEnabled }
func (c *CloudflareVlessTrojanConfig) SetUDPEnabled(v bool) { c.mu.Lock(); defer c.mu.Unlock(); c.UDPEnabled = v }

// 12. CloudflareBypassConfig options.
type CloudflareBypassConfig struct {
	mu                  sync.RWMutex
	ClearanceCookie     string
	CfBypassToken       string
	UserAgentString     string
	SolveChallenge      bool
	SolverServiceUrl    string
	UseProxyForChallenge bool
	MaxAttempts         int
	BackoffMs           int
	SuccessSelector     string
	DebugMode           bool
}

// Getters & Setters for CloudflareBypassConfig
func (c *CloudflareBypassConfig) GetClearanceCookie() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.ClearanceCookie }
func (c *CloudflareBypassConfig) SetClearanceCookie(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.ClearanceCookie = v }
func (c *CloudflareBypassConfig) GetCfBypassToken() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.CfBypassToken }
func (c *CloudflareBypassConfig) SetCfBypassToken(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.CfBypassToken = v }
func (c *CloudflareBypassConfig) GetUserAgentString() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.UserAgentString }
func (c *CloudflareBypassConfig) SetUserAgentString(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.UserAgentString = v }
func (c *CloudflareBypassConfig) GetSolveChallenge() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.SolveChallenge }
func (c *CloudflareBypassConfig) SetSolveChallenge(v bool) { c.mu.Lock(); defer c.mu.Unlock(); c.SolveChallenge = v }
func (c *CloudflareBypassConfig) GetSolverServiceUrl() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.SolverServiceUrl }
func (c *CloudflareBypassConfig) SetSolverServiceUrl(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.SolverServiceUrl = v }
func (c *CloudflareBypassConfig) GetUseProxyForChallenge() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.UseProxyForChallenge }
func (c *CloudflareBypassConfig) SetUseProxyForChallenge(v bool) { c.mu.Lock(); defer c.mu.Unlock(); c.UseProxyForChallenge = v }
func (c *CloudflareBypassConfig) GetMaxAttempts() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.MaxAttempts }
func (c *CloudflareBypassConfig) SetMaxAttempts(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.MaxAttempts = v }
func (c *CloudflareBypassConfig) GetBackoffMs() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.BackoffMs }
func (c *CloudflareBypassConfig) SetBackoffMs(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.BackoffMs = v }
func (c *CloudflareBypassConfig) GetSuccessSelector() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.SuccessSelector }
func (c *CloudflareBypassConfig) SetSuccessSelector(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.SuccessSelector = v }
func (c *CloudflareBypassConfig) GetDebugMode() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.DebugMode }
func (c *CloudflareBypassConfig) SetDebugMode(v bool) { c.mu.Lock(); defer c.mu.Unlock(); c.DebugMode = v }
