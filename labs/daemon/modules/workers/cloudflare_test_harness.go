// Package workers handles serverless and edge-worker deployments.
// Target path: server/internal/workers/cloudflare_test_harness.go

package workers

import (
	"sync"
)

// 1. WhiteDnsClientHarness verifies DNS client configs.
type WhiteDnsClientHarness struct {
	mu             sync.RWMutex
	TokenValid     bool
	AccountAccess  bool
	ZoneFound      bool
	RecordCreated  bool
	TtlApplied     bool
	ProxyActive    bool
	SslVerified    bool
	DurationOk     bool
	ErrorMessage   string
	TestDurationMs int
}

// Getters & Setters for WhiteDnsClientHarness
func (h *WhiteDnsClientHarness) GetTokenValid() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.TokenValid }
func (h *WhiteDnsClientHarness) SetTokenValid(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.TokenValid = v }
func (h *WhiteDnsClientHarness) GetAccountAccess() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.AccountAccess }
func (h *WhiteDnsClientHarness) SetAccountAccess(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.AccountAccess = v }
func (h *WhiteDnsClientHarness) GetZoneFound() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.ZoneFound }
func (h *WhiteDnsClientHarness) SetZoneFound(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.ZoneFound = v }
func (h *WhiteDnsClientHarness) GetRecordCreated() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.RecordCreated }
func (h *WhiteDnsClientHarness) SetRecordCreated(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.RecordCreated = v }
func (h *WhiteDnsClientHarness) GetTtlApplied() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.TtlApplied }
func (h *WhiteDnsClientHarness) SetTtlApplied(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.TtlApplied = v }
func (h *WhiteDnsClientHarness) GetProxyActive() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.ProxyActive }
func (h *WhiteDnsClientHarness) SetProxyActive(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.ProxyActive = v }
func (h *WhiteDnsClientHarness) GetSslVerified() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.SslVerified }
func (h *WhiteDnsClientHarness) SetSslVerified(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.SslVerified = v }
func (h *WhiteDnsClientHarness) GetDurationOk() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.DurationOk }
func (h *WhiteDnsClientHarness) SetDurationOk(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.DurationOk = v }
func (h *WhiteDnsClientHarness) GetErrorMessage() string { h.mu.RLock(); defer h.mu.RUnlock(); return h.ErrorMessage }
func (h *WhiteDnsClientHarness) SetErrorMessage(v string) { h.mu.Lock(); defer h.mu.Unlock(); h.ErrorMessage = v }
func (h *WhiteDnsClientHarness) GetTestDurationMs() int { h.mu.RLock(); defer h.mu.RUnlock(); return h.TestDurationMs }
func (h *WhiteDnsClientHarness) SetTestDurationMs(v int) { h.mu.Lock(); defer h.mu.Unlock(); h.TestDurationMs = v }

// 2. WhiteDnsAndroidHarness verifies Android config integrations.
type WhiteDnsAndroidHarness struct {
	mu            sync.RWMutex
	PathExists    bool
	Sha256Matches bool
	DownloadOk    bool
	VerifiedOk    bool
	SdkSupported  bool
	NetAllowed    bool
	PkgIdentified bool
	ServiceActive bool
	LogPrefixOk   bool
	LastError     string
}

// Getters & Setters for WhiteDnsAndroidHarness
func (h *WhiteDnsAndroidHarness) GetPathExists() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.PathExists }
func (h *WhiteDnsAndroidHarness) SetPathExists(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.PathExists = v }
func (h *WhiteDnsAndroidHarness) GetSha256Matches() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.Sha256Matches }
func (h *WhiteDnsAndroidHarness) SetSha256Matches(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.Sha256Matches = v }
func (h *WhiteDnsAndroidHarness) GetDownloadOk() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.DownloadOk }
func (h *WhiteDnsAndroidHarness) SetDownloadOk(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.DownloadOk = v }
func (h *WhiteDnsAndroidHarness) GetVerifiedOk() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.VerifiedOk }
func (h *WhiteDnsAndroidHarness) SetVerifiedOk(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.VerifiedOk = v }
func (h *WhiteDnsAndroidHarness) GetSdkSupported() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.SdkSupported }
func (h *WhiteDnsAndroidHarness) SetSdkSupported(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.SdkSupported = v }
func (h *WhiteDnsAndroidHarness) GetNetAllowed() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.NetAllowed }
func (h *WhiteDnsAndroidHarness) SetNetAllowed(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.NetAllowed = v }
func (h *WhiteDnsAndroidHarness) GetPkgIdentified() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.PkgIdentified }
func (h *WhiteDnsAndroidHarness) SetPkgIdentified(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.PkgIdentified = v }
func (h *WhiteDnsAndroidHarness) GetServiceActive() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.ServiceActive }
func (h *WhiteDnsAndroidHarness) SetServiceActive(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.ServiceActive = v }
func (h *WhiteDnsAndroidHarness) GetLogPrefixOk() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.LogPrefixOk }
func (h *WhiteDnsAndroidHarness) SetLogPrefixOk(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.LogPrefixOk = v }
func (h *WhiteDnsAndroidHarness) GetLastError() string { h.mu.RLock(); defer h.mu.RUnlock(); return h.LastError }
func (h *WhiteDnsAndroidHarness) SetLastError(v string) { h.mu.Lock(); defer h.mu.Unlock(); h.LastError = v }

// 3. WhiteDnsCleanIpHarness verifies benchmark limits.
type WhiteDnsCleanIpHarness struct {
	mu               sync.RWMutex
	NmapInstalled    bool
	AsnValid         bool
	RangeCorrect     bool
	ResolveSuccess   bool
	LatencyUnderMax  bool
	SpeedOverMin     bool
	LossUnderLimit   bool
	HostReachable    bool
	PathFound        bool
	ErrorMsg         string
}

// Getters & Setters for WhiteDnsCleanIpHarness
func (h *WhiteDnsCleanIpHarness) GetNmapInstalled() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.NmapInstalled }
func (h *WhiteDnsCleanIpHarness) SetNmapInstalled(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.NmapInstalled = v }
func (h *WhiteDnsCleanIpHarness) GetAsnValid() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.AsnValid }
func (h *WhiteDnsCleanIpHarness) SetAsnValid(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.AsnValid = v }
func (h *WhiteDnsCleanIpHarness) GetRangeCorrect() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.RangeCorrect }
func (h *WhiteDnsCleanIpHarness) SetRangeCorrect(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.RangeCorrect = v }
func (h *WhiteDnsCleanIpHarness) GetResolveSuccess() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.ResolveSuccess }
func (h *WhiteDnsCleanIpHarness) SetResolveSuccess(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.ResolveSuccess = v }
func (h *WhiteDnsCleanIpHarness) GetLatencyUnderMax() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.LatencyUnderMax }
func (h *WhiteDnsCleanIpHarness) SetLatencyUnderMax(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.LatencyUnderMax = v }
func (h *WhiteDnsCleanIpHarness) GetSpeedOverMin() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.SpeedOverMin }
func (h *WhiteDnsCleanIpHarness) SetSpeedOverMin(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.SpeedOverMin = v }
func (h *WhiteDnsCleanIpHarness) GetLossUnderLimit() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.LossUnderLimit }
func (h *WhiteDnsCleanIpHarness) SetLossUnderLimit(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.LossUnderLimit = v }
func (h *WhiteDnsCleanIpHarness) GetHostReachable() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.HostReachable }
func (h *WhiteDnsCleanIpHarness) SetHostReachable(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.HostReachable = v }
func (h *WhiteDnsCleanIpHarness) GetPathFound() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.PathFound }
func (h *WhiteDnsCleanIpHarness) SetPathFound(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.PathFound = v }
func (h *WhiteDnsCleanIpHarness) GetErrorMsg() string { h.mu.RLock(); defer h.mu.RUnlock(); return h.ErrorMsg }
func (h *WhiteDnsCleanIpHarness) SetErrorMsg(v string) { h.mu.Lock(); defer h.mu.Unlock(); h.ErrorMsg = v }

// 4. WhiteDnsMainHarness verifies parallel port scanning.
type WhiteDnsMainHarness struct {
	mu               sync.RWMutex
	PortsParsed      bool
	TimeoutValid     bool
	SynScanOk        bool
	ConnectScanOk    bool
	ResolversActive  bool
	DomainsConfigured bool
	BufferOk         bool
	UdpScanOk        bool
	RetriesExhausted bool
	JitterApplied    bool
}

// Getters & Setters for WhiteDnsMainHarness
func (h *WhiteDnsMainHarness) GetPortsParsed() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.PortsParsed }
func (h *WhiteDnsMainHarness) SetPortsParsed(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.PortsParsed = v }
func (h *WhiteDnsMainHarness) GetTimeoutValid() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.TimeoutValid }
func (h *WhiteDnsMainHarness) SetTimeoutValid(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.TimeoutValid = v }
func (h *WhiteDnsMainHarness) GetSynScanOk() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.SynScanOk }
func (h *WhiteDnsMainHarness) SetSynScanOk(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.SynScanOk = v }
func (h *WhiteDnsMainHarness) GetConnectScanOk() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.ConnectScanOk }
func (h *WhiteDnsMainHarness) SetConnectScanOk(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.ConnectScanOk = v }
func (h *WhiteDnsMainHarness) GetResolversActive() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.ResolversActive }
func (h *WhiteDnsMainHarness) SetResolversActive(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.ResolversActive = v }
func (h *WhiteDnsMainHarness) GetDomainsConfigured() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.DomainsConfigured }
func (h *WhiteDnsMainHarness) SetDomainsConfigured(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.DomainsConfigured = v }
func (h *WhiteDnsMainHarness) GetBufferOk() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.BufferOk }
func (h *WhiteDnsMainHarness) SetBufferOk(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.BufferOk = v }
func (h *WhiteDnsMainHarness) GetUdpScanOk() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.UdpScanOk }
func (h *WhiteDnsMainHarness) SetUdpScanOk(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.UdpScanOk = v }
func (h *WhiteDnsMainHarness) GetRetriesExhausted() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.RetriesExhausted }
func (h *WhiteDnsMainHarness) SetRetriesExhausted(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.RetriesExhausted = v }
func (h *WhiteDnsMainHarness) GetJitterApplied() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.JitterApplied }
func (h *WhiteDnsMainHarness) SetJitterApplied(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.JitterApplied = v }

// 5. WhiteDnsHelperHarness verifies rotating proxy logic.
type WhiteDnsHelperHarness struct {
	mu               sync.RWMutex
	ProtoSupported   bool
	IntervalValid    bool
	ThresholdMet     bool
	ChecksActive     bool
	RetryUnderLimit  bool
	ConnsUnderMax    bool
	InterfaceFound   bool
	AddressBound     bool
	PortAvailable    bool
	UserAuthenticated bool
}

// Getters & Setters for WhiteDnsHelperHarness
func (h *WhiteDnsHelperHarness) GetProtoSupported() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.ProtoSupported }
func (h *WhiteDnsHelperHarness) SetProtoSupported(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.ProtoSupported = v }
func (h *WhiteDnsHelperHarness) GetIntervalValid() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.IntervalValid }
func (h *WhiteDnsHelperHarness) SetIntervalValid(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.IntervalValid = v }
func (h *WhiteDnsHelperHarness) GetThresholdMet() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.ThresholdMet }
func (h *WhiteDnsHelperHarness) SetThresholdMet(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.ThresholdMet = v }
func (h *WhiteDnsHelperHarness) GetChecksActive() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.ChecksActive }
func (h *WhiteDnsHelperHarness) SetChecksActive(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.ChecksActive = v }
func (h *WhiteDnsHelperHarness) GetRetryUnderLimit() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.RetryUnderLimit }
func (h *WhiteDnsHelperHarness) SetRetryUnderLimit(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.RetryUnderLimit = v }
func (h *WhiteDnsHelperHarness) GetConnsUnderMax() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.ConnsUnderMax }
func (h *WhiteDnsHelperHarness) SetConnsUnderMax(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.ConnsUnderMax = v }
func (h *WhiteDnsHelperHarness) GetInterfaceFound() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.InterfaceFound }
func (h *WhiteDnsHelperHarness) SetInterfaceFound(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.InterfaceFound = v }
func (h *WhiteDnsHelperHarness) GetAddressBound() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.AddressBound }
func (h *WhiteDnsHelperHarness) SetAddressBound(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.AddressBound = v }
func (h *WhiteDnsHelperHarness) GetPortAvailable() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.PortAvailable }
func (h *WhiteDnsHelperHarness) SetPortAvailable(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.PortAvailable = v }
func (h *WhiteDnsHelperHarness) GetUserAuthenticated() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.UserAuthenticated }
func (h *WhiteDnsHelperHarness) SetUserAuthenticated(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.UserAuthenticated = v }

// 6. WhiteDnsScannerHarness verifies evasion rules.
type WhiteDnsScannerHarness struct {
	mu               sync.RWMutex
	FragmentSizeOk   bool
	DelayApplied     bool
	HostEvaded       bool
	KeepAliveOk      bool
	UserAgentSet     bool
	CiphersAllowed   bool
	SignatureMatched bool
	StrategyRun      bool
	SniGreased       bool
	CertVerified     bool
}

// Getters & Setters for WhiteDnsScannerHarness
func (h *WhiteDnsScannerHarness) GetFragmentSizeOk() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.FragmentSizeOk }
func (h *WhiteDnsScannerHarness) SetFragmentSizeOk(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.FragmentSizeOk = v }
func (h *WhiteDnsScannerHarness) GetDelayApplied() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.DelayApplied }
func (h *WhiteDnsScannerHarness) SetDelayApplied(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.DelayApplied = v }
func (h *WhiteDnsScannerHarness) GetHostEvaded() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.HostEvaded }
func (h *WhiteDnsScannerHarness) SetHostEvaded(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.HostEvaded = v }
func (h *WhiteDnsScannerHarness) GetKeepAliveOk() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.KeepAliveOk }
func (h *WhiteDnsScannerHarness) SetKeepAliveOk(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.KeepAliveOk = v }
func (h *WhiteDnsScannerHarness) GetUserAgentSet() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.UserAgentSet }
func (h *WhiteDnsScannerHarness) SetUserAgentSet(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.UserAgentSet = v }
func (h *WhiteDnsScannerHarness) GetCiphersAllowed() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.CiphersAllowed }
func (h *WhiteDnsScannerHarness) SetCiphersAllowed(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.CiphersAllowed = v }
func (h *WhiteDnsScannerHarness) GetSignatureMatched() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.SignatureMatched }
func (h *WhiteDnsScannerHarness) SetSignatureMatched(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.SignatureMatched = v }
func (h *WhiteDnsScannerHarness) GetStrategyRun() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.StrategyRun }
func (h *WhiteDnsScannerHarness) SetStrategyRun(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.StrategyRun = v }
func (h *WhiteDnsScannerHarness) GetSniGreased() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.SniGreased }
func (h *WhiteDnsScannerHarness) SetSniGreased(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.SniGreased = v }
func (h *WhiteDnsScannerHarness) GetCertVerified() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.CertVerified }
func (h *WhiteDnsScannerHarness) SetCertVerified(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.CertVerified = v }

// 7. WhiteDnsZoneHarness verifies zone replication.
type WhiteDnsZoneHarness struct {
	mu              sync.RWMutex
	SourceValid     bool
	TargetValid     bool
	MappingOk       bool
	IntervalPassed  bool
	DryRunOk        bool
	OverwriteOk     bool
	EmailSent       bool
	LogWritten      bool
	RetriesUnderMax bool
	HistorySaved    bool
}

// Getters & Setters for WhiteDnsZoneHarness
func (h *WhiteDnsZoneHarness) GetSourceValid() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.SourceValid }
func (h *WhiteDnsZoneHarness) SetSourceValid(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.SourceValid = v }
func (h *WhiteDnsZoneHarness) GetTargetValid() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.TargetValid }
func (h *WhiteDnsZoneHarness) SetTargetValid(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.TargetValid = v }
func (h *WhiteDnsZoneHarness) GetMappingOk() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.MappingOk }
func (h *WhiteDnsZoneHarness) SetMappingOk(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.MappingOk = v }
func (h *WhiteDnsZoneHarness) GetIntervalPassed() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.IntervalPassed }
func (h *WhiteDnsZoneHarness) SetIntervalPassed(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.IntervalPassed = v }
func (h *WhiteDnsZoneHarness) GetDryRunOk() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.DryRunOk }
func (h *WhiteDnsZoneHarness) SetDryRunOk(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.DryRunOk = v }
func (h *WhiteDnsZoneHarness) GetOverwriteOk() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.OverwriteOk }
func (h *WhiteDnsZoneHarness) SetOverwriteOk(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.OverwriteOk = v }
func (h *WhiteDnsZoneHarness) GetEmailSent() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.EmailSent }
func (h *WhiteDnsZoneHarness) SetEmailSent(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.EmailSent = v }
func (h *WhiteDnsZoneHarness) GetLogWritten() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.LogWritten }
func (h *WhiteDnsZoneHarness) SetLogWritten(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.LogWritten = v }
func (h *WhiteDnsZoneHarness) GetRetriesUnderMax() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.RetriesUnderMax }
func (h *WhiteDnsZoneHarness) SetRetriesUnderMax(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.RetriesUnderMax = v }
func (h *WhiteDnsZoneHarness) GetHistorySaved() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.HistorySaved }
func (h *WhiteDnsZoneHarness) SetHistorySaved(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.HistorySaved = v }

// 8. MaybeEdgeScannerHarness verifies generalized Feistel shuffle.
type MaybeEdgeScannerHarness struct {
	mu              sync.RWMutex
	RoundsValid     bool
	SeedCorrect     bool
	RangeValid      bool
	StatelessOk     bool
	CidrsConfigured bool
	IdMatches       bool
	HeartbeatSent   bool
	DirWritable     bool
	ThreadsActive   bool
	PriorityCorrect bool
}

// Getters & Setters for MaybeEdgeScannerHarness
func (h *MaybeEdgeScannerHarness) GetRoundsValid() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.RoundsValid }
func (h *MaybeEdgeScannerHarness) SetRoundsValid(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.RoundsValid = v }
func (h *MaybeEdgeScannerHarness) GetSeedCorrect() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.SeedCorrect }
func (h *MaybeEdgeScannerHarness) SetSeedCorrect(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.SeedCorrect = v }
func (h *MaybeEdgeScannerHarness) GetRangeValid() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.RangeValid }
func (h *MaybeEdgeScannerHarness) SetRangeValid(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.RangeValid = v }
func (h *MaybeEdgeScannerHarness) GetStatelessOk() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.StatelessOk }
func (h *MaybeEdgeScannerHarness) SetStatelessOk(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.StatelessOk = v }
func (h *MaybeEdgeScannerHarness) GetCidrsConfigured() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.CidrsConfigured }
func (h *MaybeEdgeScannerHarness) SetCidrsConfigured(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.CidrsConfigured = v }
func (h *MaybeEdgeScannerHarness) GetIdMatches() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.IdMatches }
func (h *MaybeEdgeScannerHarness) SetIdMatches(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.IdMatches = v }
func (h *MaybeEdgeScannerHarness) GetHeartbeatSent() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.HeartbeatSent }
func (h *MaybeEdgeScannerHarness) SetHeartbeatSent(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.HeartbeatSent = v }
func (h *MaybeEdgeScannerHarness) GetDirWritable() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.DirWritable }
func (h *MaybeEdgeScannerHarness) SetDirWritable(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.DirWritable = v }
func (h *MaybeEdgeScannerHarness) GetThreadsActive() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.ThreadsActive }
func (h *MaybeEdgeScannerHarness) SetThreadsActive(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.ThreadsActive = v }
func (h *MaybeEdgeScannerHarness) GetPriorityCorrect() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.PriorityCorrect }
func (h *MaybeEdgeScannerHarness) SetPriorityCorrect(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.PriorityCorrect = v }

// 9. MaybeScannerHarness verifies active probe results.
type MaybeScannerHarness struct {
	mu               sync.RWMutex
	IntervalMet      bool
	RetriesValid     bool
	TimeoutMet       bool
	ProtoMatches     bool
	ResponseVerified bool
	ContentMatches   bool
	PayloadSent      bool
	ErrorsUnderMax   bool
	AlarmTriggered   bool
	ResetDone        bool
}

// Getters & Setters for MaybeScannerHarness
func (h *MaybeScannerHarness) GetIntervalMet() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.IntervalMet }
func (h *MaybeScannerHarness) SetIntervalMet(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.IntervalMet = v }
func (h *MaybeScannerHarness) GetRetriesValid() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.RetriesValid }
func (h *MaybeScannerHarness) SetRetriesValid(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.RetriesValid = v }
func (h *MaybeScannerHarness) GetTimeoutMet() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.TimeoutMet }
func (h *MaybeScannerHarness) SetTimeoutMet(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.TimeoutMet = v }
func (h *MaybeScannerHarness) GetProtoMatches() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.ProtoMatches }
func (h *MaybeScannerHarness) SetProtoMatches(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.ProtoMatches = v }
func (h *MaybeScannerHarness) GetResponseVerified() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.ResponseVerified }
func (h *MaybeScannerHarness) SetResponseVerified(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.ResponseVerified = v }
func (h *MaybeScannerHarness) GetContentMatches() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.ContentMatches }
func (h *MaybeScannerHarness) SetContentMatches(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.ContentMatches = v }
func (h *MaybeScannerHarness) GetPayloadSent() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.PayloadSent }
func (h *MaybeScannerHarness) SetPayloadSent(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.PayloadSent = v }
func (h *MaybeScannerHarness) GetErrorsUnderMax() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.ErrorsUnderMax }
func (h *MaybeScannerHarness) SetErrorsUnderMax(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.ErrorsUnderMax = v }
func (h *MaybeScannerHarness) GetAlarmTriggered() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.AlarmTriggered }
func (h *MaybeScannerHarness) SetAlarmTriggered(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.AlarmTriggered = v }
func (h *MaybeScannerHarness) GetResetDone() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.ResetDone }
func (h *MaybeScannerHarness) SetResetDone(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.ResetDone = v }

// 10. CloudflareR2Harness verifies bucket object storage.
type CloudflareR2Harness struct {
	mu                sync.RWMutex
	BucketExists      bool
	EndpointValid     bool
	KeyIdCorrect      bool
	SecretCorrect     bool
	RegionValid       bool
	SslUsed           bool
	PartSizeOk        bool
	RetriesUnderLimit bool
	CacheControlOk    bool
	UrlPublic         bool
}

// Getters & Setters for CloudflareR2Harness
func (h *CloudflareR2Harness) GetBucketExists() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.BucketExists }
func (h *CloudflareR2Harness) SetBucketExists(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.BucketExists = v }
func (h *CloudflareR2Harness) GetEndpointValid() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.EndpointValid }
func (h *CloudflareR2Harness) SetEndpointValid(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.EndpointValid = v }
func (h *CloudflareR2Harness) GetKeyIdCorrect() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.KeyIdCorrect }
func (h *CloudflareR2Harness) SetKeyIdCorrect(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.KeyIdCorrect = v }
func (h *CloudflareR2Harness) GetSecretCorrect() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.SecretCorrect }
func (h *CloudflareR2Harness) SetSecretCorrect(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.SecretCorrect = v }
func (h *CloudflareR2Harness) GetRegionValid() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.RegionValid }
func (h *CloudflareR2Harness) SetRegionValid(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.RegionValid = v }
func (h *CloudflareR2Harness) GetSslUsed() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.SslUsed }
func (h *CloudflareR2Harness) SetSslUsed(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.SslUsed = v }
func (h *CloudflareR2Harness) GetPartSizeOk() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.PartSizeOk }
func (h *CloudflareR2Harness) SetPartSizeOk(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.PartSizeOk = v }
func (h *CloudflareR2Harness) GetRetriesUnderLimit() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.RetriesUnderLimit }
func (h *CloudflareR2Harness) SetRetriesUnderLimit(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.RetriesUnderLimit = v }
func (h *CloudflareR2Harness) GetCacheControlOk() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.CacheControlOk }
func (h *CloudflareR2Harness) SetCacheControlOk(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.CacheControlOk = v }
func (h *CloudflareR2Harness) GetUrlPublic() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.UrlPublic }
func (h *CloudflareR2Harness) SetUrlPublic(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.UrlPublic = v }

// 11. CloudflareVlessTrojanHarness verifies proxy endpoint.
type CloudflareVlessTrojanHarness struct {
	mu               sync.RWMutex
	PasswordMatched  bool
	UuidValid        bool
	PathConfigured   bool
	SniMatches       bool
	MuxActive        bool
	MuxConcurrencyOk bool
	FallbackOk       bool
	DnsResolved      bool
	LogLevelSet      bool
	UdpActive        bool
}

// Getters & Setters for CloudflareVlessTrojanHarness
func (h *CloudflareVlessTrojanHarness) GetPasswordMatched() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.PasswordMatched }
func (h *CloudflareVlessTrojanHarness) SetPasswordMatched(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.PasswordMatched = v }
func (h *CloudflareVlessTrojanHarness) GetUuidValid() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.UuidValid }
func (h *CloudflareVlessTrojanHarness) SetUuidValid(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.UuidValid = v }
func (h *CloudflareVlessTrojanHarness) GetPathConfigured() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.PathConfigured }
func (h *CloudflareVlessTrojanHarness) SetPathConfigured(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.PathConfigured = v }
func (h *CloudflareVlessTrojanHarness) GetSniMatches() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.SniMatches }
func (h *CloudflareVlessTrojanHarness) SetSniMatches(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.SniMatches = v }
func (h *CloudflareVlessTrojanHarness) GetMuxActive() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.MuxActive }
func (h *CloudflareVlessTrojanHarness) SetMuxActive(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.MuxActive = v }
func (h *CloudflareVlessTrojanHarness) GetMuxConcurrencyOk() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.MuxConcurrencyOk }
func (h *CloudflareVlessTrojanHarness) SetMuxConcurrencyOk(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.MuxConcurrencyOk = v }
func (h *CloudflareVlessTrojanHarness) GetFallbackOk() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.FallbackOk }
func (h *CloudflareVlessTrojanHarness) SetFallbackOk(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.FallbackOk = v }
func (h *CloudflareVlessTrojanHarness) GetDnsResolved() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.DnsResolved }
func (h *CloudflareVlessTrojanHarness) SetDnsResolved(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.DnsResolved = v }
func (h *CloudflareVlessTrojanHarness) GetLogLevelSet() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.LogLevelSet }
func (h *CloudflareVlessTrojanHarness) SetLogLevelSet(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.LogLevelSet = v }
func (h *CloudflareVlessTrojanHarness) GetUdpActive() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.UdpActive }
func (h *CloudflareVlessTrojanHarness) SetUdpActive(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.UdpActive = v }

// 12. CloudflareBypassHarness verifies challenge solving.
type CloudflareBypassHarness struct {
	mu                   sync.RWMutex
	CookieValid          bool
	TokenValid           bool
	UserAgentCorrect     bool
	ChallengeSolved      bool
	ServiceReachable     bool
	ProxyUsed            bool
	AttemptsUnderMax     bool
	BackoffApplied       bool
	SelectorFound        bool
	DebugOk              bool
}

// Getters & Setters for CloudflareBypassHarness
func (h *CloudflareBypassHarness) GetCookieValid() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.CookieValid }
func (h *CloudflareBypassHarness) SetCookieValid(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.CookieValid = v }
func (h *CloudflareBypassHarness) GetTokenValid() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.TokenValid }
func (h *CloudflareBypassHarness) SetTokenValid(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.TokenValid = v }
func (h *CloudflareBypassHarness) GetUserAgentCorrect() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.UserAgentCorrect }
func (h *CloudflareBypassHarness) SetUserAgentCorrect(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.UserAgentCorrect = v }
func (h *CloudflareBypassHarness) GetChallengeSolved() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.ChallengeSolved }
func (h *CloudflareBypassHarness) SetChallengeSolved(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.ChallengeSolved = v }
func (h *CloudflareBypassHarness) GetServiceReachable() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.ServiceReachable }
func (h *CloudflareBypassHarness) SetServiceReachable(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.ServiceReachable = v }
func (h *CloudflareBypassHarness) GetProxyUsed() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.ProxyUsed }
func (h *CloudflareBypassHarness) SetProxyUsed(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.ProxyUsed = v }
func (h *CloudflareBypassHarness) GetAttemptsUnderMax() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.AttemptsUnderMax }
func (h *CloudflareBypassHarness) SetAttemptsUnderMax(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.AttemptsUnderMax = v }
func (h *CloudflareBypassHarness) GetBackoffApplied() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.BackoffApplied }
func (h *CloudflareBypassHarness) SetBackoffApplied(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.BackoffApplied = v }
func (h *CloudflareBypassHarness) GetSelectorFound() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.SelectorFound }
func (h *CloudflareBypassHarness) SetSelectorFound(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.SelectorFound = v }
func (h *CloudflareBypassHarness) GetDebugOk() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.DebugOk }
func (h *CloudflareBypassHarness) SetDebugOk(v bool) { h.mu.Lock(); defer h.mu.Unlock(); h.DebugOk = v }
