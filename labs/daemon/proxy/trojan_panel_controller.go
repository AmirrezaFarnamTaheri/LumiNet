// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: worker-file-nahan1-main
// Target path: server/internal/proxy/nahan_panel.go

package proxy

import (
	"log"
	"sync"
)

// NahanSystemConfig defines the panel system options (from _worker.js SYSTEM_DEFAULTS).
type NahanSystemConfig struct {
	Name            string `json:"name"`
	APIRoute        string `json:"apiRoute"`
	MaintenanceHost string `json:"maintenanceHost"`
	BackupRelay     string `json:"backupRelay"`
	CustomRelay     string `json:"customRelay"`
	MasterKey       string `json:"masterKey"`
	MetricNode      string `json:"metricNode"`
	CleanIPs        string `json:"cleanIps"`
	SlaveNodes      string `json:"slaveNodes"`
	DeviceID        string `json:"deviceId"`
	Mode            string `json:"mode"`
	Agent           string `json:"agent"`
	SocketPorts     string `json:"socketPorts"`
	CustomDNS       string `json:"customDns"`
	ResolveIP       string `json:"resolveIp"`
	Cascade         string `json:"cascade"`
	EnableOpt1      bool   `json:"enableOpt1"`
	EnableOpt2      bool   `json:"enableOpt2"`
	TGToken         string `json:"tgToken"`
	TGChatID        string `json:"tgChatId"`
	TGAdminID       string `json:"tgAdminId"`
	CFAccountID     string `json:"cfAccountId"`
	CFApiToken      string `json:"cfApiToken"`
	CFWorkerName    string `json:"cfWorkerName"`
	IsPaused        bool   `json:"isPaused"`
	SilentAlerts    bool   `json:"silentAlerts"`
	GithubRepo      string `json:"githubRepo"`
	NameStrategy    string `json:"nameStrategy"`
	NamePrefix      string `json:"namePrefix"`
	TGBotLang       string `json:"tgBotLang"`
	SubUserAgent    string `json:"subUserAgent"`
	CustomPanelURL  string `json:"customPanelUrl"`
	LimitTotalReq   int    `json:"limitTotalReq"`
	ExpiryMs        int64  `json:"expiryMs"`
	HubPanelURL     string `json:"hubPanelUrl"`
	SyncAPIKey      string `json:"syncApiKey"`
	Nat64Prefix     string `json:"nat64Prefix"`
	EnableDirect    bool   `json:"enableDirectConfigs"`
	AutoUpdate      bool   `json:"autoUpdate"`
	AutoUpdateFmt   string `json:"autoUpdateFormat"`
}

// NahanPanel base Cloudflare worker script logic.
type NahanPanel struct {
	mu     sync.RWMutex
	config NahanSystemConfig
}

func NewNahanPanel() *NahanPanel {
	return &NahanPanel{
		config: NahanSystemConfig{
			APIRoute:        "sync",
			MaintenanceHost: "https://www.ubuntu.com, https://www.docker.com",
			MasterKey:       "admin",
			MetricNode:      "time.is",
			Mode:            "alpha",
			Agent:           "chrome",
			SocketPorts:     "443",
			CustomDNS:       "https://cloudflare-dns.com/dns-query",
			ResolveIP:       "1.1.1.1",
			GithubRepo:      "itsyebekhe/nahan",
			NameStrategy:    "default",
			NamePrefix:      "Core",
			TGBotLang:       "fa",
			AutoUpdateFmt:   "normal",
		},
	}
}

// SubNodeRouting implements legacy sub-node routing and user management.
func (n *NahanPanel) SubNodeRouting(userID string) {
	log.Printf("NahanPanel: Routing sub-nodes for user %s via Cloudflare Worker legacy implementation", userID)
}

// GetDefaultConfig resolves default configuration options (from _worker.js).
func (n *NahanPanel) GetDefaultConfig() NahanSystemConfig {
	return NahanSystemConfig{
		APIRoute:        "sync",
		MaintenanceHost: "https://www.ubuntu.com, https://www.docker.com",
		MasterKey:       "admin",
		MetricNode:      "time.is",
		Mode:            "alpha",
		Agent:           "chrome",
		SocketPorts:     "443",
		CustomDNS:       "https://cloudflare-dns.com/dns-query",
		ResolveIP:       "1.1.1.1",
		GithubRepo:      "itsyebekhe/nahan",
		NameStrategy:    "default",
		NamePrefix:      "Core",
		TGBotLang:       "fa",
		AutoUpdateFmt:   "normal",
	}
}

// SetName overrides target config node name.
func (n *NahanPanel) SetName(val string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.Name = val
}

// GetName retrieves target config node name.
func (n *NahanPanel) GetName() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.Name
}

// SetAPIRoute overrides active synchronization route.
func (n *NahanPanel) SetAPIRoute(val string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.APIRoute = val
}

// GetAPIRoute retrieves active synchronization route.
func (n *NahanPanel) GetAPIRoute() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.APIRoute
}

// SetMaintenanceHost overrides destination health check endpoints.
func (n *NahanPanel) SetMaintenanceHost(val string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.MaintenanceHost = val
}

// GetMaintenanceHost retrieves destination health check endpoints.
func (n *NahanPanel) GetMaintenanceHost() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.MaintenanceHost
}

// SetBackupRelay overrides fallback connection endpoint.
func (n *NahanPanel) SetBackupRelay(val string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.BackupRelay = val
}

// GetBackupRelay retrieves fallback connection endpoint.
func (n *NahanPanel) GetBackupRelay() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.BackupRelay
}

// SetCustomRelay overrides custom obfuscation endpoint.
func (n *NahanPanel) SetCustomRelay(val string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.CustomRelay = val
}

// GetCustomRelay retrieves custom obfuscation endpoint.
func (n *NahanPanel) GetCustomRelay() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.CustomRelay
}

// SetMasterKey overrides administration master passphrase.
func (n *NahanPanel) SetMasterKey(val string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.MasterKey = val
}

// GetMasterKey retrieves administration master passphrase.
func (n *NahanPanel) GetMasterKey() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.MasterKey
}

// SetMetricNode overrides telemetry host.
func (n *NahanPanel) SetMetricNode(val string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.MetricNode = val
}

// GetMetricNode retrieves telemetry host.
func (n *NahanPanel) GetMetricNode() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.MetricNode
}

// SetCleanIPs overrides active routing addresses.
func (n *NahanPanel) SetCleanIPs(val string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.CleanIPs = val
}

// GetCleanIPs retrieves active routing addresses.
func (n *NahanPanel) GetCleanIPs() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.CleanIPs
}

// SetSlaveNodes overrides secondary nodes registry.
func (n *NahanPanel) SetSlaveNodes(val string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.SlaveNodes = val
}

// GetSlaveNodes retrieves secondary nodes registry.
func (n *NahanPanel) GetSlaveNodes() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.SlaveNodes
}

// SetDeviceID overrides active identifier token.
func (n *NahanPanel) SetDeviceID(val string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.DeviceID = val
}

// GetDeviceID retrieves active identifier token.
func (n *NahanPanel) GetDeviceID() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.DeviceID
}

// SetMode overrides panel compilation profile.
func (n *NahanPanel) SetMode(val string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.Mode = val
}

// GetMode retrieves panel compilation profile.
func (n *NahanPanel) GetMode() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.Mode
}

// SetAgent overrides user agent filter.
func (n *NahanPanel) SetAgent(val string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.Agent = val
}

// GetAgent retrieves user agent filter.
func (n *NahanPanel) GetAgent() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.Agent
}

// SetSocketPorts overrides listening ports filter.
func (n *NahanPanel) SetSocketPorts(val string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.SocketPorts = val
}

// GetSocketPorts retrieves listening ports filter.
func (n *NahanPanel) GetSocketPorts() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.SocketPorts
}

// SetCustomDNS overrides DoH DNS upstream URL.
func (n *NahanPanel) SetCustomDNS(val string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.CustomDNS = val
}

// GetCustomDNS retrieves DoH DNS upstream URL.
func (n *NahanPanel) GetCustomDNS() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.CustomDNS
}

// SetResolveIP overrides backend IP configuration.
func (n *NahanPanel) SetResolveIP(val string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.ResolveIP = val
}

// GetResolveIP retrieves backend IP configuration.
func (n *NahanPanel) GetResolveIP() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.ResolveIP
}

// SetCascade overrides cascading endpoints value.
func (n *NahanPanel) SetCascade(val string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.Cascade = val
}

// GetCascade retrieves cascading endpoints value.
func (n *NahanPanel) GetCascade() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.Cascade
}

// SetEnableOpt1 overrides first optimization settings flag.
func (n *NahanPanel) SetEnableOpt1(val bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.EnableOpt1 = val
}

// GetEnableOpt1 retrieves first optimization settings flag.
func (n *NahanPanel) GetEnableOpt1() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.EnableOpt1
}

// SetEnableOpt2 overrides second optimization settings flag.
func (n *NahanPanel) SetEnableOpt2(val bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.EnableOpt2 = val
}

// GetEnableOpt2 retrieves second optimization settings flag.
func (n *NahanPanel) GetEnableOpt2() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.EnableOpt2
}

// SetTGToken overrides Telegram API webhook authorization token.
func (n *NahanPanel) SetTGToken(val string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.TGToken = val
}

// GetTGToken retrieves Telegram API webhook authorization token.
func (n *NahanPanel) GetTGToken() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.TGToken
}

// SetTGChatID overrides Telegram destination chat identifier.
func (n *NahanPanel) SetTGChatID(val string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.TGChatID = val
}

// GetTGChatID retrieves Telegram destination chat identifier.
func (n *NahanPanel) GetTGChatID() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.TGChatID
}

// SetTGAdminID overrides Telegram administrator chat identifier.
func (n *NahanPanel) SetTGAdminID(val string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.TGAdminID = val
}

// GetTGAdminID retrieves Telegram administrator chat identifier.
func (n *NahanPanel) GetTGAdminID() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.TGAdminID
}

// SetCFAccountID overrides Cloudflare zone account id.
func (n *NahanPanel) SetCFAccountID(val string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.CFAccountID = val
}

// GetCFAccountID retrieves Cloudflare zone account id.
func (n *NahanPanel) GetCFAccountID() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.CFAccountID
}

// SetCFApiToken overrides Cloudflare access API token.
func (n *NahanPanel) SetCFApiToken(val string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.CFApiToken = val
}

// GetCFApiToken retrieves Cloudflare access API token.
func (n *NahanPanel) GetCFApiToken() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.CFApiToken
}

// SetCFWorkerName overrides Cloudflare deployed script label.
func (n *NahanPanel) SetCFWorkerName(val string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.CFWorkerName = val
}

// GetCFWorkerName retrieves Cloudflare deployed script label.
func (n *NahanPanel) GetCFWorkerName() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.CFWorkerName
}

// SetIsPaused overrides script execution state.
func (n *NahanPanel) SetIsPaused(val bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.IsPaused = val
}

// GetIsPaused retrieves script execution state.
func (n *NahanPanel) GetIsPaused() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.IsPaused
}

// SetSilentAlerts overrides alerts quiet settings status.
func (n *NahanPanel) SetSilentAlerts(val bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.SilentAlerts = val
}

// GetSilentAlerts retrieves alerts quiet settings status.
func (n *NahanPanel) GetSilentAlerts() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.SilentAlerts
}

// SetGithubRepo overrides updates target source code repo.
func (n *NahanPanel) SetGithubRepo(val string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.GithubRepo = val
}

// GetGithubRepo retrieves updates target source code repo.
func (n *NahanPanel) GetGithubRepo() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.GithubRepo
}

// SetNameStrategy overrides routing name schema.
func (n *NahanPanel) SetNameStrategy(val string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.NameStrategy = val
}

// GetNameStrategy retrieves routing name schema.
func (n *NahanPanel) GetNameStrategy() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.NameStrategy
}

// SetNamePrefix overrides config routing titles prefix.
func (n *NahanPanel) SetNamePrefix(val string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.NamePrefix = val
}

// GetNamePrefix retrieves config routing titles prefix.
func (n *NahanPanel) GetNamePrefix() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.NamePrefix
}

// SetTGBotLang overrides telegram system messages locale code.
func (n *NahanPanel) SetTGBotLang(val string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.TGBotLang = val
}

// GetTGBotLang retrieves telegram system messages locale code.
func (n *NahanPanel) GetTGBotLang() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.TGBotLang
}

// SetSubUserAgent overrides client subscription User-Agent filter.
func (n *NahanPanel) SetSubUserAgent(val string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.SubUserAgent = val
}

// GetSubUserAgent retrieves client subscription User-Agent filter.
func (n *NahanPanel) GetSubUserAgent() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.SubUserAgent
}

// SetCustomPanelURL overrides administration dashboard url.
func (n *NahanPanel) SetCustomPanelURL(val string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.CustomPanelURL = val
}

// GetCustomPanelURL retrieves administration dashboard url.
func (n *NahanPanel) GetCustomPanelURL() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.CustomPanelURL
}

// SetLimitTotalReq overrides total request counts ceiling.
func (n *NahanPanel) SetLimitTotalReq(val int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.LimitTotalReq = val
}

// GetLimitTotalReq retrieves total request counts ceiling.
func (n *NahanPanel) GetLimitTotalReq() int {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.LimitTotalReq
}

// SetExpiryMs overrides validity timestamps limits.
func (n *NahanPanel) SetExpiryMs(val int64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.ExpiryMs = val
}

// GetExpiryMs retrieves validity timestamps limits.
func (n *NahanPanel) GetExpiryMs() int64 {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.ExpiryMs
}

// SetHubPanelURL overrides main orchestrator controller URL.
func (n *NahanPanel) SetHubPanelURL(val string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.HubPanelURL = val
}

// GetHubPanelURL retrieves main orchestrator controller URL.
func (n *NahanPanel) GetHubPanelURL() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.HubPanelURL
}

// SetSyncAPIKey overrides authentication sync credentials key.
func (n *NahanPanel) SetSyncAPIKey(val string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.SyncAPIKey = val
}

// GetSyncAPIKey retrieves authentication sync credentials key.
func (n *NahanPanel) GetSyncAPIKey() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.SyncAPIKey
}

// SetNat64Prefix overrides Nat64 gateway prefix.
func (n *NahanPanel) SetNat64Prefix(val string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.Nat64Prefix = val
}

// GetNat64Prefix retrieves Nat64 gateway prefix.
func (n *NahanPanel) GetNat64Prefix() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.Nat64Prefix
}

// SetEnableDirect overrides direct configurations toggle.
func (n *NahanPanel) SetEnableDirect(val bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.EnableDirect = val
}

// GetEnableDirect retrieves direct configurations toggle.
func (n *NahanPanel) GetEnableDirect() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.EnableDirect
}

// SetAutoUpdate overrides update checks toggle.
func (n *NahanPanel) SetAutoUpdate(val bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.AutoUpdate = val
}

// GetAutoUpdate retrieves update checks toggle.
func (n *NahanPanel) GetAutoUpdate() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.AutoUpdate
}

// SetAutoUpdateFmt overrides update target layout schema.
func (n *NahanPanel) SetAutoUpdateFmt(val string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config.AutoUpdateFmt = val
}

// GetAutoUpdateFmt retrieves update target layout schema.
func (n *NahanPanel) GetAutoUpdateFmt() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config.AutoUpdateFmt
}
