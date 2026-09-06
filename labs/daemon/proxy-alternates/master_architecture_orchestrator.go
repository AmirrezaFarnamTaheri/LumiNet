package proxy

import (
	"context"
	"sync"
	"time"
)

// MasterArchitectureConfig unifies settings across all ported subsystems.
type MasterArchitectureConfig struct {
	EnableCDNDiscovery bool          `json:"enable_cdn_discovery"`
	EnableAntiBot      bool          `json:"enable_anti_bot"`
	EnableGDriveRelay  bool          `json:"enable_gdrive_relay"`
	EnableSNISpoofing  bool          `json:"enable_sni_spoofing"`
	EnableDPIDesync    bool          `json:"enable_dpi_desync"`
	EnableDoHBlocklist bool          `json:"enable_doh_blocklist"`
	TelemetryInterval  time.Duration `json:"telemetry_interval"`
}

// MasterArchitectureOrchestrator acts as the central hub managing all holistic modules.
type MasterArchitectureOrchestrator struct {
	mu          sync.RWMutex
	config      MasterArchitectureConfig
	cdnEngine   *CDNDiscoveryEngine
	antiBot     *AntiBotDetector
	gdriveRelay *GDriveTunnelRelay
	sniSpoofer  *SNISpoofingInjector
	dpiEngine   *DPIDesyncEngine
	blocklist   *DoHBlocklistFilter
	activeState map[string]interface{}
}

// NewMasterArchitectureOrchestrator initializes the complete unified system architecture.
func NewMasterArchitectureOrchestrator(cfg MasterArchitectureConfig) *MasterArchitectureOrchestrator {
	return &MasterArchitectureOrchestrator{
		config:      cfg,
		cdnEngine:   NewCDNDiscoveryEngine(),
		antiBot:     NewAntiBotDetector(),
		gdriveRelay: NewGDriveTunnelRelay(GDriveTunnelConfig{Enabled: cfg.EnableGDriveRelay}),
		sniSpoofer:  NewSNISpoofingInjector(SNISpoofConfig{Enabled: cfg.EnableSNISpoofing}),
		dpiEngine:   NewDPIDesyncEngine(DPIDesyncConfig{Enabled: cfg.EnableDPIDesync}),
		blocklist:   NewDoHBlocklistFilter(),
		activeState: make(map[string]interface{}),
	}
}

// StartTelemetryLoop initiates periodic subsystem health and telemetry checks.
func (m *MasterArchitectureOrchestrator) StartTelemetryLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.mu.Lock()
			m.activeState["sni_stats"] = m.sniSpoofer.GetStats()
			m.activeState["gdrive_stats"] = m.gdriveRelay.GetStats()
			m.activeState["blocked_queries"] = m.blocklist.GetBlockedCount()
			m.activeState["timestamp"] = time.Now().Unix()
			m.mu.Unlock()
		}
	}
}

// GetSystemTelemetry returns the aggregated runtime state of all holistic architectural subsystems.
func (m *MasterArchitectureOrchestrator) GetSystemTelemetry() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	res := make(map[string]interface{})
	for k, v := range m.activeState {
		res[k] = v
	}
	return res
}
