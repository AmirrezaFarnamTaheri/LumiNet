package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/foundation/config"
	"github.com/maybeknott/luminet/internal/platform/process"
	"github.com/maybeknott/luminet/internal/runtime/proxy"
)

// GetStartupStatus handles GET /api/system/startup — returns startup status.
func (s *Server) GetStartupStatus(c *gin.Context) {
	enabled := process.IsStartupEnabled()
	c.JSON(http.StatusOK, StartupStatusResponse{Supported: process.StartupSupported(), Enabled: enabled})
}

// SetStartup handles POST /api/system/startup — enables or disables auto-start.
func (s *Server) SetStartup(c *gin.Context) {
	var req SetStartupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var err error
	if req.Enabled {
		err = process.EnableStartup()
	} else {
		err = process.DisableStartup()
	}

	if err != nil {
		writePlatformFeatureError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"enabled": req.Enabled,
	})
}

// SystemSettings represents the settings payload for the frontend configuration.
type SystemSettings struct {
	DefaultTimeoutMs int                       `json:"default_timeout_ms"`
	MaxConcurrency   int                       `json:"max_concurrency"`
	DebugLogs        bool                      `json:"debug_logs"`
	DNSResolution    bool                      `json:"dns_resolution"`
	MihomoRules      config.MihomoRulesOptions `json:"mihomo_rules"`
	HostsOverride    bool                      `json:"hosts_override"`
	Revision         uint64                    `json:"revision"`
}

// GetSystemSettings handles GET /api/system/settings — returns scanner & UI config values.
func (s *Server) GetSystemSettings(c *gin.Context) {
	cfg, revision := s.configManager.GetWithRevision()
	exposeConfigRevision(c, revision)
	c.JSON(http.StatusOK, SystemSettings{
		DefaultTimeoutMs: cfg.DefaultTimeoutMs,
		MaxConcurrency:   cfg.MaxConcurrency,
		DebugLogs:        cfg.DebugLogs,
		DNSResolution:    cfg.DNSResolution,
		MihomoRules:      cfg.MihomoRules,
		HostsOverride:    cfg.HostsOverride,
		Revision:         revision,
	})
}

// SetSystemSettings handles POST /api/system/settings — saves scanner & UI config values.
func (s *Server) SetSystemSettings(c *gin.Context) {
	var req SystemSettings
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, committed := commitConfigMutation(c, s.configManager, req.Revision, func(cfg *config.Config) error {
		cfg.DefaultTimeoutMs = req.DefaultTimeoutMs
		cfg.MaxConcurrency = req.MaxConcurrency
		cfg.DebugLogs = req.DebugLogs
		cfg.DNSResolution = req.DNSResolution
		cfg.MihomoRules = req.MihomoRules
		cfg.HostsOverride = req.HostsOverride
		return nil
	})
	if !committed {
		return
	}

	// Runtime side effects follow the durable configuration commit. A failed or
	// stale write must never partially change live proxy behavior.
	proxy.GetEvasionManager().SetHostsOverride(req.HostsOverride)

	c.JSON(http.StatusOK, gin.H{"status": "ok", "revision": result.Revision})
}
