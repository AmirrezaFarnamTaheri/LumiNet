package api

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/foundation/config"
	"github.com/maybeknott/luminet/internal/networking/dns"
)

// GetDdnsStatus handles GET /api/system/ddns — returns DDNS status.
func (s *Server) GetDdnsStatus(c *gin.Context) {
	cfg, revision := s.configManager.GetWithRevision()
	exposeConfigRevision(c, revision)
	c.JSON(http.StatusOK, gin.H{
		"enabled":  cfg.DDNS.Enabled,
		"provider": cfg.DDNS.Provider,
		"domain":   cfg.DDNS.Domain,
		"interval": cfg.DDNS.Interval,
		"revision": revision,
	})
}

// SetDdnsConfig handles POST /api/system/ddns — updates DDNS configuration.
func (s *Server) SetDdnsConfig(c *gin.Context) {
	var req struct {
		Enabled  bool   `json:"enabled"`
		Provider string `json:"provider"`
		Token    string `json:"token"`
		Domain   string `json:"domain"`
		Interval int    `json:"interval"`
		Revision uint64 `json:"revision"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, committed := commitConfigMutation(c, s.configManager, req.Revision, func(cfg *config.Config) error {
		cfg.DDNS.Enabled = req.Enabled
		cfg.DDNS.Provider = req.Provider
		if req.Token != "" {
			cfg.DDNS.Token = req.Token
		}
		cfg.DDNS.Domain = req.Domain
		cfg.DDNS.Interval = req.Interval
		return nil
	})
	if !committed {
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "saved", "revision": result.Revision})
}

// ForceDdns handles POST /api/system/ddns/force — triggers immediate DDNS update.
func (s *Server) ForceDdns(c *gin.Context) {
	cfg := s.configManager.Get()
	if !cfg.DDNS.Enabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "DDNS is not enabled"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	result, err := RunDDNSUpdate(ctx, cfg.DDNS.Provider, cfg.DDNS.Token, cfg.DDNS.Domain)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

// RunDDNSUpdate performs a DDNS update with the given configuration.
// This is exported for use by the serve command's scheduler.
func RunDDNSUpdate(ctx context.Context, provider, token, domain string) (*dns.UpdateResult, error) {
	updater := dns.NewUpdater(provider, token, domain)
	ip, err := updater.GetPublicIP(ctx)
	if err != nil {
		return nil, err
	}
	return updater.UpdateIP(ctx, ip)
}
