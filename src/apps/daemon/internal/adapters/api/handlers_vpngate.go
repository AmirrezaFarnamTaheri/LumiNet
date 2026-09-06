package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/integrations/vpngate"
)

// setupVPNGateRoutes exposes the public VPN Gate catalog as a ranked read-only
// discovery surface. Connecting still goes through the runtime engine owner.
func (s *Server) setupVPNGateRoutes(rg *gin.RouterGroup) {
	g := rg.Group("/providers/vpngate")
	g.GET("/servers", s.ListVPNGateServers)
}

func (s *Server) ListVPNGateServers(c *gin.Context) {
	limit, _ := strconv.Atoi(c.Query("limit"))
	maxPing, _ := strconv.Atoi(c.Query("max_ping_ms"))
	minSpeed, _ := strconv.ParseInt(c.Query("min_speed_bps"), 10, 64)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 20*time.Second)
	defer cancel()
	servers, err := vpngate.Fetch(ctx, nil, vpngate.Filter{
		Country: strings.TrimSpace(c.Query("country")), Limit: limit,
		MaxPingMS: maxPing, MinSpeedBPS: minSpeed,
	})
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "VPNGATE_CATALOG_UNAVAILABLE", "message": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"servers":      servers,
		"count":        len(servers),
		"catalog_url":  vpngate.CatalogURL,
		"sstp_handoff": "Use sstp_server with /api/system/engines and the returned public vpn/vpn credentials.",
	})
}
