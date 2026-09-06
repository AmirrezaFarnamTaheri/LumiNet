package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/contracts/buildinfo"
	"github.com/maybeknott/luminet/internal/foundation/capabilities"
)

func (s *Server) getMetrics(c *gin.Context) {
	c.Data(http.StatusNotImplemented, "text/plain; charset=utf-8", []byte(
		"metrics unavailable: no production metrics pipeline is initialized\n",
	))
}

// setupVersionRoute exposes the link-time build identity without authentication.
// It is safe to publish and lets local launchers verify which daemon they found.
func (s *Server) setupVersionRoute(r *gin.Engine) {
	r.GET("/api/version", func(c *gin.Context) {
		c.JSON(http.StatusOK, buildinfo.Current())
	})
}

// setupHistoryRoutes registers /api/history and /api/export endpoints.
func (s *Server) setupHistoryRoutes(rg *gin.RouterGroup) {
	rg.GET("/history", s.GetHistory)
	rg.DELETE("/history", s.ClearHistory)
	rg.GET("/export", s.ExportHistory)
	rg.GET("/jobs/:id", s.GetJob)
	rg.POST("/jobs/:id/cancel", s.CancelJob)
	rg.GET("/jobs/:id/recovery", s.GetJobRecovery)
	rg.POST("/jobs/:id/requeue", s.RequeueJob)
}

// setupCapabilitiesRoute registers /api/capabilities endpoint.
func (s *Server) setupCapabilitiesRoute(rg *gin.RouterGroup) {
	rg.GET("/capabilities", s.GetCapabilities)
}

// setupServerConfigRoute registers /api/server-config endpoint.
func (s *Server) setupServerConfigRoute(rg *gin.RouterGroup) {
	rg.GET("/server-config", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"host":    s.config.Host,
			"port":    s.config.Port,
			"version": buildinfo.Version,
		})
	})
}

// setupTelegramRoutes registers /api/telegram/* endpoints.
func (s *Server) setupTelegramRoutes(rg *gin.RouterGroup) {
	tg := rg.Group("/telegram")
	tg.GET("/mtproto", s.GetTelegramMTProtoProxies)
}

// setupSubscriptionRoutes registers /api/subscriptions endpoints.
func (s *Server) setupSubscriptionRoutes(rg *gin.RouterGroup) {
	subs := rg.Group("/subscriptions")
	subs.POST("/aggregate", s.AggregateSubscriptionsHandler)
	subs.POST("/shape", s.ShapeSubscriptionHandler)
	subs.POST("/convert", capabilities.GuardRoute(s.capabilities, capabilities.CapProfileConversion), s.ConvertSubscriptionHandler)
	subs.POST("/deeplink/inspect", s.InspectSubscriptionDeepLink)
	subs.GET("/profiles", s.ListSubscriptionProfiles)
	subs.POST("/profiles", s.CreateSubscriptionProfile)
	subs.GET("/profiles/:id", s.GetSubscriptionProfile)
	subs.PUT("/profiles/:id", s.UpdateSubscriptionProfile)
	subs.DELETE("/profiles/:id", s.DeleteSubscriptionProfile)
	subs.POST("/profiles/:id/refresh", s.RefreshSubscriptionProfile)
	subs.GET("/profiles/:id/nodes", s.ListSubscriptionNodes)
	subs.POST("/profiles/:id/nodes/visibility", s.SetSubscriptionNodeVisibility)
	subs.POST("/profiles/:id/nodes/:node_id/activate", s.ActivateSubscriptionNode)
	subs.GET("/runtime", s.GetSubscriptionRuntime)
	subs.POST("/runtime/stop", s.StopSubscriptionRuntime)
}
