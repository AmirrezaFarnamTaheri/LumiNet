package api

import (
	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/foundation/capabilities"
)

// routeCatalog is the composition boundary for authenticated API routes. It
// keeps route inventory in one place while individual handlers stay owned by
// their feature modules.
type routeCatalog struct{ server *Server }

func (c routeCatalog) register(api *gin.RouterGroup) {
	s := c.server
	api.POST("/session/ws", s.issueWebsocketSession)
	s.setupScanRoutes(api)
	api.GET("/scan-results", s.GetAllScanResults)
	s.setupProxyScanRoutes(api)
	s.setupProxyTestRoutes(api)
	s.setupDnsScanRoutes(api)
	s.setupTlsScanRoutes(api)
	s.setupSniScanRoutes(api)
	s.setupDiagnosticRoutes(api)
	s.setupSniSpoofRoutes(api)
	api.GET("/doctor", gin.WrapH(s.newDoctorHandler()))
	api.GET("/metrics", s.getMetrics)
	s.setupSystemRoutes(api)
	s.setupHistoryRoutes(api)
	s.setupCapabilitiesRoute(api)
	s.setupServerConfigRoute(api)
	s.setupTelegramRoutes(api)
	s.setupSubscriptionRoutes(api)
	s.setupPresetRoutes(api)
	s.setupRoutingPluginRoutes(api)
	s.setupSpeedtestRoutes(api)
	s.setupProviderCorpusRoutes(api)
	s.setupVPNGateRoutes(api)
	s.setupCircumventionCatalogRoutes(api)
	s.setupFptnRoutes(api)
}

// diagnosticsGuard is kept here as route metadata rather than dispersed in
// handlers. It documents the capability boundary used by the catalog.
func diagnosticsGuard(s *Server) gin.HandlerFunc {
	return capabilities.GuardRoute(s.capabilities, capabilities.CapDiagnostics)
}
