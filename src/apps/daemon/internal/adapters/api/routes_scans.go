package api

import (
	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/foundation/capabilities"
)

// setupScanRoutes registers /api/scans endpoints.
func (s *Server) setupScanRoutes(rg *gin.RouterGroup) {
	scans := rg.Group("/scans")
	scans.POST("", s.CreateScan)
	scans.GET("/:id", s.GetScan)
	scans.GET("/:id/alive", s.GetScanAlive)
	scans.GET("/:id/results", s.GetScanResults)
	scans.POST("/:id/cancel", s.CancelScan)

	portScans := rg.Group("/port-scans")
	portScans.POST("", s.CreatePortScan)
	portScans.GET("/:id", s.GetPortScan)

	proxies := rg.Group("/proxies")
	proxies.GET("", s.ListProxyNodes)
	proxies.POST("", s.AddProxyNode)
	proxies.POST("/parse", s.ParseProxyContent)
	proxies.POST("/rewrite", s.RewriteProxyContent)
	proxies.DELETE("/:id", s.DeleteProxyNode)
}

// setupProxyScanRoutes registers /api/proxy-scans endpoints.
func (s *Server) setupProxyScanRoutes(rg *gin.RouterGroup) {
	ps := rg.Group("/proxy-scans")
	ps.POST("", s.CreateProxyScan)
	ps.GET("/:id", s.GetProxyScan)
	ps.GET("/:id/rows", s.GetProxyScanRows)
	ps.POST("/:id/cancel", s.CancelProxyScan)
}

// setupProxyTestRoutes registers /api/proxy-tests endpoints.
func (s *Server) setupProxyTestRoutes(rg *gin.RouterGroup) {
	pt := rg.Group("/proxy-tests")
	pt.POST("", s.CreateProxyTest)
	pt.GET("/:id", s.GetProxyTest)
	pt.GET("/:id/stream", s.StreamProxyTest)
}

// setupDnsScanRoutes registers /api/dns-scans endpoints.
func (s *Server) setupDnsScanRoutes(rg *gin.RouterGroup) {
	dns := rg.Group("/dns-scans")
	dns.POST("", s.CreateDnsScan)
	dns.GET("/:id", s.GetDnsScan)
}

// setupTlsScanRoutes registers /api/tls-scans endpoints.
func (s *Server) setupTlsScanRoutes(rg *gin.RouterGroup) {
	tls := rg.Group("/tls-scans")
	tls.POST("", s.CreateTlsScan)
	tls.GET("/:id", s.GetTlsScan)
}

// setupSniScanRoutes registers /api/sni-scans endpoints.
func (s *Server) setupSniScanRoutes(rg *gin.RouterGroup) {
	sni := rg.Group("/sni-scans")
	sni.POST("", s.CreateSniScan)
	sni.GET("/:id", s.GetSniScan)
}

// setupDiagnosticRoutes registers /api/diagnostics endpoints.
func (s *Server) setupDiagnosticRoutes(rg *gin.RouterGroup) {
	diag := rg.Group("/diagnostics")
	diag.Use(capabilities.GuardRoute(s.capabilities, capabilities.CapDiagnostics))
	diag.POST("", s.RunDiagnostic)
	diag.GET("/phases", s.GetDiagnosticPhases)
	diag.GET("/:id", s.GetDiagnostic)
	diag.GET("/:id/export", s.ExportDiagnostic)
	diag.GET("/geoip", s.HandleGeoIPLookup)
}
