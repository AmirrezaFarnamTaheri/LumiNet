package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	presetcatalog "github.com/maybeknott/luminet/internal/integrations/presets"
	"github.com/maybeknott/luminet/internal/integrations/sub"
)

// setupPresetRoutes registers presets endpoints.
func (s *Server) setupPresetRoutes(rg *gin.RouterGroup) {
	presets := rg.Group("/presets")
	presets.GET("", s.GetPresets)
	presets.GET("/cdn", s.GetCDNPresets)
	presets.GET("/doh", s.GetDoHPresets)
	presets.GET("/dns", s.GetDNSPresets)
	presets.GET("/scanner", s.GetScannerPresets)
	presets.GET("/isp", s.GetISPPresets)
	presets.GET("/serverless", s.GetServerlessPresets)
	presets.GET("/cottendns", s.GetCottenDnsPresets)
	presets.GET("/candyconnect", s.GetCandyConnectPresets)
	presets.GET("/dohot", s.GetDoHoTPresets)
	presets.GET("/frp", s.GetFRPPresets)
}

// GetPresets returns all presets in a single payload.
func (s *Server) GetPresets(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"cdn":          presetcatalog.GetCDNPresets(),
		"doh":          presetcatalog.GetDoHPresets(),
		"dns":          presetcatalog.GetDNSPresets(),
		"scanner":      presetcatalog.GetScanPresets(),
		"isp":          presetcatalog.GetEvasionISPPresets(),
		"serverless":   presetcatalog.GetServerlessRoutingPresets(),
		"cottendns":    sub.GetCottenDnsPresets(),
		"candyconnect": sub.CandyConnectPresets(),
		"dohot":        sub.DoHoTPresets(),
		"frp":          sub.FRPPresets(),
	})
}

// GetCDNPresets returns only CDN presets.
func (s *Server) GetCDNPresets(c *gin.Context) {
	c.JSON(http.StatusOK, presetcatalog.GetCDNPresets())
}

// GetDoHPresets returns only DoH presets.
func (s *Server) GetDoHPresets(c *gin.Context) {
	c.JSON(http.StatusOK, presetcatalog.GetDoHPresets())
}

// GetDNSPresets returns only standard/gaming DNS presets.
func (s *Server) GetDNSPresets(c *gin.Context) {
	c.JSON(http.StatusOK, presetcatalog.GetDNSPresets())
}

// GetScannerPresets returns only scanner presets.
func (s *Server) GetScannerPresets(c *gin.Context) {
	c.JSON(http.StatusOK, presetcatalog.GetScanPresets())
}

// GetISPPresets returns only ISP evasion presets.
func (s *Server) GetISPPresets(c *gin.Context) {
	c.JSON(http.StatusOK, presetcatalog.GetEvasionISPPresets())
}

// GetServerlessPresets returns only Serverless routing presets.
func (s *Server) GetServerlessPresets(c *gin.Context) {
	c.JSON(http.StatusOK, presetcatalog.GetServerlessRoutingPresets())
}

// GetCottenDnsPresets returns only CottenDns presets.
func (s *Server) GetCottenDnsPresets(c *gin.Context) {
	c.JSON(http.StatusOK, sub.GetCottenDnsPresets())
}

// GetCandyConnectPresets returns CandyConnect multi-protocol presets.
func (s *Server) GetCandyConnectPresets(c *gin.Context) {
	c.JSON(http.StatusOK, sub.CandyConnectPresets())
}

// GetDoHoTPresets returns DNS-over-HTTPS-over-Tor presets.
func (s *Server) GetDoHoTPresets(c *gin.Context) {
	c.JSON(http.StatusOK, sub.DoHoTPresets())
}

// GetFRPPresets returns Fast Reverse Proxy configuration presets.
func (s *Server) GetFRPPresets(c *gin.Context) {
	c.JSON(http.StatusOK, sub.FRPPresets())
}
