package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/runtime/safety"
)

// GetSafetyPolicy handles GET /api/system/safety-policy — returns the current safety settings.
func (s *Server) GetSafetyPolicy(c *gin.Context) {
	gov := safety.GetGovernor()
	settings := safety.DefaultSettings()
	c.JSON(http.StatusOK, gin.H{
		"respect_safety":          settings.RespectSafety,
		"authorization_confirmed": settings.AuthorizationConfirmed,
		"rate_ceiling":            settings.RateCeiling,
		"audit_log_path":          gov.AuditLogPath,
	})
}

// SetSafetyPolicy handles POST /api/system/safety-policy — validates and applies safety settings.
func (s *Server) SetSafetyPolicy(c *gin.Context) {
	var req struct {
		Target                 string `json:"target"`
		RespectSafety          bool   `json:"respect_safety"`
		AuthorizationConfirmed bool   `json:"authorization_confirmed"`
		RateCeiling            int    `json:"rate_ceiling"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Target == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target is required"})
		return
	}

	settings := safety.Settings{
		RespectSafety:          req.RespectSafety,
		AuthorizationConfirmed: req.AuthorizationConfirmed,
		RateCeiling:            req.RateCeiling,
	}

	gov := safety.GetGovernor()
	if err := gov.ValidateScan(req.Target, settings); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":                      true,
		"target":                  req.Target,
		"respect_safety":          settings.RespectSafety,
		"authorization_confirmed": settings.AuthorizationConfirmed,
		"rate_ceiling":            settings.RateCeiling,
	})
}

// AuditSafetyPolicy handles GET /api/system/safety-policy/audit — audits the host environment.
func (s *Server) AuditSafetyPolicy(c *gin.Context) {
	gov := safety.GetGovernor()
	issues, err := gov.AuditProcessSecurity()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"clean":  len(issues) == 0,
		"issues": issues,
	})
}
