package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/platform/system"
)

// PreflightLocalPort handles POST /api/system/port-preflight.
func (s *Server) PreflightLocalPort(c *gin.Context) {
	var request struct {
		Host string `json:"host,omitempty"`
		Port int    `json:"port" binding:"required"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	result, err := system.CheckLocalTCPPort(request.Host, request.Port)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}
