package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

const fptnUnsupported = "embedded FPTN tunnel runtime is not available"

// setupFptnRoutes preserves the historical FPTN route shape while reporting
// capability truth. The former in-process implementation was a simulator with
// synthetic addresses, credentials, tokens, and packet echo behavior.
func (s *Server) setupFptnRoutes(rg *gin.RouterGroup) {
	fptnGroup := rg.Group("/fptn")
	fptnGroup.GET("/dns", fptnUnavailable)
	fptnGroup.POST("/login", fptnUnavailable)
	fptnGroup.GET("/test_file.bin", fptnUnavailable)
	fptnGroup.GET("/tunnel", fptnUnavailable)
}

func fptnUnavailable(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"supported": false,
		"running":   false,
		"error":     fptnUnsupported,
	})
}
