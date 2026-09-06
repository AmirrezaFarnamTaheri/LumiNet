package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/protocols/tarpit"
)

// GetTarpitStatus handles GET /api/system/tarpit — returns tarpit server status.
func (s *Server) GetTarpitStatus(c *gin.Context) {
	server := tarpit.GetTarpitServer()
	c.JSON(http.StatusOK, gin.H{
		"running": server.IsRunning(),
		"address": server.ListenAddr(),
	})
}
