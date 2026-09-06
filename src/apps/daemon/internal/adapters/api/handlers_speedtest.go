package api

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// setupSpeedtestRoutes registers the speedtest endpoints.
func (s *Server) setupSpeedtestRoutes(rg *gin.RouterGroup) {
	rg.POST("/system/speedtest", s.RunSpeedtest)
}

// RunSpeedtest runs bounded latency-quality probes and a download speedtest through the configured endpoint.
func (s *Server) RunSpeedtest(c *gin.Context) {
	var req SpeedtestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, SpeedtestResponse{
			Success: false,
			Error:   fmt.Sprintf("invalid speedtest request body: %v", err),
		})
		return
	}

	result, status := runSpeedtest(c.Request.Context(), req)
	c.JSON(status, result)
}
