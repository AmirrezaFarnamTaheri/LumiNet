package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/platform/system"
)

// PlanHostNetwork previews one authoritative host-network mutation without
// changing the host or granting apply authority.
func (s *Server) PlanHostNetwork(c *gin.Context) {
	var change system.HostNetworkChange
	if err := c.ShouldBindJSON(&change); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	plan, err := system.PlanHostNetwork(ctx, change)
	if err != nil {
		if errors.Is(err, system.ErrUnsupportedPlatformFeature) {
			writePlatformFeatureError(c, err)
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}
