package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/platform/process"
	"github.com/maybeknott/luminet/internal/platform/system"
)

// writePlatformFeatureError preserves capability truth for platform-specific
// controls while retaining ordinary 500 responses for real runtime failures.
func writePlatformFeatureError(c *gin.Context, err error) {
	if errors.Is(err, system.ErrUnsupportedPlatformFeature) || errors.Is(err, process.ErrUnsupportedPlatformFeature) {
		c.JSON(http.StatusNotImplemented, gin.H{
			"supported": false,
			"error":     err.Error(),
		})
		return
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
}
