package capabilities

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func GuardRoute(reg *Registry, capID CapabilityID) gin.HandlerFunc {
	return func(c *gin.Context) {
		if reg == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error":  "Capability unavailable",
				"reason": "CAPABILITY_REGISTRY_UNINITIALIZED",
			})
			c.Abort()
			return
		}
		permitted, err := reg.IsPermitted(capID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Capability verification failed",
				"message": err.Error(),
			})
			c.Abort()
			return
		}
		if !permitted {
			reason := string("The capability " + capID + " is unavailable on current platform or mode")
			for _, capability := range reg.All() {
				if capability.ID == capID && capability.UnavailableReason != "" {
					reason = capability.UnavailableReason
					break
				}
			}
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "Capability restricted",
				"message": reason,
			})
			c.Abort()
			return
		}
		c.Next()
	}
}
