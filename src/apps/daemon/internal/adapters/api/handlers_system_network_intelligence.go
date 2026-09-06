package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/analysis/netintel"
	canonicalprovider "github.com/maybeknott/luminet/internal/analysis/provider"
	"github.com/maybeknott/luminet/internal/foundation/flowregistry"
	"github.com/maybeknott/luminet/internal/platform/system"
)

const networkIntelligenceHistory = 16

// GetSystemNetworkIntelligence derives a read-only operational summary from
// already-authoritative observation planes. It performs no DNS, remote GeoIP,
// probing, route mutation, or runtime mutation.
func (s *Server) GetSystemNetworkIntelligence(c *gin.Context) {
	reg := flowregistry.Default()
	providerStatus, providerReady := canonicalprovider.DefaultService.Status(time.Now())
	summary := netintel.Build(
		time.Now(),
		reg.Snapshot(),
		reg.Coverage(),
		reg.Stats(),
		system.GetNetworkMonitor().Status(networkIntelligenceHistory),
		canonicalprovider.DefaultService.Lookup,
		providerStatus,
		providerReady,
	)
	c.JSON(http.StatusOK, summary)
}
