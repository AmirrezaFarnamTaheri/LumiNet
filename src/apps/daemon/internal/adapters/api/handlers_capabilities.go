package api

import (
	"runtime"
	"sort"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/analysis/provider"
	"github.com/maybeknott/luminet/internal/foundation/capabilities"
	"github.com/maybeknott/luminet/internal/foundation/flowregistry"
	"github.com/maybeknott/luminet/internal/native/bridge"
	"github.com/maybeknott/luminet/internal/platform/system"
)

// capabilityAvailability is the public state of a registered capability. It
// intentionally separates what is registered from what is usable on this host.
type capabilityAvailability struct {
	ID          capabilities.CapabilityID `json:"id"`
	Name        string                    `json:"name"`
	Description string                    `json:"description"`
	Maturity    capabilities.Maturity     `json:"maturity"`
	Platforms   []string                  `json:"platforms"`
	Workflow    capabilities.WorkflowID   `json:"workflow"`
	Status      string                    `json:"status"`
	Reason      string                    `json:"reason,omitempty"`
}

// GetCapabilities handles GET /api/capabilities. The response is derived from
// the injected registry and live native-core ABI negotiation; it never treats
// a source file, porting record, or placeholder as proof of availability.
func (s *Server) GetCapabilities(c *gin.Context) {
	items := make([]capabilityAvailability, 0)
	if s.capabilities != nil {
		for _, capability := range s.capabilities.All() {
			item := capabilityAvailability{
				ID:          capability.ID,
				Name:        capability.Name,
				Description: capability.Description,
				Maturity:    capability.Maturity,
				Platforms:   capability.Platforms,
				Workflow:    capability.Workflow,
				Status:      "unavailable",
			}
			if permitted, err := s.capabilities.IsPermitted(capability.ID); err == nil && permitted {
				item.Status = "available"
			} else if err != nil {
				item.Reason = err.Error()
			} else {
				item.Reason = "disabled by capability registry"
			}
			items = append(items, item)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })

	native := gin.H{"status": "unavailable"}
	if !bridge.NativeCoreLinked {
		native["reason"] = "native core is not linked in this build"
	} else if version, err := bridge.NegotiateVersion(); err == nil {
		native["status"] = "available"
		native["version"] = version
	} else {
		native["reason"] = "native core ABI negotiation failed"
	}

	flowCoverage := flowregistry.Default().Coverage()
	flowStats := flowregistry.Default().Stats()
	networkStatus := system.GetNetworkMonitor().Status(0)
	providerStatus, providerReady := provider.DefaultService.Status(time.Now().UTC())

	c.JSON(200, gin.H{
		"schema_version": 4,
		"runtime": gin.H{
			"os":          runtime.GOOS,
			"arch":        runtime.GOARCH,
			"native_core": native,
		},
		"capabilities": items,
		"coverage": gin.H{
			"flow_registry": gin.H{
				"coverage_complete": false,
				"coverage_model":    "participating-runtime-owners-only",
				"owners":            flowCoverage,
				"stats":             flowStats,
			},
			"network_state": gin.H{
				"running":     networkStatus.Running,
				"revision":    networkStatus.Current.Revision,
				"captured_at": networkStatus.Current.CapturedAt,
				"last_error":  networkStatus.LastError,
			},
			"provider_corpus": gin.H{
				"ready":  providerReady,
				"status": providerStatus,
			},
		},
		"safety_boundary": "Capability presence, owner coverage, network observation, and provider freshness are reported independently; missing evidence is never promoted to availability.",
	})
}
