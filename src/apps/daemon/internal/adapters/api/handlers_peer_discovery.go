package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/analysis/peerdiscovery"
	"github.com/maybeknott/luminet/internal/runtime/trust"
)

// PlanPeerDiscovery validates an operator-supplied candidate set and returns a
// bounded BEP42/Kademlia-style ordering. It is deliberately read-only: the
// endpoint does not discover, dial, persist, rate, or route through peers.
func (s *Server) PlanPeerDiscovery(c *gin.Context) {
	var req peerdiscovery.PlanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	plan, err := peerdiscovery.BuildPlan(req, trust.GetStore().SnapshotScores())
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}
