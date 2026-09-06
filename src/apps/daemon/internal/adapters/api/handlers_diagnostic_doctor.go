package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/analysis/diagnostics"
	"github.com/maybeknott/luminet/internal/runtime/trust"
)

// HandleCensorshipDiagnose handles GET /api/system/doctor/diagnose
func (s *Server) HandleCensorshipDiagnose(c *gin.Context) {
	target := c.Query("target")
	diagnosis, err := diagnostics.DiagnoseCensorship(c.Request.Context(), target)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, diagnosis)
}

// HandleGetTrustScores handles GET /api/system/doctor/trust
func (s *Server) HandleGetTrustScores(c *gin.Context) {
	nodeID := c.Query("node_id")
	stack := trust.GetStore()

	if nodeID != "" {
		score := stack.ComputeTrustScore(nodeID)
		c.JSON(http.StatusOK, gin.H{
			"node_id":     nodeID,
			"trust_score": score,
		})
		return
	}

	c.JSON(http.StatusOK, stack.SnapshotScores())
}

// HandleSubmitNodeRating handles POST /api/system/doctor/rate
func (s *Server) HandleSubmitNodeRating(c *gin.Context) {
	var req struct {
		NodeID string  `json:"node_id" binding:"required"`
		Rating float64 `json:"rating" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Rating < 0.0 || req.Rating > 5.0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "rating must be between 0.0 and 5.0"})
		return
	}

	trust.GetStore().SubmitRating(req.NodeID, req.Rating)

	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"message": "rating submitted successfully",
	})
}

// HandleEstablishPathBonding handles POST /api/system/doctor/path-bonding
func (s *Server) HandleEstablishPathBonding(c *gin.Context) {
	var req struct {
		TargetHost string   `json:"target_host" binding:"required"`
		TargetPort int      `json:"target_port" binding:"required"`
		Relays     []string `json:"relays" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusNotImplemented, gin.H{
		"supported": false,
		"status":    "unavailable",
		"error":     "path bonding is unavailable: LumiNet has no stream-correct multipath transport owner",
	})
}
