package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/workflows/jobs"
)

// CreatePortScan handles POST /api/port-scans — creates and starts a new TCP port scan.
func (s *Server) CreatePortScan(c *gin.Context) {
	var req CreatePortScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	jobID, err := s.createAndStartJob(jobs.PortScanIntent{Target: req.Target, Ports: req.Ports, TimeoutMs: req.Timeout, Concurrency: req.Concurrency})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"id": jobID, "status": "running"})
}

// GetPortScan handles GET /api/port-scans/:id — returns current port scan status.
func (s *Server) GetPortScan(c *gin.Context) {
	id := c.Param("id")
	job, err := s.jobManager.GetJob(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":           job.ID,
		"status":       string(job.Status),
		"progress":     job.Progress,
		"results":      job.Results,
		"error":        job.Error,
		"created_at":   job.CreatedAt,
		"started_at":   job.StartedAt,
		"completed_at": job.CompletedAt,
	})
}
