package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/workflows/jobs"
)

// CreateTlsScan handles POST /api/tls-scans.
func (s *Server) CreateTlsScan(c *gin.Context) {
	var req CreateTlsScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Mode == "cdn_sweep" {
		if len(req.Targets) == 0 && req.Target != "" {
			req.Targets = []string{req.Target}
		}
		if len(req.Targets) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "targets are required for cdn_sweep"})
			return
		}
		jobID, err := s.createAndStartJob(jobs.CdnScanIntent{Targets: req.Targets, CDNHost: req.Sni, SampleRate: req.SampleRate, TimeoutMs: req.TimeoutMs, Concurrency: req.Concurrency})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusAccepted, gin.H{"id": jobID, "status": "running"})
		return
	}
	if req.Target == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target is required"})
		return
	}
	jobID, err := s.createAndStartJob(jobs.TlsScanIntent{Target: req.Target, Port: req.Port, TimeoutMs: req.TimeoutMs, SNI: req.Sni})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"id": jobID, "status": "running"})
}

// GetTlsScan handles GET /api/tls-scans/:id.
func (s *Server) GetTlsScan(c *gin.Context) {
	id := c.Param("id")
	job, err := s.jobManager.GetJob(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"id": job.ID, "status": string(job.Status),
		"progress": job.Progress, "results": job.Results, "error": job.Error,
	})
}
