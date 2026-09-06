package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/workflows/jobs"
)

// CreateDnsScan handles POST /api/dns-scans.
func (s *Server) CreateDnsScan(c *gin.Context) {
	var req CreateDnsScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	jobID, err := s.createAndStartJob(jobs.DnsScanIntent{Server: req.Server, Domain: req.Domain, RecordType: req.RecordType, TimeoutMs: req.TimeoutMs})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"id": jobID, "status": "running"})
}

// GetDnsScan handles GET /api/dns-scans/:id.
func (s *Server) GetDnsScan(c *gin.Context) {
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
