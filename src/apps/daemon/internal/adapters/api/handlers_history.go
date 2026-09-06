package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/workflows/jobs"
)

// GetHistory handles GET /api/history — returns the job history.
func (s *Server) GetHistory(c *gin.Context) {
	allJobs := s.jobManager.ListJobs(jobs.JobFilter{Limit: 100})
	c.JSON(http.StatusOK, gin.H{
		"jobs":  allJobs,
		"total": len(allJobs),
	})
}

// GetJob handles GET /api/jobs/:id — returns one job with config/results.
func (s *Server) GetJob(c *gin.Context) {
	job, err := s.jobManager.GetJob(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, job)
}

// CancelJob handles POST /api/jobs/:id/cancel — cancels a queued/running job.
func (s *Server) CancelJob(c *gin.Context) {
	if err := s.jobManager.CancelJob(c.Param("id")); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "cancelled"})
}

// ClearHistory handles DELETE /api/history — clears the job history.
func (s *Server) ClearHistory(c *gin.Context) {
	if err := s.jobManager.ClearHistory(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "cleared"})
}

// ExportHistory handles GET /api/export — exports all jobs to JSON.
func (s *Server) ExportHistory(c *gin.Context) {
	allJobs := s.jobManager.ListJobs(jobs.JobFilter{Limit: 1000})
	c.Header("Content-Disposition", "attachment; filename=luminet-history.json")
	c.JSON(http.StatusOK, gin.H{
		"exported_at": time.Now(),
		"jobs":        allJobs,
	})
}

// GetJobRecovery handles GET /api/jobs/:id/recovery. It is read-only and
// explains whether an interrupted job can be reconstructed from durable,
// credential-free state. It never schedules work.
func (s *Server) GetJobRecovery(c *gin.Context) {
	info, err := s.jobManager.GetRecoveryInfo(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, info)
}

// RequeueJob handles POST /api/jobs/:id/requeue. Recovery is deliberately
// operator-confirmed, produces a new immutable job record, and never mutates the
// interrupted source record. Duplicate active descendants are rejected by the
// job manager before a new job is created.
func (s *Server) RequeueJob(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1024)
	var req struct {
		Confirm bool `json:"confirm"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid recovery confirmation: " + err.Error()})
		return
	}
	if !req.Confirm {
		c.JSON(http.StatusBadRequest, gin.H{"error": "confirm=true is required to create a new recovery execution"})
		return
	}

	sourceID := c.Param("id")
	info, err := s.jobManager.GetRecoveryInfo(sourceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if !info.Reconstructible {
		c.JSON(http.StatusConflict, gin.H{"error": info.Reason, "recovery": info})
		return
	}

	newID, err := s.jobManager.RequeueInterrupted(sourceID)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error(), "recovery": info})
		return
	}
	if err := s.jobManager.StartJob(newID); err != nil {
		// The new descendant is retained as an auditable cancelled record rather
		// than silently disappearing after a failed scheduler admission.
		_ = s.jobManager.CancelJob(newID)
		c.JSON(http.StatusBadGateway, gin.H{
			"error":          "recovery job was created but could not start: " + err.Error(),
			"job_id":         newID,
			"recovered_from": sourceID,
		})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"job_id":         newID,
		"recovered_from": sourceID,
		"status":         string(jobs.JobStatusRunning),
		"policy":         info.Policy,
	})
}
