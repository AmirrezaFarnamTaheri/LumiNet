package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

// GetAllScanResults handles GET /api/scan-results — returns flat list of historical scan results.
func (s *Server) GetAllScanResults(c *gin.Context) {
	limitStr := c.DefaultQuery("limit", "100")
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}

	ctx := c.Request.Context()
	// List recent job records (limit 10)
	jobs, err := s.store.ListJobRecords(ctx, 10, 0)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	results := []gin.H{}
	for _, job := range jobs {
		evidence, err := s.store.ListByJob(ctx, job.ID, limit, 0)
		if err != nil {
			continue
		}
		for _, e := range evidence {
			var metaStr string
			if len(e.Metadata) > 0 {
				if b, err := json.Marshal(e.Metadata); err == nil {
					metaStr = string(b)
				}
			}
			if metaStr == "" && e.Error != "" {
				metaStr = e.Error
			}

			results = append(results, gin.H{
				"target":     e.Target,
				"latency_ms": e.LatencyMs,
				"metadata":   metaStr,
				"success":    e.State == "alive",
				"job_id":     e.JobID,
			})
		}
		if len(results) >= limit {
			results = results[:limit]
			break
		}
	}

	c.JSON(http.StatusOK, gin.H{"results": results})
}
