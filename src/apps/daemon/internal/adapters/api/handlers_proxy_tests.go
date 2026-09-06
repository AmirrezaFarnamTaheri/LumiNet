package api

import (
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/maybeknott/luminet/internal/networking/proxyconfig"
	"github.com/maybeknott/luminet/internal/workflows/jobs"
)

// CreateProxyTest handles POST /api/proxy-tests — creates a single proxy test.
func (s *Server) CreateProxyTest(c *gin.Context) {
	var req CreateProxyTestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	target := ""
	if len(req.URLs) > 0 {
		target = req.URLs[0]
	}
	jobID, err := s.createAndStartJob(jobs.ProxyTestIntent{ProxyAddr: req.ProxyURI, ProxyPreview: proxyconfig.URITransportPreview(req.ProxyURI, 72), Target: target, Timeout: req.Timeout, DNSResolver: req.DnsResolver})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusAccepted, ProxyTestResponse{ID: jobID, Status: string(jobs.JobStatusRunning)})
}

// GetProxyTest handles GET /api/proxy-tests/:id — returns proxy test status.
func (s *Server) GetProxyTest(c *gin.Context) {
	id := c.Param("id")
	job, err := s.jobManager.GetJob(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	resp := ProxyTestResponse{
		ID:     job.ID,
		Status: string(job.Status),
		Error:  job.Error,
	}

	if job.Status == jobs.JobStatusCompleted && job.Results != "" {
		var row ProxyScanRowResponse
		if err := json.Unmarshal([]byte(job.Results), &row); err == nil {
			resp.Result = &row
		}
	}

	c.JSON(http.StatusOK, resp)
}

// StreamProxyTest handles GET /api/proxy-tests/:id/stream — WebSocket stream for live test results.
func (s *Server) StreamProxyTest(c *gin.Context) {
	id := c.Param("id")

	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			if origin == "" {
				return true
			}
			u, err := url.Parse(origin)
			if err != nil {
				return false
			}
			host := u.Hostname()
			if host == "localhost" || host == "127.0.0.1" || host == "::1" {
				return true
			}
			for _, allowed := range s.config.AllowedOrigins {
				if allowed == "*" || allowed == origin {
					return true
				}
				if au, err := url.Parse(allowed); err == nil && au.Hostname() == host {
					return true
				}
			}
			return false
		},
	}

	// Upgrade to WebSocket
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	// Push initial state immediately if job exists
	if job, err := s.jobManager.GetJob(id); err == nil {
		initialMsg, _ := json.Marshal(map[string]interface{}{
			"type":     "progress",
			"job_id":   job.ID,
			"status":   string(job.Status),
			"progress": job.Progress,
			"results":  job.Results,
			"error":    job.Error,
		})
		_ = conn.WriteMessage(1, initialMsg)

		if job.Status == jobs.JobStatusCompleted ||
			job.Status == jobs.JobStatusFailed ||
			job.Status == jobs.JobStatusCancelled {
			return
		}
	}

	// Reactive sub-millisecond event streaming via Broadcaster
	broadcaster := s.jobManager.Broadcaster()
	eventCh := broadcaster.Subscribe(id)
	defer broadcaster.Unsubscribe(id, eventCh)

	ctx := c.Request.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-eventCh:
			if !ok {
				return
			}
			msg, err := json.Marshal(map[string]interface{}{
				"type":      evt.Type,
				"job_id":    evt.JobID,
				"data":      evt.Data,
				"timestamp": evt.Timestamp,
			})
			if err != nil {
				continue
			}
			if err := conn.WriteMessage(1, msg); err != nil {
				return
			}

			// Check if job completed
			if evt.Type == "status_change" {
				if status, ok := evt.Data.(string); ok && (status == string(jobs.JobStatusCompleted) || status == string(jobs.JobStatusFailed) || status == string(jobs.JobStatusCancelled)) {
					return
				}
			}
		}
	}
}
