package api

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/analysis/diagnostics"
)

// SniSpoofScanRequest is the request body for the SNI spoof scanner.
type SniSpoofScanRequest struct {
	Target        string   `json:"target" binding:"required"` // host:port
	SNIs          []string `json:"snis"`                      // list of fake SNIs to test
	TimeoutSecs   int      `json:"timeout_secs"`
	Concurrency   int      `json:"concurrency"`
	StabilityRuns int      `json:"stability_runs,omitempty"`
}

// setupSniSpoofRoutes registers the SNI spoof scanner endpoint.
func (s *Server) setupSniSpoofRoutes(rg *gin.RouterGroup) {
	rg.POST("/sni-scans/spoof", s.RunSniSpoofScan)
	rg.GET("/sni-scans/spoof/defaults", s.GetSniSpoofDefaults)
}

// RunSniSpoofScan executes the concurrent SNI spoof scan.
func (s *Server) RunSniSpoofScan(c *gin.Context) {
	var req SniSpoofScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if len(req.SNIs) == 0 {
		req.SNIs = defaultSniSpoofList()
	}
	if len(req.SNIs) > 500 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "too many SNIs: max 500"})
		return
	}

	timeout := time.Duration(req.TimeoutSecs) * time.Second
	if timeout <= 0 {
		timeout = 6 * time.Second
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), timeout*time.Duration(len(req.SNIs))+30*time.Second)
	defer cancel()

	cfg := diagnostics.SniSpoofScanConfig{
		Target:      req.Target,
		Timeout:     timeout,
		Concurrency: req.Concurrency,
	}

	if req.StabilityRuns > 1 {
		results := diagnostics.RunSniSpoofStabilityScan(ctx, cfg, req.SNIs, req.StabilityRuns)
		passing := 0
		for _, r := range results {
			if r.Successes > 0 {
				passing++
			}
		}
		c.JSON(http.StatusOK, gin.H{
			"target": req.Target, "total": len(results), "passing": passing,
			"stability_runs": min(req.StabilityRuns, 5), "results": results,
		})
		return
	}

	results := diagnostics.RunSniSpoofScan(ctx, cfg, req.SNIs)
	ok := 0
	for _, r := range results {
		if r.Outcome == diagnostics.SniSpoofOK {
			ok++
		}
	}
	passRate := 0.0
	if len(results) > 0 {
		passRate = float64(ok) / float64(len(results))
	}
	c.JSON(http.StatusOK, gin.H{"target": req.Target, "total": len(results), "passing": ok, "pass_rate": passRate, "results": results})
}

// GetSniSpoofDefaults returns the default SNI list for the spoof scanner.
func (s *Server) GetSniSpoofDefaults(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"default_snis":        defaultSniSpoofList(),
		"default_target":      "104.18.4.130:443",
		"default_timeout_sec": 6,
		"default_concurrency": 10,
	})
}

// defaultSniSpoofList returns a curated list of reputable domain SNIs for testing.
// Based on sni-spoofing-rust data/scan-snis.txt content structure.
func defaultSniSpoofList() []string {
	return diagnostics.CuratedSniCandidates()
}
