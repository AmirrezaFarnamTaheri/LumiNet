package api

import (
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/analysis/provider"
)

const maxProviderCorpusUploadBytes int64 = 4 << 20

// setupProviderCorpusRoutes registers provider corpus endpoints.
func (s *Server) setupProviderCorpusRoutes(rg *gin.RouterGroup) {
	pc := rg.Group("/provider-corpus")
	pc.GET("", s.GetProviderCorpusStatus)
	pc.POST("", s.UpdateProviderCorpus)
}

// GetProviderCorpusStatus handles GET /api/provider-corpus — returns status of the active provider corpus.
func (s *Server) GetProviderCorpusStatus(c *gin.Context) {
	status, ok := provider.DefaultService.Status(time.Now())
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "PROVIDER_CORPUS_UNAVAILABLE",
			"message": "provider corpus status unavailable",
		})
		return
	}
	c.JSON(http.StatusOK, status)
}

// UpdateProviderCorpus handles POST /api/provider-corpus — uploads a new JSON provider corpus.
func (s *Server) UpdateProviderCorpus(c *gin.Context) {
	bodyBytes, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, maxProviderCorpusUploadBytes))
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{
				"error":   "PROVIDER_CORPUS_TOO_LARGE",
				"message": "provider corpus exceeds the upload limit",
			})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "PROVIDER_CORPUS_READ_FAILED",
			"message": "failed to read provider corpus",
		})
		return
	}

	corpus, err := provider.Parse(bodyBytes)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "INVALID_CORPUS_SCHEMA",
			"message": "failed to parse corpus: " + err.Error(),
		})
		return
	}

	status, err := provider.DefaultService.ActivateWithStatus(corpus, time.Now())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to swap provider corpus: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status": "swapped",
		"corpus": status,
	})
}
