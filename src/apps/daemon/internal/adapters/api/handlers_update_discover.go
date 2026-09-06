package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/contracts/buildinfo"
	"github.com/maybeknott/luminet/internal/foundation/updateadmission"
)

const maxUpdateDiscoveryRequestBytes = 8 << 10

type updateDiscoveryRequest struct {
	ManifestURL string `json:"manifest_url"`
}

// DiscoverSignedUpdate fetches a bounded signed envelope from an HTTPS URL and
// verifies it against the same configured trust roots as manual admission.
func (s *Server) DiscoverSignedUpdate(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxUpdateDiscoveryRequestBytes)
	var request updateDiscoveryRequest
	dec := json.NewDecoder(c.Request.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&request); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "update discovery request exceeds size limit"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		c.JSON(http.StatusBadRequest, gin.H{"error": "update discovery request contains trailing JSON values"})
		return
	}
	if strings.TrimSpace(request.ManifestURL) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "manifest_url is required"})
		return
	}

	cfg := s.configManager.Get()
	if cfg == nil || len(cfg.UpdateAdmission.TrustedKeys) == 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "update admission trust roots are not configured"})
		return
	}
	verifier, err := updateadmission.NewVerifier(cfg.UpdateAdmission.TrustedKeys)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update admission trust configuration is invalid"})
		return
	}
	envelope, err := updateadmission.Discover(c.Request.Context(), nil, request.ManifestURL)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	plan, err := s.verifySignedUpdateAgainstHighWater(c.Request.Context(), verifier, buildinfo.Version, envelope)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"envelope": envelope, "plan": plan})
}
