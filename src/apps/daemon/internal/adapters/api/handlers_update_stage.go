package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/contracts/buildinfo"
	"github.com/maybeknott/luminet/internal/foundation/updateadmission"
)

// StageSignedUpdate verifies and downloads a signed update artifact into the
// daemon-owned cache. Staging does not execute or install the artifact.
func (s *Server) StageSignedUpdate(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxUpdateAdmissionRequestBytes)
	var request updateAdmissionRequest
	dec := json.NewDecoder(c.Request.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&request); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "update staging request exceeds size limit"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		c.JSON(http.StatusBadRequest, gin.H{"error": "update staging request contains trailing JSON values"})
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
	plan, err := s.verifySignedUpdateAgainstHighWater(c.Request.Context(), verifier, buildinfo.Version, request.Envelope)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.acceptSignedUpdateSequence(c.Request.Context(), &plan); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	result, err := updateadmission.Stage(c.Request.Context(), nil, "", plan)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}
