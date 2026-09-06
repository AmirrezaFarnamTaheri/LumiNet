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

type updateAdmissionRequest struct {
	Envelope updateadmission.Envelope `json:"envelope" binding:"required"`
}

const maxUpdateAdmissionRequestBytes = 64 << 10

// PlanSignedUpdate verifies a release intent against configured trust roots.
// It is intentionally a planning endpoint: success never downloads or applies
// an artifact and the returned plan always has apply_authorized=false.
func (s *Server) PlanSignedUpdate(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxUpdateAdmissionRequestBytes)
	var request updateAdmissionRequest
	dec := json.NewDecoder(c.Request.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&request); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "update admission request exceeds size limit"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		c.JSON(http.StatusBadRequest, gin.H{"error": "update admission request contains trailing JSON values"})
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
	c.JSON(http.StatusOK, plan)
}
