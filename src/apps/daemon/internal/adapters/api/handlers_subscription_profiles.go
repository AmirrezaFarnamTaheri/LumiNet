package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/maybeknott/luminet/internal/integrations/sub"
)

// API aliases retain existing JSON and Go contracts while internal/sub owns
// profile state, fetches, metadata parsing, and stale-refresh protection.
type SubscriptionProfile = sub.ManagedProfile
type SubscriptionInfo = sub.ProfileInfo

type CreateProfileRequest struct {
	Name               string   `json:"name" binding:"required"`
	URL                string   `json:"url" binding:"required"`
	Mirrors            []string `json:"mirrors,omitempty"`
	UpdateIntervalH    int      `json:"update_interval_hours"`
	AutoRefresh        bool     `json:"auto_refresh"`
	RemoteFetchEnabled bool     `json:"remote_fetch_enabled"`
}

type UpdateProfileRequest = sub.ProfilePatch

type SubscriptionProfileView struct {
	SubscriptionProfile
	Entitlement sub.ProfileEntitlement `json:"entitlement"`
}

func subscriptionProfileViewAt(profile SubscriptionProfile, now time.Time) SubscriptionProfileView {
	return SubscriptionProfileView{
		SubscriptionProfile: profile,
		Entitlement:         sub.EvaluateProfileEntitlement(profile.Info, now),
	}
}

func validateSubscriptionSources(primary string, mirrors []string) error {
	if err := sub.ValidateProfileSourceURL(primary); err != nil {
		return fmt.Errorf("subscription URL: %w", err)
	}
	if len(mirrors) > 3 {
		return fmt.Errorf("at most 3 subscription mirrors are allowed")
	}
	for i, mirror := range mirrors {
		if err := sub.ValidateProfileSourceURL(mirror); err != nil {
			return fmt.Errorf("subscription mirror %d: %w", i, err)
		}
	}
	return nil
}

func (s *Server) ListSubscriptionProfiles(c *gin.Context) {
	profiles := s.profileService.List()
	now := time.Now().UTC()
	views := make([]SubscriptionProfileView, 0, len(profiles))
	for _, profile := range profiles {
		views = append(views, subscriptionProfileViewAt(profile, now))
	}
	c.JSON(http.StatusOK, gin.H{"profiles": views, "total": len(views)})
}

func (s *Server) CreateSubscriptionProfile(c *gin.Context) {
	var request CreateProfileRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := validateSubscriptionSources(request.URL, request.Mirrors); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	profile := s.profileService.Create(SubscriptionProfile{
		ID:                 uuid.New().String(),
		Name:               request.Name,
		URL:                request.URL,
		Mirrors:            request.Mirrors,
		UpdateIntervalH:    request.UpdateIntervalH,
		Active:             true,
		RemoteFetchEnabled: request.RemoteFetchEnabled,
		AutoRefresh:        request.AutoRefresh,
	})
	if request.AutoRefresh && request.RemoteFetchEnabled {
		s.profileService.QueueRefresh(profile.ID)
	}
	c.JSON(http.StatusCreated, subscriptionProfileViewAt(profile, time.Now().UTC()))
}

func (s *Server) GetSubscriptionProfile(c *gin.Context) {
	profile, ok := s.profileService.Get(c.Param("id"))
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "profile not found"})
		return
	}
	c.JSON(http.StatusOK, subscriptionProfileViewAt(profile, time.Now().UTC()))
}

func (s *Server) UpdateSubscriptionProfile(c *gin.Context) {
	id := c.Param("id")
	if _, ok := s.profileService.Get(id); !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "profile not found"})
		return
	}
	current, _ := s.profileService.Get(id)
	var request UpdateProfileRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	effectiveURL := current.URL
	if request.URL != nil {
		effectiveURL = *request.URL
	}
	effectiveMirrors := current.Mirrors
	if request.Mirrors != nil {
		effectiveMirrors = *request.Mirrors
	}
	if err := validateSubscriptionSources(effectiveURL, effectiveMirrors); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if request.URL != nil && *request.URL != current.URL && s.subscriptionRuntime != nil {
		status := s.subscriptionRuntime.Status()
		if status.Active && status.ProfileID == id {
			c.JSON(http.StatusConflict, gin.H{"error": "cannot change subscription source while its node is active"})
			return
		}
	}
	profile, ok := s.profileService.Update(id, request)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "profile not found"})
		return
	}
	c.JSON(http.StatusOK, subscriptionProfileViewAt(profile, time.Now().UTC()))
}

func (s *Server) DeleteSubscriptionProfile(c *gin.Context) {
	id := c.Param("id")
	if s.subscriptionRuntime != nil {
		status := s.subscriptionRuntime.Status()
		if status.Active && status.ProfileID == id {
			if err := s.subscriptionRuntime.Stop(id, status.NodeID); err != nil {
				c.JSON(http.StatusConflict, gin.H{"error": err.Error(), "runtime": status})
				return
			}
		}
	}
	if !s.profileService.Delete(id) {
		c.JSON(http.StatusNotFound, gin.H{"error": "profile not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": id})
}

func (s *Server) RefreshSubscriptionProfile(c *gin.Context) {
	profile, ok := s.profileService.Get(c.Param("id"))
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "profile not found"})
		return
	}
	if !s.profileService.QueueRefresh(profile.ID) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "subscription refresh unavailable"})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"message": "refresh queued", "id": profile.ID})
}
