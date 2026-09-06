package mobilehost

import (
	"encoding/json"
	"errors"
	"sync"
	"time"
)

// SupportedProtocol denotes the underlying tunnel protocol
type SupportedProtocol string

const (
	ProtoAmneziaWg SupportedProtocol = "amnezia_wg"
	ProtoVless     SupportedProtocol = "vless"
	ProtoShadow22  SupportedProtocol = "shadowsocks_2022"
	ProtoMasque    SupportedProtocol = "masque"
)

// ProfileContainer holds profile metadata and configuration payload
type ProfileContainer struct {
	ProfileID      string            `json:"profile_id"`
	Name           string            `json:"name"`
	Protocol       SupportedProtocol `json:"protocol"`
	ServerEndpoint string            `json:"server_endpoint"`
	FallbackOrder  int               `json:"fallback_order"`
	ConfigPayload  string            `json:"config_payload"`
	CreatedAt      time.Time         `json:"created_at"`
}

// ProtocolProfileOrchestrator manages protocol switching, profile imports, and fallback chains
type ProtocolProfileOrchestrator struct {
	profiles       map[string]ProfileContainer
	activeProfileID string
	mu             sync.RWMutex
}

// NewProtocolProfileOrchestrator creates a new orchestrator
func NewProtocolProfileOrchestrator() *ProtocolProfileOrchestrator {
	return &ProtocolProfileOrchestrator{
		profiles: make(map[string]ProfileContainer),
	}
}

// AddProfile stores a new profile
func (o *ProtocolProfileOrchestrator) AddProfile(profile ProfileContainer) {
	o.mu.Lock()
	defer o.mu.Unlock()
	profile.CreatedAt = time.Now()
	o.profiles[profile.ProfileID] = profile
	if o.activeProfileID == "" {
		o.activeProfileID = profile.ProfileID
	}
}

// SetActiveProfile activates a specific profile by ID
func (o *ProtocolProfileOrchestrator) SetActiveProfile(profileID string) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if _, exists := o.profiles[profileID]; !exists {
		return errors.New("profile ID not found")
	}
	o.activeProfileID = profileID
	return nil
}

// GetActiveProfile retrieves current active profile
func (o *ProtocolProfileOrchestrator) GetActiveProfile() (ProfileContainer, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()

	profile, exists := o.profiles[o.activeProfileID]
	if !exists {
		return ProfileContainer{}, errors.New("no active profile set")
	}
	return profile, nil
}

// GetFallbackChain returns profiles ordered by fallback precedence
func (o *ProtocolProfileOrchestrator) GetFallbackChain() []ProfileContainer {
	o.mu.RLock()
	defer o.mu.RUnlock()

	var list []ProfileContainer
	for _, p := range o.profiles {
		list = append(list, p)
	}

	// Sort by FallbackOrder ascending
	for i := 0; i < len(list); i++ {
		for j := i + 1; j < len(list); j++ {
			if list[i].FallbackOrder > list[j].FallbackOrder {
				list[i], list[j] = list[j], list[i]
			}
		}
	}
	return list
}

// ExportProfilesJSON serializes all profiles to JSON
func (o *ProtocolProfileOrchestrator) ExportProfilesJSON() ([]byte, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()

	var list []ProfileContainer
	for _, p := range o.profiles {
		list = append(list, p)
	}
	return json.Marshal(list)
}

// ImportProfilesJSON deserializes and registers profiles from JSON
func (o *ProtocolProfileOrchestrator) ImportProfilesJSON(data []byte) error {
	var list []ProfileContainer
	if err := json.Unmarshal(data, &list); err != nil {
		return err
	}

	o.mu.Lock()
	defer o.mu.Unlock()
	for _, p := range list {
		p.CreatedAt = time.Now()
		o.profiles[p.ProfileID] = p
	}
	if o.activeProfileID == "" && len(list) > 0 {
		o.activeProfileID = list[0].ProfileID
	}
	return nil
}
