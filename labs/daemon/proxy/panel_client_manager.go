// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: panel-main
// Target path: server/internal/proxy/panel_client_manager.go

package proxy

import (
	"sync"
)

// ClientBadges defines display priorities and features for client cards (from clients.ts).
type ClientBadges struct {
	Featured bool `json:"featured,omitempty"`
	HWID     bool `json:"hwid,omitempty"`
}

// ClientLinks defines external documentation and web links (from clients.ts).
type ClientLinks struct {
	Docs     string `json:"docs,omitempty"`
	GitHub   string `json:"github,omitempty"`
	Telegram string `json:"telegram,omitempty"`
	Website  string `json:"website,omitempty"`
}

// DownloadLinks specifies platform-specific direct download urls (from clients.ts).
type DownloadLinks struct {
	Android string `json:"android,omitempty"`
	IOS     string `json:"ios,omitempty"`
	Linux   string `json:"linux,omitempty"`
	MacOS   string `json:"macos,omitempty"`
	Windows string `json:"windows,omitempty"`
}

// PanelClient metadata definitions for proxy subscriber downloads (from clients.ts).
type PanelClient struct {
	ID            string        `json:"id"`
	Name          string        `json:"name"`
	Core          string        `json:"core"`
	Platforms     []string      `json:"platforms"`
	Description   string        `json:"description"`
	Logo          string        `json:"logo,omitempty"`
	Badges        ClientBadges  `json:"badges,omitempty"`
	DownloadLinks DownloadLinks `json:"downloadLinks,omitempty"`
	Links         ClientLinks   `json:"links,omitempty"`
}

// PanelClientManager orchestrates client profiles lists (from clients.ts).
type PanelClientManager struct {
	mu      sync.RWMutex
	clients map[string]PanelClient
}

// NewPanelClientManager creates a new PanelClientManager with default clients pre-populated (from clients.ts).
func NewPanelClientManager() *PanelClientManager {
	m := &PanelClientManager{
		clients: make(map[string]PanelClient),
	}

	// Register Happ client (from clients.ts)
	m.AddClient(PanelClient{
		ID:          "happ",
		Name:        "Happ",
		Core:        "xray",
		Platforms:   []string{"android", "ios", "macos", "windows", "linux"},
		Description: "Modern and feature-rich proxy client for Android, iOS, macOS, and Windows.",
		Logo:        "/clients/logo/happ-dark.svg",
		Badges: ClientBadges{
			Featured: true,
			HWID:     true,
		},
		DownloadLinks: DownloadLinks{
			Android: "https://play.google.com/store/apps/details?id=com.happproxy",
			IOS:     "https://apps.apple.com/us/app/happ-proxy-utility/id6504287215",
			MacOS:   "https://apps.apple.com/us/app/happ-proxy-utility/id6504287215",
			Windows: "https://github.com/Happ-proxy/happ-desktop/releases/latest/download/setup-Happ.x64.exe",
			Linux:   "https://github.com/Happ-proxy/happ-desktop/releases/latest",
		},
		Links: ClientLinks{
			Website:  "https://happ.su/main",
			Telegram: "https://t.me/happ_chat",
		},
	})

	// Register FlClashX client (from clients.ts)
	m.AddClient(PanelClient{
		ID:          "flclashx",
		Name:        "FlClashX",
		Core:        "mihomo",
		Platforms:   []string{"android", "windows", "macos", "linux"},
		Description: "Fork of FlClash with improvements and additional features.",
		Logo:        "/clients/logo/flclashx-dark.svg",
		Badges: ClientBadges{
			Featured: true,
			HWID:     true,
		},
		DownloadLinks: DownloadLinks{
			Android: "https://github.com/pluralplay/flclashx/releases/latest",
			Windows: "https://github.com/pluralplay/flclashx/releases/latest",
			MacOS:   "https://github.com/pluralplay/flclashx/releases/latest",
			Linux:   "https://github.com/pluralplay/flclashx/releases/latest",
		},
		Links: ClientLinks{
			GitHub: "https://github.com/pluralplay/flclashx",
		},
	})

	return m
}

// AddClient inserts a client metadata definition (from clients.ts).
func (m *PanelClientManager) AddClient(c PanelClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clients[c.ID] = c
}

// RemoveClient deletes client profile by ID.
func (m *PanelClientManager) RemoveClient(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.clients, id)
}

// GetClient retrieves client by ID.
func (m *PanelClientManager) GetClient(id string) (PanelClient, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.clients[id]
	return c, ok
}

// ListClientsByPlatform filters client lists by platform compatibility.
func (m *PanelClientManager) ListClientsByPlatform(platform string) []PanelClient {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var matched []PanelClient
	for _, c := range m.clients {
		for _, p := range c.Platforms {
			if p == platform {
				matched = append(matched, c)
				break
			}
		}
	}
	return matched
}
