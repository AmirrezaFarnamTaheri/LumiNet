// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: v2rayng-panel
// Target path: server/internal/proxy/inbound_panel_adapter.go

package proxy

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"sync"
)

// InboundClient represents client credentials for parsed inbounds.
type InboundClient struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

// InboundDetails holds parsed V2Ray/Xray inbound settings.
type InboundDetails struct {
	Port     int             `json:"port"`
	Protocol string          `json:"protocol"` // "vmess", "vless", "trojan"
	Path     string          `json:"path,omitempty"`
	Clients  []InboundClient `json:"clients,omitempty"`
}

// InboundPanelAdapter manages import configurations of active inbound clients.
type InboundPanelAdapter struct {
	mu       sync.RWMutex
	inbounds []InboundDetails
}

// NewInboundPanelAdapter instantiates InboundPanelAdapter.
func NewInboundPanelAdapter() *InboundPanelAdapter {
	return &InboundPanelAdapter{
		inbounds: make([]InboundDetails, 0),
	}
}

// 1. ImportInboundsFromJSON parses raw config.json and registers details.
func (i *InboundPanelAdapter) ImportInboundsFromJSON(rawConfig []byte) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	var cfg struct {
		Inbounds []struct {
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
			Settings struct {
				Clients []struct {
					ID    string `json:"id"`
					Email string `json:"email"`
				} `json:"clients"`
			} `json:"settings"`
			StreamSettings struct {
				Network    string `json:"network"`
				WsSettings struct {
					Path string `json:"path"`
				} `json:"wsSettings"`
			} `json:"streamSettings"`
		} `json:"inbounds"`
	}

	err := json.Unmarshal(rawConfig, &cfg)
	if err != nil {
		return err
	}

	for _, in := range cfg.Inbounds {
		clients := make([]InboundClient, len(in.Settings.Clients))
		for idx, c := range in.Settings.Clients {
			clients[idx] = InboundClient{ID: c.ID, Email: c.Email}
		}

		details := InboundDetails{
			Port:     in.Port,
			Protocol: in.Protocol,
			Clients:  clients,
		}

		if in.StreamSettings.Network == "ws" {
			details.Path = in.StreamSettings.WsSettings.Path
		}

		i.inbounds = append(i.inbounds, details)
	}

	return nil
}

// 2. GetInboundsList returns registered details.
func (i *InboundPanelAdapter) GetInboundsList() []InboundDetails {
	i.mu.RLock()
	defer i.mu.RUnlock()

	res := make([]InboundDetails, len(i.inbounds))
	copy(res, i.inbounds)
	return res
}

// 3. AddInbound registers a new inbound configuration detail.
func (i *InboundPanelAdapter) AddInbound(in InboundDetails) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	for _, val := range i.inbounds {
		if val.Port == in.Port {
			return fmt.Errorf("inbound port %d already exists", in.Port)
		}
	}
	i.inbounds = append(i.inbounds, in)
	return nil
}

// 4. RemoveInbound deletes an inbound by port.
func (i *InboundPanelAdapter) RemoveInbound(port int) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	for idx, val := range i.inbounds {
		if val.Port == port {
			i.inbounds = append(i.inbounds[:idx], i.inbounds[idx+1:]...)
			return nil
		}
	}
	return fmt.Errorf("inbound port %d not found", port)
}

// 5. ClearInbounds clears all inbound registry list items.
func (i *InboundPanelAdapter) ClearInbounds() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.inbounds = make([]InboundDetails, 0)
}

// 6. GetInboundCount returns tracked count.
func (i *InboundPanelAdapter) GetInboundCount() int {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return len(i.inbounds)
}

// 7. AddClientToInbound appends a client to active inbound config list.
func (i *InboundPanelAdapter) AddClientToInbound(port int, client InboundClient) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	for idx, val := range i.inbounds {
		if val.Port == port {
			for _, c := range val.Clients {
				if c.Email == client.Email {
					return fmt.Errorf("client %s already exists on port %d", client.Email, port)
				}
			}
			i.inbounds[idx].Clients = append(i.inbounds[idx].Clients, client)
			return nil
		}
	}
	return fmt.Errorf("inbound port %d not found", port)
}

// 8. RemoveClientFromInbound removes a client.
func (i *InboundPanelAdapter) RemoveClientFromInbound(port int, email string) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	for idx, val := range i.inbounds {
		if val.Port == port {
			for cIdx, c := range val.Clients {
				if c.Email == email {
					i.inbounds[idx].Clients = append(val.Clients[:cIdx], val.Clients[cIdx+1:]...)
					return nil
				}
			}
			return fmt.Errorf("client %s not found on port %d", email, port)
		}
	}
	return fmt.Errorf("inbound port %d not found", port)
}

// 9. GetClientsForInbound returns registered clients list for a port.
func (i *InboundPanelAdapter) GetClientsForInbound(port int) ([]InboundClient, error) {
	i.mu.RLock()
	defer i.mu.RUnlock()

	for _, val := range i.inbounds {
		if val.Port == port {
			copied := make([]InboundClient, len(val.Clients))
			copy(copied, val.Clients)
			return copied, nil
		}
	}
	return nil, fmt.Errorf("inbound port %d not found", port)
}

// 10. InboundExists returns true if port is registered.
func (i *InboundPanelAdapter) InboundExists(port int) bool {
	i.mu.RLock()
	defer i.mu.RUnlock()

	for _, val := range i.inbounds {
		if val.Port == port {
			return true
		}
	}
	return false
}

// 11. SetPathForInbound configures websocket path.
func (i *InboundPanelAdapter) SetPathForInbound(port int, path string) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	for idx, val := range i.inbounds {
		if val.Port == port {
			i.inbounds[idx].Path = path
			return nil
		}
	}
	return fmt.Errorf("inbound port %d not found", port)
}

// 12. SetProtocolForInbound configures protocol.
func (i *InboundPanelAdapter) SetProtocolForInbound(port int, proto string) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	for idx, val := range i.inbounds {
		if val.Port == port {
			i.inbounds[idx].Protocol = proto
			return nil
		}
	}
	return fmt.Errorf("inbound port %d not found", port)
}

// 13. ExportInboundsJSON saves list as JSON.
func (i *InboundPanelAdapter) ExportInboundsJSON(filePath string) error {
	i.mu.RLock()
	defer i.mu.RUnlock()

	data, err := json.MarshalIndent(i.inbounds, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filePath, data, 0644)
}

// 14. ImportInboundsFromFile loads configurations from disk paths.
func (i *InboundPanelAdapter) ImportInboundsFromFile(filePath string) error {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}
	return i.ImportInboundsFromJSON(data)
}

// 15. ImportInboundJSON acts as the diagnostic legacy interface entry.
func (i *InboundPanelAdapter) ImportInboundJSON(jsonStr string) {
	_ = i.ImportInboundsFromJSON([]byte(jsonStr))
	fmt.Printf("InboundPanelAdapter: Imported JSON configs count: %d\n", len(i.inbounds))
}
