// Package android provides Go functionality for Android desktop components.
package android

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// ZedSecureProfile holds a ZedSecure/Flutter Android client proxy profile.
type ZedSecureProfile struct {
	Name                string `json:"name"`
	Protocol            string `json:"protocol"` // "reality", "vless", "vmess"
	Address             string `json:"address"`
	Port                int    `json:"port"`
	UUID                string `json:"uuid,omitempty"`
	RealityFingerprint  string `json:"reality_fingerprint,omitempty"` // e.g. "chrome", "firefox"
	RealityServerName   string `json:"reality_server_name,omitempty"`
	RealityPublicKey    string `json:"reality_public_key,omitempty"`
	SplitTunnelPackages []string `json:"split_tunnel_packages,omitempty"`
}

// ZedSecureClient manages Flutter Android client profiles, Reality fingerprint
// selectors, and split-tunneling package wrappers for ZedSecure.
type ZedSecureClient struct {
	// ProfileDir is the directory where ZedSecure profile JSON files are stored.
	ProfileDir string
}

func NewZedSecureClient() *ZedSecureClient {
	return &ZedSecureClient{
		ProfileDir: "/data/data/io.luminet/files/zedsecure/profiles",
	}
}

// Connect loads the active profile and initializes the ZedSecure connection.
func (z *ZedSecureClient) Connect() error {
	profiles, err := z.LoadProfiles()
	if err != nil {
		return fmt.Errorf("ZedSecureClient.Connect: %w", err)
	}
	if len(profiles) == 0 {
		slog.Warn("ZedSecureClient: no profiles found", "dir", z.ProfileDir)
		return nil
	}
	active := profiles[0]
	slog.Info("ZedSecureClient: connecting",
		"profile", active.Name,
		"protocol", active.Protocol,
		"address", active.Address,
		"fingerprint", active.RealityFingerprint,
		"split_tunnel_pkgs", len(active.SplitTunnelPackages),
	)
	return nil
}

// LoadProfiles reads all ZedSecure profile JSON files from ProfileDir.
func (z *ZedSecureClient) LoadProfiles() ([]*ZedSecureProfile, error) {
	entries, err := os.ReadDir(z.ProfileDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("ZedSecureClient.LoadProfiles: %w", err)
	}
	var profiles []*ZedSecureProfile
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(z.ProfileDir, entry.Name()))
		if err != nil {
			slog.Warn("ZedSecureClient: skip unreadable profile", "file", entry.Name(), "err", err)
			continue
		}
		var p ZedSecureProfile
		if err := json.Unmarshal(data, &p); err != nil {
			slog.Warn("ZedSecureClient: skip malformed profile", "file", entry.Name(), "err", err)
			continue
		}
		profiles = append(profiles, &p)
	}
	return profiles, nil
}

// SetSplitTunnel updates the split-tunnel package list on the active profile.
func (z *ZedSecureClient) SetSplitTunnel(profileName string, packages []string) error {
	profiles, err := z.LoadProfiles()
	if err != nil {
		return fmt.Errorf("ZedSecureClient.SetSplitTunnel: %w", err)
	}
	for _, p := range profiles {
		if p.Name == profileName {
			p.SplitTunnelPackages = packages
			data, err := json.MarshalIndent(p, "", "  ")
			if err != nil {
				return fmt.Errorf("ZedSecureClient.SetSplitTunnel: marshal: %w", err)
			}
			path := filepath.Join(z.ProfileDir, profileName+".json")
			if err := os.WriteFile(path, data, 0o644); err != nil {
				return fmt.Errorf("ZedSecureClient.SetSplitTunnel: write: %w", err)
			}
			slog.Info("ZedSecureClient: split tunnel updated", "profile", profileName, "packages", len(packages))
			return nil
		}
	}
	return fmt.Errorf("ZedSecureClient.SetSplitTunnel: profile %q not found", profileName)
}
