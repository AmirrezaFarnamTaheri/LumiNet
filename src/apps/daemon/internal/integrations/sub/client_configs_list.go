package sub

import "log/slog"

// ClientConfigsList handles profile extraction.
type ClientConfigsList struct{}

func NewClientConfigsList() *ClientConfigsList {
	return &ClientConfigsList{}
}

// Parse ports collection parser extracting profiles lists from mixed text feeds.
func (c *ClientConfigsList) Parse() {
	slog.Info("ClientConfigsList: parsing profile collections from mixed text feeds")
}

// CottenDnsPreset represents a secure DNS tunneling profile.
type CottenDnsPreset struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Role        string `json:"role"`
	Description string `json:"description"`
	Content     string `json:"content"`
}

// GetCottenDnsPresets returns the secure DNS tunneling presets.
func GetCottenDnsPresets() []CottenDnsPreset {
	return []CottenDnsPreset{
		{
			ID:          "speed-client",
			Name:        "Speed Client Preset",
			Role:        "client",
			Description: "Lower base duplication, MTU-weighted resolver selection, LZ4, and loss-aware MTU probing.",
			Content: `# CottenDNS paired preset: speed
# Use with server_config.speed.toml.
CONFIG_PRESET = "speed"
DOMAINS = ["REPLACE_WITH_YOUR_DELEGATED_DOMAIN"]
ENCRYPTION_KEY = ""`,
		},
		{
			ID:          "speed-server",
			Name:        "Speed Server Preset",
			Role:        "server",
			Description: "Lower base duplication, LZ4, and loss-aware MTU probing on the server side.",
			Content: `# CottenDNS paired preset: speed
# Use with client_config.speed.toml.
CONFIG_PRESET = "speed"
DOMAIN = ["REPLACE_WITH_YOUR_DELEGATED_DOMAIN"]
ENCRYPTION_KEY_FILE = "encrypt_key.txt"`,
		},
		{
			ID:          "survival-client",
			Name:        "Survival Client Preset",
			Role:        "client",
			Description: "More duplication, smaller/stubbier DNS shape, lower MTU ceilings, and auto-FEC for lossy networks.",
			Content: `# CottenDNS paired preset: survival
# Use with server_config.survival.toml for restrictive, lossy UDP networks.
CONFIG_PRESET = "survival"
DOMAINS = ["REPLACE_WITH_YOUR_DELEGATED_DOMAIN"]
ENCRYPTION_KEY = ""`,
		},
		{
			ID:          "survival-server",
			Name:        "Survival Server Preset",
			Role:        "server",
			Description: "More duplication, smaller DNS shape, and auto-FEC on the server side.",
			Content: `# CottenDNS paired preset: survival
# Use with client_config.survival.toml.
CONFIG_PRESET = "survival"
DOMAIN = ["REPLACE_WITH_YOUR_DELEGATED_DOMAIN"]
ENCRYPTION_KEY_FILE = "encrypt_key.txt"`,
		},
		{
			ID:          "tcp-survival-client",
			Name:        "TCP-Survival Client Preset",
			Role:        "client",
			Description: "Forces DNS-over-TCP/53 on the client side.",
			Content: `# CottenDNS paired preset: tcp-survival
# Use with server_config.tcp-survival.toml when TCP/53 is the main working path.
CONFIG_PRESET = "tcp-survival"
DOMAINS = ["REPLACE_WITH_YOUR_DELEGATED_DOMAIN"]
ENCRYPTION_KEY = ""`,
		},
		{
			ID:          "tcp-survival-server",
			Name:        "TCP-Survival Server Preset",
			Role:        "server",
			Description: "Keeps the server TCP listener tuned for long-lived fallback connections.",
			Content: `# CottenDNS paired preset: tcp-survival
# Use with client_config.tcp-survival.toml.
CONFIG_PRESET = "tcp-survival"
DOMAIN = ["REPLACE_WITH_YOUR_DELEGATED_DOMAIN"]
ENCRYPTION_KEY_FILE = "encrypt_key.txt"`,
		},
	}
}
