package proxyconfig

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// DnsWizardConfig defines parameters for DNS VPN profile generation.
type DnsWizardConfig struct {
	ProfileName    string   `json:"profile_name"`
	DnsServer      string   `json:"dns_server"`
	RootDomain     string   `json:"root_domain"`
	ObfuscationKey string   `json:"obfuscation_key"`
	Compression    bool     `json:"compression"`
	FallbackServers []string `json:"fallback_servers"`
	Port           int      `json:"port"`
}

// WizardProfileResult holds the compiled artifact and metadata.
type WizardProfileResult struct {
	ID        string    `json:"id"`
	RawJSON   string    `json:"raw_json"`
	Base64URI string    `json:"base64_uri"`
	CreatedAt time.Time `json:"created_at"`
}

// GenerateDnsWizardProfile compiles a configuration into an active proxy profile.
func GenerateDnsWizardProfile(cfg DnsWizardConfig) (*WizardProfileResult, error) {
	if cfg.ProfileName == "" {
		return nil, fmt.Errorf("profile name cannot be empty")
	}
	if cfg.DnsServer == "" {
		return nil, fmt.Errorf("dns server cannot be empty")
	}
	if cfg.RootDomain == "" {
		return nil, fmt.Errorf("root domain cannot be empty")
	}
	if cfg.Port <= 0 || cfg.Port > 65535 {
		cfg.Port = 53
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}

	uri := fmt.Sprintf("dnsvpn://%s@%s:%d?domain=%s&comp=%t",
		cfg.ObfuscationKey,
		cfg.DnsServer,
		cfg.Port,
		cfg.RootDomain,
		cfg.Compression,
	)

	b64URI := base64.URLEncoding.EncodeToString([]byte(uri))
	id := fmt.Sprintf("dns-wiz-%s-%d", strings.ToLower(cfg.ProfileName), time.Now().UnixNano()%100000)

	return &WizardProfileResult{
		ID:        id,
		RawJSON:   string(data),
		Base64URI: b64URI,
		CreatedAt: time.Now(),
	}, nil
}
