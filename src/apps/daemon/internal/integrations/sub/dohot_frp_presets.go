package sub

// DoHoTPreset represents a DNS-over-HTTPS-over-Tor configuration.
type DoHoTPreset struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	// DNS listen address
	ListenAddr string `json:"listen_addr"`
	// Upstream resolver (DoH provider)
	Resolver string `json:"resolver"`
	// Use Tor SOCKS5 proxy
	TorProxy string `json:"tor_proxy"`
	// Force TCP (required for Tor)
	ForceTCP bool `json:"force_tcp"`
	// Block IPv6 queries
	BlockIPv6 bool `json:"block_ipv6"`
	// Require DNSSEC
	RequireDNSSEC bool `json:"require_dnssec"`
	// Require NoFilter
	RequireNoFilter bool `json:"require_no_filter"`
	// Allow logging (false = privacy mode)
	RequireNoLog bool `json:"require_no_log"`
	// Tags
	Tags []string `json:"tags"`
}

// FRPPreset represents a Fast Reverse Proxy client/server configuration.
type FRPPreset struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	// Server address and port
	ServerAddr string `json:"server_addr"`
	ServerPort int    `json:"server_port"`
	// Proxy type: tcp, udp, http, https, stcp, xtcp
	ProxyType string `json:"proxy_type"`
	// Local service
	LocalIP   string `json:"local_ip"`
	LocalPort int    `json:"local_port"`
	// Remote port
	RemotePort int `json:"remote_port"`
	// TLS
	TLSEnable bool     `json:"tls_enable"`
	Tags      []string `json:"tags"`
}

// ExoneratorQuery holds parameters for Tor relay exit checker.
type ExoneratorQuery struct {
	// IP address to check
	IP string `json:"ip"`
	// Date in YYYY-MM-DD format
	Date string `json:"date"`
	// Optional port to check
	Port *int `json:"port,omitempty"`
}

// ExoneratorResult indicates whether the IP was a Tor relay at the given date.
type ExoneratorResult struct {
	IP                string   `json:"ip"`
	Date              string   `json:"date"`
	IsTorRelay        bool     `json:"is_tor_relay"`
	IsExitRelay       bool     `json:"is_exit_relay"`
	RelayFingerprints []string `json:"relay_fingerprints,omitempty"`
	// Checked via Tor Metrics API
	SourceURL string `json:"source_url"`
}

// DoHoTPresets returns reference DNS-over-HTTPS-over-Tor presets from dohot-master.
func DoHoTPresets() []DoHoTPreset {
	return []DoHoTPreset{
		{
			ID:              "dohot-cloudflare",
			Name:            "DoHoT via Cloudflare",
			Description:     "DNS-over-HTTPS-over-Tor using Cloudflare resolver. Hides DNS queries from your ISP via Tor.",
			ListenAddr:      "0.0.0.0:53",
			Resolver:        "cloudflare",
			TorProxy:        "socks5://127.0.0.1:9050",
			ForceTCP:        true,
			BlockIPv6:       true,
			RequireDNSSEC:   true,
			RequireNoFilter: true,
			RequireNoLog:    false,
			Tags:            []string{"tor", "doh", "cloudflare", "privacy", "dnscrypt"},
		},
		{
			ID:              "dohot-google",
			Name:            "DoHoT via Google",
			Description:     "DNS-over-HTTPS-over-Tor using Google's DNS resolver.",
			ListenAddr:      "0.0.0.0:53",
			Resolver:        "google",
			TorProxy:        "socks5://127.0.0.1:9050",
			ForceTCP:        true,
			BlockIPv6:       true,
			RequireDNSSEC:   true,
			RequireNoFilter: true,
			RequireNoLog:    false,
			Tags:            []string{"tor", "doh", "google", "privacy", "dnscrypt"},
		},
		{
			ID:              "dohot-onion-cloudflare",
			Name:            "DoHoT via Cloudflare Onion",
			Description:     "DNS-over-HTTPS-over-Tor using Cloudflare's .onion DoH resolver for maximum privacy.",
			ListenAddr:      "0.0.0.0:53",
			Resolver:        "onion-cloudflare",
			TorProxy:        "socks5://127.0.0.1:9050",
			ForceTCP:        true,
			BlockIPv6:       true,
			RequireDNSSEC:   true,
			RequireNoFilter: true,
			RequireNoLog:    false,
			Tags:            []string{"tor", "doh", "cloudflare", "onion", "privacy", "maximum"},
		},
	}
}

// FRPPresets returns standard Fast Reverse Proxy configuration presets.
func FRPPresets() []FRPPreset {
	return []FRPPreset{
		{
			ID:          "frp-tcp-ssh",
			Name:        "FRP TCP SSH Tunnel",
			Description: "Expose local SSH service via FRP server reverse proxy",
			ServerAddr:  "frp.example.com",
			ServerPort:  7000,
			ProxyType:   "tcp",
			LocalIP:     "127.0.0.1",
			LocalPort:   22,
			RemotePort:  6000,
			TLSEnable:   false,
			Tags:        []string{"frp", "tcp", "ssh", "reverse-proxy"},
		},
		{
			ID:          "frp-tcp-tls",
			Name:        "FRP TCP TLS Tunnel",
			Description: "Reverse proxy with TLS encryption for secure tunneling",
			ServerAddr:  "frp.example.com",
			ServerPort:  7000,
			ProxyType:   "tcp",
			LocalIP:     "127.0.0.1",
			LocalPort:   8080,
			RemotePort:  8080,
			TLSEnable:   true,
			Tags:        []string{"frp", "tcp", "tls", "secure", "reverse-proxy"},
		},
		{
			ID:          "frp-http",
			Name:        "FRP HTTP Service",
			Description: "Expose local HTTP server via FRP for web app tunneling",
			ServerAddr:  "frp.example.com",
			ServerPort:  7000,
			ProxyType:   "http",
			LocalIP:     "127.0.0.1",
			LocalPort:   80,
			RemotePort:  80,
			TLSEnable:   false,
			Tags:        []string{"frp", "http", "web", "reverse-proxy"},
		},
		{
			ID:          "frp-stcp",
			Name:        "FRP STCP Peer-to-Peer",
			Description: "Secret TCP tunnel for P2P connections without exposing port publicly",
			ServerAddr:  "frp.example.com",
			ServerPort:  7000,
			ProxyType:   "stcp",
			LocalIP:     "127.0.0.1",
			LocalPort:   22,
			RemotePort:  0,
			TLSEnable:   true,
			Tags:        []string{"frp", "stcp", "p2p", "secret", "reverse-proxy"},
		},
	}
}
