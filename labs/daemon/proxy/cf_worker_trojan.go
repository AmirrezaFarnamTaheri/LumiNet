// Package proxy implements multi-protocol proxy servers and clients.
// Ported from: Cloudflare-vless-trojan-main (Trojan_workers_pages/)
// Target path: server/internal/proxy/cf_worker_trojan.go

package proxy

// CFWorkerTrojanConfig holds Trojan connection parameters.
// Maps to Trojan properties parsed in Trojan worker script.
type CFWorkerTrojanConfig struct {
	Password   string `json:"password"`
	Hostname   string `json:"hostname"`
	ProxyIP    string `json:"proxy_ip"`
	Port       int    `json:"port"`
	Path       string `json:"path"`
	Encryption string `json:"encryption"`
}

// Getters & Setters for CFWorkerTrojanConfig
func (c *CFWorkerTrojanConfig) GetPassword() string  { return c.Password }
func (c *CFWorkerTrojanConfig) SetPassword(v string) { c.Password = v }

// GenerateTrojanWorkerURL formats a standard trojan:// sharing URL.
// Maps to Trojan config sharing formats.
func GenerateTrojanWorkerURL(cfg CFWorkerTrojanConfig, remarks string) string {
	return buildCFWorkerURL(cfWorkerURLSpec{
		Scheme:     "trojan",
		Credential: cfg.Password,
		Hostname:   cfg.Hostname,
		ProxyIP:    cfg.ProxyIP,
		Port:       cfg.Port,
		Path:       cfg.Path,
		Remarks:    remarks,
	})
}
