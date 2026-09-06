// Package proxy implements multi-protocol proxy servers and clients.
// Ported from: Cloudflare-vless-trojan-main (Vless_workers_pages/_worker.js)
// Target path: server/internal/proxy/cf_worker_vless.go

package proxy

// CFWorkerVlessConfig holds VLESS connection parameters.
// Maps to javascript VLESS properties parsed in _worker.js.
type CFWorkerVlessConfig struct {
	UserUUID   string `json:"user_uuid"`
	Hostname   string `json:"hostname"`
	ProxyIP    string `json:"proxy_ip"`
	Port       int    `json:"port"`
	Path       string `json:"path"`
	Encryption string `json:"encryption"`
	Flow       string `json:"flow,omitempty"`
}

// Getters & Setters for CFWorkerVlessConfig
func (c *CFWorkerVlessConfig) GetUserUUID() string  { return c.UserUUID }
func (c *CFWorkerVlessConfig) SetUserUUID(v string) { c.UserUUID = v }

// GenerateVlessWorkerURL formats a standard vless:// sharing URL.
// Maps to upstream URL builder parsed by client configs.
func GenerateVlessWorkerURL(cfg CFWorkerVlessConfig, remarks string) string {
	encryption := cfg.Encryption
	if encryption == "" {
		encryption = "none"
	}
	return buildCFWorkerURL(cfWorkerURLSpec{
		Scheme:     "vless",
		Credential: cfg.UserUUID,
		Hostname:   cfg.Hostname,
		ProxyIP:    cfg.ProxyIP,
		Port:       cfg.Port,
		Path:       cfg.Path,
		Remarks:    remarks,
		Parameters: map[string]string{"encryption": encryption, "flow": cfg.Flow},
	})
}
