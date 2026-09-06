package system

// ProxySettings represents the system-wide proxy settings.
type ProxySettings struct {
	Enabled    bool   `json:"enabled"`
	Server     string `json:"server"`
	Bypass     string `json:"bypass"`
	HTTPServer string `json:"http_server"`
	BypassList string `json:"bypass_list"`
	PACURL     string `json:"pac_url"`
}
