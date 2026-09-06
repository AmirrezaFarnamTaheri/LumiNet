// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: v2board-master
// Target path: server/internal/proxy/v2board.go

package proxy

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// V2BoardServer represents a proxy server configuration served by V2Board.
type V2BoardServer struct {
	ID       int      `json:"id"`
	Name     string   `json:"name"`
	Type     string   `json:"type"` // "ss", "vmess", "vless", "trojan"
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	Cipher   string   `json:"cipher,omitempty"`   // for ss
	Password string   `json:"password,omitempty"` // for ss/trojan
	UUID     string   `json:"uuid,omitempty"`     // for vmess/vless
	Network  string   `json:"network,omitempty"`  // "tcp", "ws", "grpc"
	Path     string   `json:"path,omitempty"`     // for ws/grpc
	TLS      bool     `json:"tls,omitempty"`
	Sni      string   `json:"sni,omitempty"`
	Tags     []string `json:"tags,omitempty"`
}

// V2BoardSubscription manages server subscriptions and configuration conversions.
type V2BoardSubscription struct {
	active bool
}

// NewV2BoardSubscription instantiates a new V2BoardSubscription service.
func NewV2BoardSubscription() *V2BoardSubscription {
	return &V2BoardSubscription{active: true}
}

// GenerateSubscriptionBase64 generates the standard Base64 line-separated subscription links.
func (v *V2BoardSubscription) GenerateSubscriptionBase64(servers []V2BoardServer) string {
	var links []string
	for _, s := range servers {
		switch s.Type {
		case "ss":
			// ss://base64(cipher:password)@host:port#name
			userInfo := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", s.Cipher, s.Password)))
			link := fmt.Sprintf("ss://%s@%s:%d#%s", userInfo, s.Host, s.Port, s.Name)
			links = append(links, link)
		case "trojan":
			// trojan://password@host:port?sni=sni#name
			link := fmt.Sprintf("trojan://%s@%s:%d?sni=%s#%s", s.Password, s.Host, s.Port, s.Sni, s.Name)
			links = append(links, link)
		case "vmess":
			// vmess://base64(vmessJSON)
			vMsg := map[string]interface{}{
				"v":    "2",
				"ps":   s.Name,
				"add":  s.Host,
				"port": s.Port,
				"id":   s.UUID,
				"aid":  0,
				"net":  s.Network,
				"path": s.Path,
				"tls":  "none",
			}
			if s.TLS {
				vMsg["tls"] = "tls"
				vMsg["sni"] = s.Sni
			}
			js, err := json.Marshal(vMsg)
			if err == nil {
				link := fmt.Sprintf("vmess://%s", base64.StdEncoding.EncodeToString(js))
				links = append(links, link)
			}
		case "vless":
			// vless://uuid@host:port?type=network&path=path#name
			link := fmt.Sprintf("vless://%s@%s:%d?type=%s&path=%s#%s", s.UUID, s.Host, s.Port, s.Network, s.Path, s.Name)
			links = append(links, link)
		}
	}
	return base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n")))
}

// GenerateClashConfig generates Clash compatible YAML configuration for subscriptions.
func (v *V2BoardSubscription) GenerateClashConfig(servers []V2BoardServer) string {
	var yaml strings.Builder
	yaml.WriteString("proxies:\n")
	for _, s := range servers {
		yaml.WriteString(fmt.Sprintf("  - name: \"%s\"\n", s.Name))
		switch s.Type {
		case "ss":
			yaml.WriteString("    type: ss\n")
			yaml.WriteString(fmt.Sprintf("    server: %s\n", s.Host))
			yaml.WriteString(fmt.Sprintf("    port: %d\n", s.Port))
			yaml.WriteString(fmt.Sprintf("    cipher: %s\n", s.Cipher))
			yaml.WriteString(fmt.Sprintf("    password: \"%s\"\n", s.Password))
		case "trojan":
			yaml.WriteString("    type: trojan\n")
			yaml.WriteString(fmt.Sprintf("    server: %s\n", s.Host))
			yaml.WriteString(fmt.Sprintf("    port: %d\n", s.Port))
			yaml.WriteString(fmt.Sprintf("    password: \"%s\"\n", s.Password))
			if s.Sni != "" {
				yaml.WriteString(fmt.Sprintf("    sni: %s\n", s.Sni))
			}
		case "vmess":
			yaml.WriteString("    type: vmess\n")
			yaml.WriteString(fmt.Sprintf("    server: %s\n", s.Host))
			yaml.WriteString(fmt.Sprintf("    port: %d\n", s.Port))
			yaml.WriteString(fmt.Sprintf("    uuid: %s\n", s.UUID))
			yaml.WriteString("    alterId: 0\n")
			yaml.WriteString("    cipher: auto\n")
			if s.Network != "" {
				yaml.WriteString(fmt.Sprintf("    network: %s\n", s.Network))
			}
			if s.Path != "" {
				yaml.WriteString("    ws-opts:\n")
				yaml.WriteString(fmt.Sprintf("      path: %s\n", s.Path))
			}
			if s.TLS {
				yaml.WriteString("    tls: true\n")
				if s.Sni != "" {
					yaml.WriteString(fmt.Sprintf("    sni: %s\n", s.Sni))
				}
			}
		}
	}
	return yaml.String()
}
