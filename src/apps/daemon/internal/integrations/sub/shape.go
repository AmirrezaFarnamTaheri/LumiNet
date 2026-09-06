package sub

import (
	"fmt"
	"strings"

	"github.com/maybeknott/luminet/internal/networking/proxyconfig"
)

func ShapeProxyConfig(template *proxyconfig.ProxyConfig, cleanIPs []string, nameTemplate string) ([]*proxyconfig.ProxyConfig, error) {
	if template == nil {
		return nil, fmt.Errorf("template proxy config is required")
	}
	out := make([]*proxyconfig.ProxyConfig, 0, len(cleanIPs))
	original := template.Address
	for _, rawIP := range cleanIPs {
		ip := strings.TrimSpace(rawIP)
		if ip == "" {
			continue
		}
		cfg := *template
		cfg.ALPN = append([]string(nil), template.ALPN...)
		cfg.LocalAddress = append([]string(nil), template.LocalAddress...)
		cfg.Reserved = append([]int(nil), template.Reserved...)
		cfg.Address = ip
		if cfg.SNI == "" && template.TLS {
			cfg.SNI = original
		}
		if cfg.Host == "" && (template.Transport == "ws" || template.Transport == "h2" || template.Transport == "httpupgrade" || template.Transport == "http") {
			cfg.Host = original
		}
		if nameTemplate != "" {
			cfg.Name = strings.NewReplacer("{name}", template.Name, "{ip}", ip).Replace(nameTemplate)
		} else {
			cfg.Name = fmt.Sprintf("%s - %s", template.Name, ip)
		}
		out = append(out, &cfg)
	}
	return out, nil
}
