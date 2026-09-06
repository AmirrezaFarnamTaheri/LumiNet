package proxyconfig

import (
	"fmt"
	"strings"
)

type ClashProxy struct {
	Name     string
	Type     string
	Server   string
	Port     int
	UUID     string
	Latency  int
}

type ClashProxyGroup struct {
	Name     string
	Type     string
	Proxies  []string
	URL      string
	Interval int
}

type ClashSynthesizer struct {
	MixedPort int
	Proxies   []ClashProxy
	Groups    []ClashProxyGroup
}

func NewClashSynthesizer(mixedPort int) *ClashSynthesizer {
	return &ClashSynthesizer{
		MixedPort: mixedPort,
		Proxies:   make([]ClashProxy, 0),
		Groups:    make([]ClashProxyGroup, 0),
	}
}

func (c *ClashSynthesizer) AddProxy(p ClashProxy) {
	c.Proxies = append(c.Proxies, p)
}

func (c *ClashSynthesizer) AddGroup(g ClashProxyGroup) {
	c.Groups = append(c.Groups, g)
}

func (c *ClashSynthesizer) SynthesizeYAML() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("mixed-port: %d\n", c.MixedPort))
	sb.WriteString("allow-lan: false\n")
	sb.WriteString("mode: rule\n\n")

	sb.WriteString("proxies:\n")
	for _, p := range c.Proxies {
		sb.WriteString(fmt.Sprintf("  - name: \"%s\"\n", p.Name))
		sb.WriteString(fmt.Sprintf("    type: %s\n", p.Type))
		sb.WriteString(fmt.Sprintf("    server: %s\n", p.Server))
		sb.WriteString(fmt.Sprintf("    port: %d\n", p.Port))
		sb.WriteString(fmt.Sprintf("    uuid: %s\n", p.UUID))
	}

	sb.WriteString("\nproxy-groups:\n")
	for _, g := range c.Groups {
		sb.WriteString(fmt.Sprintf("  - name: \"%s\"\n", g.Name))
		sb.WriteString(fmt.Sprintf("    type: %s\n", g.Type))
		sb.WriteString("    proxies:\n")
		for _, px := range g.Proxies {
			sb.WriteString(fmt.Sprintf("      - \"%s\"\n", px))
		}
		if g.Type == "url-test" {
			sb.WriteString(fmt.Sprintf("    url: %s\n", g.URL))
			sb.WriteString(fmt.Sprintf("    interval: %d\n", g.Interval))
		}
	}
	return sb.String()
}
