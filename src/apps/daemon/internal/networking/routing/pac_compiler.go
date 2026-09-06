package routing

import (
	"fmt"
	"net"
	"strings"
)

// PacProxyMode defines the proxy instruction string in PAC format.
type PacProxyMode string

const (
	PacDirect PacProxyMode = "DIRECT"
)

// PacScriptCompiler manages domain matching sets, CIDRs, and PAC script synthesis.
type PacScriptCompiler struct {
	directDomains  map[string]struct{}
	proxyDomains   map[string]struct{}
	cnPrefixes     []*net.IPNet
	defaultProxy   string
}

func NewPacScriptCompiler(defaultProxy string) *PacScriptCompiler {
	return &PacScriptCompiler{
		directDomains: make(map[string]struct{}),
		proxyDomains:  make(map[string]struct{}),
		cnPrefixes:    make([]*net.IPNet, 0),
		defaultProxy:  defaultProxy,
	}
}

func (p *PacScriptCompiler) AddDirectDomain(domain string) {
	clean := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(domain), "."))
	if clean != "" {
		p.directDomains[clean] = struct{}{}
	}
}

func (p *PacScriptCompiler) AddProxyDomain(domain string) {
	clean := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(domain), "."))
	if clean != "" {
		p.proxyDomains[clean] = struct{}{}
	}
}

func (p *PacScriptCompiler) AddCnCidr(cidr string) error {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	p.cnPrefixes = append(p.cnPrefixes, ipnet)
	return nil
}

func (p *PacScriptCompiler) EvaluateDomain(domain string) string {
	lower := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(domain), "."))
	if _, ok := p.directDomains[lower]; ok {
		return string(PacDirect)
	}
	if _, ok := p.proxyDomains[lower]; ok {
		return fmt.Sprintf("PROXY %s", p.defaultProxy)
	}

	// Suffix checking
	parts := strings.Split(lower, ".")
	for i := 1; i < len(parts); i++ {
		sub := strings.Join(parts[i:], ".")
		if _, ok := p.directDomains[sub]; ok {
			return string(PacDirect)
		}
		if _, ok := p.proxyDomains[sub]; ok {
			return fmt.Sprintf("PROXY %s", p.defaultProxy)
		}
	}

	return fmt.Sprintf("PROXY %s", p.defaultProxy)
}

func (p *PacScriptCompiler) EvaluateIP(ip net.IP) string {
	for _, prefix := range p.cnPrefixes {
		if prefix.Contains(ip) {
			return string(PacDirect)
		}
	}
	return fmt.Sprintf("PROXY %s", p.defaultProxy)
}

func (p *PacScriptCompiler) CompilePacScript() string {
	var sb strings.Builder
	sb.WriteString("// LumiNet PAC Engine\n")
	sb.WriteString(fmt.Sprintf("var proxy = 'PROXY %s';\n", p.defaultProxy))
	sb.WriteString("var direct = 'DIRECT';\n\n")
	sb.WriteString("function FindProxyForURL(url, host) {\n")
	sb.WriteString("  if (isPlainHostName(host) || host === '127.0.0.1') return direct;\n")
	for d := range p.directDomains {
		sb.WriteString(fmt.Sprintf("  if (dnsDomainIs(host, '%s')) return direct;\n", d))
	}
	for d := range p.proxyDomains {
		sb.WriteString(fmt.Sprintf("  if (dnsDomainIs(host, '%s')) return proxy;\n", d))
	}
	sb.WriteString("  return proxy;\n")
	sb.WriteString("}\n")
	return sb.String()
}
