package proxy

import "strings"

// ResolveDNS resolves host through the evasion runtime's configured resolver
// and returns a comma-separated list for compatibility with mobile bindings.
func ResolveDNS(host string) string {
	manager := GetEvasionManager()
	resolver := ""
	if manager != nil {
		if cfg := manager.config.Load(); cfg != nil {
			resolver = cfg.DnsResolver
		}
	}
	ips, err := resolveHostsSecurely(host, resolver)
	if err != nil {
		return ""
	}
	return strings.Join(ips, ",")
}
