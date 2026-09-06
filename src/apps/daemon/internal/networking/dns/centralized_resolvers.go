package dns

import "strings"

// centralizedDNSResolvers lists well-known centralized resolver anycast
// addresses that must never be used as tunnel exits.
var centralizedDNSResolvers = map[string]struct{}{
	"8.8.8.8": {}, "8.8.4.4": {},
	"1.1.1.1": {}, "1.0.0.1": {},
	"9.9.9.9": {}, "9.9.9.10": {},
	"149.112.112.10": {}, "149.112.112.112": {},
	"208.67.222.123": {}, "208.67.220.123": {},
	"208.67.222.222": {}, "208.67.220.220": {},
	"4.2.2.1": {}, "4.2.2.2": {}, "4.2.2.3": {},
	"4.2.2.4": {}, "4.2.2.5": {}, "4.2.2.6": {},
}

// IsCentralizedDNSResolver returns true if the given IP address matches a
// centralized DNS resolver. Sourced from ansible-relayor-master dns resolver
// blacklist to prevent DNS correlation; behavior is byte-for-byte compatible
// with the pre-consolidation server/internal/dns/blocklists.go implementation
// (restored 2026-08-24 after its companion test survived the move).
func IsCentralizedDNSResolver(ip string) bool {
	if _, ok := centralizedDNSResolvers[ip]; ok {
		return true
	}

	if strings.HasPrefix(ip, "2001:4860:4860:") {
		return strings.HasSuffix(ip, ":8888") || strings.HasSuffix(ip, ":8844")
	}
	if strings.HasPrefix(ip, "2620:119:35:") && strings.HasSuffix(ip, ":35") {
		return true
	}
	if strings.HasPrefix(ip, "2620:119:53:") && strings.HasSuffix(ip, ":53") {
		return true
	}
	if strings.HasPrefix(ip, "2606:4700:4700:") {
		return strings.HasSuffix(ip, ":1111") || strings.HasSuffix(ip, ":1001")
	}
	if strings.HasPrefix(ip, "2620:fe:") {
		return strings.HasSuffix(ip, ":fe") || strings.HasSuffix(ip, ":9") || strings.HasSuffix(ip, ":10") || strings.HasSuffix(ip, ":fe:10")
	}

	return false
}
