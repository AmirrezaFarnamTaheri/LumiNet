package dns

import "strings"

var dohBlockedDomains = map[string]struct{}{
	"doubleclick.net": {}, "google-analytics.com": {}, "analytics.google.com": {},
	"telemetry.microsoft.com": {}, "stats.g.doubleclick.net": {},
}

func IsDoHBlockedDomain(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	for blocked := range dohBlockedDomains {
		if domain == blocked || strings.HasSuffix(domain, "."+blocked) {
			return true
		}
	}
	return false
}
