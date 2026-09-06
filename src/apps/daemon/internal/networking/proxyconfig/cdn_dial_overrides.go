package proxyconfig

// CDNDialOverrides holds custom IP and SNI dial parameters for CDN fronting.
//
// Restored 2026-08-24: the pre-consolidation implementation lived in
// server/internal/proxy/cdn_fronting.go, whose bulk was correctly retired as
// zero-consumer, but this pure value-builder remained reachable through
// internal/adapters/api HandleCDNFronting and moved here, next to the
// subscription/proxy configuration types it feeds.
type CDNDialOverrides struct {
	CustomIPList string `json:"custom_ip_list"`
	CustomSNI    string `json:"custom_sni"`
}

// BuildCDNDialOverrides returns a CDNDialOverrides struct from the given IP list and SNI strings.
func BuildCDNDialOverrides(customIPList, customSNI string) *CDNDialOverrides {
	return &CDNDialOverrides{
		CustomIPList: customIPList,
		CustomSNI:    customSNI,
	}
}
