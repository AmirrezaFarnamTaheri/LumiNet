package sub

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"strings"

	"github.com/maybeknott/luminet/internal/foundation/textconfusables"
	"github.com/maybeknott/luminet/internal/networking/geoip"
	"github.com/maybeknott/luminet/internal/networking/proxyconfig"
)

// FilterSafeProxyConfig applies the secure-by-default subscription admission
// policy. TLS verification bypass is rejected unless the caller explicitly
// opts in through SubscriptionFilters.AllowInsecureTLS.
func FilterSafeProxyConfig(cfg *proxyconfig.ProxyConfig) bool {
	return filterSafeProxyConfig(cfg, false)
}

func filterSafeProxyConfig(cfg *proxyconfig.ProxyConfig, allowInsecureTLS bool) bool {
	if cfg == nil || strings.TrimSpace(cfg.Address) == "" {
		return false
	}
	if cfg.SkipCertVerify && !allowInsecureTLS {
		return false
	}

	if ip := net.ParseIP(cfg.Address); ip != nil {
		if ip.IsUnspecified() || geoip.IsLocalOrLanIP(cfg.Address) {
			return false
		}
	}
	hostLower := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(cfg.Address), "."))
	// Homograph defence: subscription-supplied hostnames with non-ASCII
	// or confusable runes dial somewhere else than they display.
	for _, hostField := range []string{cfg.Address, cfg.SNI, cfg.Host} {
		if bad, why := textconfusables.SuspiciousHostname(strings.TrimSpace(hostField)); bad {
			_ = why
			return false
		}
	}
	if hostLower == "localhost" || strings.HasSuffix(hostLower, ".local") {
		return false
	}
	return true
}

func dedupeProxyConfigs(configs []*proxyconfig.ProxyConfig) []*proxyconfig.ProxyConfig {
	seen := make(map[string]struct{}, len(configs))
	out := make([]*proxyconfig.ProxyConfig, 0, len(configs))
	for _, cfg := range configs {
		if cfg == nil {
			continue
		}
		key := proxySemanticKey(cfg)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, cfg)
	}
	return out
}

func proxySemanticKey(cfg *proxyconfig.ProxyConfig) string {
	clone := cloneProxyIdentity(cfg, make(map[*proxyconfig.ProxyConfig]bool))
	payload, err := json.Marshal(clone)
	if err != nil {
		// ProxyConfig is JSON-serializable by contract. If that changes, fall
		// back to a deterministic per-instance key rather than silently
		// collapsing unrelated configs.
		return string(cfg.Protocol) + "\x00" + cfg.Address + "\x00" + cfg.RawURI
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func cloneProxyIdentity(cfg *proxyconfig.ProxyConfig, active map[*proxyconfig.ProxyConfig]bool) *proxyconfig.ProxyConfig {
	if cfg == nil || active[cfg] {
		return nil
	}
	active[cfg] = true
	defer delete(active, cfg)
	clone := *cfg
	clone.Name = ""
	clone.RawURI = ""
	clone.Detour = cloneProxyIdentity(cfg.Detour, active)
	return &clone
}
