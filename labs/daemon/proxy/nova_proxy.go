// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: Nova-Proxy-main
// Target path: server/internal/proxy/nova_proxy.go

package proxy

// NovaProxyWrapper wraps NovaProxy for Cloudflare workers.
type NovaProxyWrapper struct {
	Proxy *NovaProxy
}

// NewNovaProxyWrapper initializes the wrapper.
func NewNovaProxyWrapper() *NovaProxyWrapper {
	return &NovaProxyWrapper{
		Proxy: NewNovaProxy(),
	}
}
