// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: Tools-main / nova-backend
// Target path: server/internal/proxy/nova_backend.go

package proxy

// NovaBackendWrapper wraps NovaBackend.
type NovaBackendWrapper struct {
	Backend *NovaBackend
}

// NewNovaBackendWrapper initializes the wrapper.
func NewNovaBackendWrapper() *NovaBackendWrapper {
	return &NovaBackendWrapper{
		Backend: NewNovaBackend(),
	}
}
