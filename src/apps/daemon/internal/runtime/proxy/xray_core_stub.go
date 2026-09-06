//go:build !embed_cores

package proxy

import (
	"fmt"
)

// XrayEmbeddedCore is a stub implementation when native embedding is disabled.
type XrayEmbeddedCore struct{}

// NewXrayEmbeddedCore instantiates a stub XrayEmbeddedCore.
func NewXrayEmbeddedCore() *XrayEmbeddedCore {
	return &XrayEmbeddedCore{}
}

// Start returns an error indicating that embed_cores build tag must be enabled.
func (x *XrayEmbeddedCore) Start(configJSON []byte) error {
	return fmt.Errorf("native xray embedding is disabled; compile with --tags embed_cores to enable")
}

// Close is a no-op when native embedding is disabled.
func (x *XrayEmbeddedCore) Close() error {
	return nil
}
