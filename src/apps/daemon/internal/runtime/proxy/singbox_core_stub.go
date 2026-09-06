//go:build !embed_cores

package proxy

import (
	"context"
	"fmt"
)

// SingboxEmbeddedCore is a stub implementation when native embedding is disabled.
type SingboxEmbeddedCore struct{}

// NewSingboxEmbeddedCore instantiates a stub SingboxEmbeddedCore.
func NewSingboxEmbeddedCore() *SingboxEmbeddedCore {
	return &SingboxEmbeddedCore{}
}

// Start returns an error indicating that embed_cores build tag must be enabled.
func (s *SingboxEmbeddedCore) Start(ctx context.Context, configJSON []byte) error {
	return fmt.Errorf("native sing-box embedding is disabled; compile with --tags embed_cores to enable")
}

// Close is a no-op when native embedding is disabled.
func (s *SingboxEmbeddedCore) Close() error {
	return nil
}
