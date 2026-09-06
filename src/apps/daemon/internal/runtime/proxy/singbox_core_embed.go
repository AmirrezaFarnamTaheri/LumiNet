//go:build embed_cores

package proxy

import (
	"context"
	"encoding/json"
	"fmt"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
)

// SingboxEmbeddedCore manages an in-process natively embedded sing-box instance.
type SingboxEmbeddedCore struct {
	instance *box.Instance
}

// NewSingboxEmbeddedCore instantiates a new SingboxEmbeddedCore.
func NewSingboxEmbeddedCore() *SingboxEmbeddedCore {
	return &SingboxEmbeddedCore{}
}

// Start launches the in-process sing-box instance using the given JSON config options.
func (s *SingboxEmbeddedCore) Start(ctx context.Context, configJSON []byte) error {
	var opt option.Options
	if err := json.Unmarshal(configJSON, &opt); err != nil {
		return fmt.Errorf("invalid sing-box JSON config: %w", err)
	}

	instance, err := box.NewInstance(ctx, opt)
	if err != nil {
		return fmt.Errorf("failed to create sing-box instance: %w", err)
	}

	if err := instance.Start(); err != nil {
		return fmt.Errorf("failed to start sing-box instance: %w", err)
	}

	s.instance = instance
	return nil
}

// Close stops and terminates the in-process sing-box instance.
func (s *SingboxEmbeddedCore) Close() error {
	if s.instance != nil {
		err := s.instance.Close()
		s.instance = nil
		return err
	}
	return nil
}
