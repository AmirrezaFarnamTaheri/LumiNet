//go:build embed_cores

package proxy

import (
	"encoding/json"
	"fmt"

	xray "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
)

// XrayEmbeddedCore manages an in-process natively embedded Xray-core instance.
type XrayEmbeddedCore struct {
	instance *xray.Instance
}

// NewXrayEmbeddedCore instantiates a new XrayEmbeddedCore.
func NewXrayEmbeddedCore() *XrayEmbeddedCore {
	return &XrayEmbeddedCore{}
}

// Start launches the in-process Xray-core instance using the given JSON config.
func (x *XrayEmbeddedCore) Start(configJSON []byte) error {
	var c conf.Config
	if err := json.Unmarshal(configJSON, &c); err != nil {
		return fmt.Errorf("invalid xray JSON config: %w", err)
	}

	pbConfig, err := c.Build()
	if err != nil {
		return fmt.Errorf("failed to build xray proto config: %w", err)
	}

	instance, err := xray.New(pbConfig)
	if err != nil {
		return fmt.Errorf("failed to create xray instance: %w", err)
	}

	if err := instance.Start(); err != nil {
		return fmt.Errorf("failed to start xray instance: %w", err)
	}

	x.instance = instance
	return nil
}

// Close stops and terminates the in-process Xray instance.
func (x *XrayEmbeddedCore) Close() error {
	if x.instance != nil {
		err := x.instance.Close()
		x.instance = nil
		return err
	}
	return nil
}
