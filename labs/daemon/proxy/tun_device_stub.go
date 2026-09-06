//go:build !linux && !windows

package proxy

import (
	"errors"
)

// errTunUnsupported is returned on platforms where TUN creation is not supported.
var errTunUnsupported = errors.New("tun: device creation is not supported on this platform")

// openTunPlatform returns an error on unsupported platforms.
func openTunPlatform(td *TunDevice) error {
	return errTunUnsupported
}

// NewTunDevice creates a TunDevice struct but does not open the OS interface.
// On unsupported platforms Open() will return errTunUnsupported.
func NewTunDevice(cfg TunConfig) (*TunDevice, error) {
	if cfg.MTU == 0 {
		cfg.MTU = 1500
	}
	td := &TunDevice{
		cfg:   cfg,
		flows: make(map[TunFlowKey]*TunFlowEntry),
	}
	td.initFilter()
	if err := openTunPlatform(td); err != nil {
		return nil, err
	}
	return td, nil
}
