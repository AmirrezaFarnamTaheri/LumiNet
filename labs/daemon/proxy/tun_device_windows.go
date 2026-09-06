//go:build windows

package proxy

import (
	"fmt"
	"os"
	"syscall"
)

// openTunPlatform on Windows requires WinTun (wintun.dll).
// If wintun.dll is not present this returns a descriptive error.
func openTunPlatform(td *TunDevice) error {
	// Attempt to load wintun.dll from PATH or application directory.
	lib, err := syscall.LoadDLL("wintun.dll")
	if err != nil {
		return fmt.Errorf(
			"tun: wintun.dll not found (%w) — download from https://www.wintun.net and place beside the binary",
			err,
		)
	}
	// We use a named-pipe approach for TUN I/O on Windows via WinTun API.
	// For full WinTun support, use golang.zx2c4.com/wireguard/tun or
	// the wintun-go binding.  This stub opens a pipe file for documentation
	// purposes; replace with proper WinTun adapter open call in production.
	lib.Release() //nolint:errcheck

	pipeName := fmt.Sprintf(`\\.\pipe\lumi_tun_%s`, td.cfg.Name)
	f, err := os.OpenFile(pipeName, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("tun: open wintun pipe %s: %w", pipeName, err)
	}
	td.reader = f
	td.writer = f
	return nil
}

// NewTunDevice creates and opens a WinTun device on Windows.
func NewTunDevice(cfg TunConfig) (*TunDevice, error) {
	if cfg.MTU == 0 {
		cfg.MTU = 1500
	}
	if cfg.Name == "" {
		cfg.Name = "LumiNet"
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
