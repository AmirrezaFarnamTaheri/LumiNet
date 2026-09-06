//go:build linux

package proxy

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	tunIfNameSize = 16
	tunSetIFF     = 0x400454ca // TUNSETIFF ioctl
	tunIFFTun     = 0x0001     // IFF_TUN
	tunIFFNoPi    = 0x1000     // IFF_NO_PI
)

type ifReq struct {
	Name  [tunIfNameSize]byte
	Flags uint16
	pad   [22]byte
}

// openTunPlatform opens /dev/net/tun on Linux and configures it.
func openTunPlatform(td *TunDevice) error {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("tun: open /dev/net/tun: %w", err)
	}

	var req ifReq
	copy(req.Name[:], td.cfg.Name)
	req.Flags = tunIFFTun | tunIFFNoPi

	if _, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		f.Fd(),
		tunSetIFF,
		uintptr(unsafe.Pointer(&req)),
	); errno != 0 {
		f.Close()
		return fmt.Errorf("tun: TUNSETIFF: %w", errno)
	}

	td.reader = f
	td.writer = f
	return nil
}

// NewTunDevice creates and opens a TUN device on Linux.
func NewTunDevice(cfg TunConfig) (*TunDevice, error) {
	if cfg.MTU == 0 {
		cfg.MTU = 1500
	}
	if cfg.Name == "" {
		cfg.Name = "lumi0"
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
