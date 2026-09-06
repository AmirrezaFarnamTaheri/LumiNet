//go:build !linux

package proxy

import (
	"context"
	"fmt"
)

type stubTcShaper struct{}

func newPlatformTcShaper() TcShaper {
	return &stubTcShaper{}
}

func (s *stubTcShaper) LimitPort(ctx context.Context, iface string, port int, rateKbps int) error {
	return fmt.Errorf("tc shaping is only supported on Linux")
}

func (s *stubTcShaper) ClearPortLimits(ctx context.Context, iface string, port int) error {
	return fmt.Errorf("tc shaping is only supported on Linux")
}

func (s *stubTcShaper) ClearAll(ctx context.Context, iface string) error {
	return fmt.Errorf("tc shaping is only supported on Linux")
}
