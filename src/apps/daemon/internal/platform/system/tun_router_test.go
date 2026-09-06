package system

import (
	"context"
	"errors"
	"io"
	"testing"
)

func TestTunRouterManagerRejectsUnavailableDevice(t *testing.T) {
	mgr := NewTunRouterManager()

	if mgr.IsRunning() {
		t.Errorf("Expected TUN router manager to be idle initially")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr.deviceFactory = func(string) (io.ReadWriteCloser, error) {
		return nil, errors.New("TUN unavailable")
	}
	if _, err := mgr.startWithLease(ctx, "wintun0", "127.0.0.1:1080", nil); err == nil {
		t.Fatal("expected unavailable device error")
	}
	if mgr.IsRunning() {
		t.Fatal("unavailable device must not report running")
	}
	deviceName, proxyAddress, _ := mgr.GetDeviceDetails()
	if deviceName != "" || proxyAddress != "" {
		t.Fatalf("failed bind leaked device state: %q %q", deviceName, proxyAddress)
	}
}

type testTunDevice struct{ closed bool }

func (*testTunDevice) Read([]byte) (int, error)    { return 0, io.EOF }
func (*testTunDevice) Write(p []byte) (int, error) { return len(p), nil }
func (d *testTunDevice) Close() error              { d.closed = true; return nil }

type testCloser struct{ closed bool }

func (c *testCloser) Close() error { c.closed = true; return nil }

func TestTunRouterRouteFailureIsFailClosed(t *testing.T) {
	mgr := NewTunRouterManager()
	dev := &testTunDevice{}
	mgr.deviceFactory = func(string) (io.ReadWriteCloser, error) { return dev, nil }
	mgr.planRoutes = func(context.Context, string, string) (*tunRouteLease, error) {
		return nil, errors.New("route unavailable")
	}
	if _, err := mgr.startWithLease(context.Background(), "wintun0", "127.0.0.1:1080", nil); err == nil {
		t.Fatal("want route failure")
	}
	if mgr.IsRunning() {
		t.Fatal("route failure reported running")
	}
	if !dev.closed {
		t.Fatal("device not released")
	}
}

func TestTunRouterDNSFailureRollsBackRoutes(t *testing.T) {
	mgr := NewTunRouterManager()
	dev := &testTunDevice{}
	removed := false
	mgr.deviceFactory = func(string) (io.ReadWriteCloser, error) { return dev, nil }
	mgr.planRoutes = func(context.Context, string, string) (*tunRouteLease, error) {
		return &tunRouteLease{DeviceName: "wintun0"}, nil
	}
	mgr.applyRoutes = func(context.Context, *tunRouteLease) error { return nil }
	mgr.removeRoutes = func(context.Context, *tunRouteLease) error { removed = true; return nil }
	mgr.enableDNS = func(context.Context, string) error { return errors.New("dns protection failed") }
	mgr.disableDNS = func(context.Context) error { return nil }
	if _, err := mgr.startWithLease(context.Background(), "wintun0", "127.0.0.1:1080", nil); err == nil {
		t.Fatal("want DNS failure")
	}
	if !removed || !dev.closed {
		t.Fatalf("cleanup missing removed=%v closed=%v", removed, dev.closed)
	}
	if mgr.IsRunning() {
		t.Fatal("DNS failure reported running")
	}
}
