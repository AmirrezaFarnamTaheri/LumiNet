package system

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReleaseRouteRestoresExactOriginalProxy(t *testing.T) {
	dir := t.TempDir()
	original := ProxySettings{Enabled: true, Server: "old.example:8080", Bypass: "localhost;intranet", PACURL: "https://pac.example/pac.js"}
	f := &fakeHost{dns: map[string][]string{}, proxy: original}
	m := newHostNetworkManager(dir, fakeHostOps(f))
	active := HostNetworkChange{Kind: HostNetworkChangeRoute, RouteMode: HostRouteProxy, Proxy: ProxySettings{Enabled: true, Server: "127.0.0.1:19080", Bypass: "<local>"}}
	if err := m.Apply(context.Background(), active); err != nil {
		t.Fatal(err)
	}
	if err := m.ReleaseRoute(context.Background(), active); err != nil {
		t.Fatal(err)
	}
	if !proxySettingsEqual(f.proxy, original) {
		t.Fatalf("restored proxy=%+v want %+v", f.proxy, original)
	}
	if _, err := os.Stat(filepath.Join(dir, "host-network-session.json")); !os.IsNotExist(err) {
		t.Fatalf("session remains: %v", err)
	}
}

func TestReleaseRouteRejectsStaleExpectedOwner(t *testing.T) {
	dir := t.TempDir()
	f := &fakeHost{dns: map[string][]string{}, proxy: ProxySettings{}}
	m := newHostNetworkManager(dir, fakeHostOps(f))
	active := HostNetworkChange{Kind: HostNetworkChangeRoute, RouteMode: HostRouteProxy, Proxy: ProxySettings{Enabled: true, Server: "127.0.0.1:19080", Bypass: "<local>"}}
	if err := m.Apply(context.Background(), active); err != nil {
		t.Fatal(err)
	}
	stale := active
	stale.Proxy.Server = "127.0.0.1:19081"
	if err := m.ReleaseRoute(context.Background(), stale); err == nil {
		t.Fatal("expected stale-owner rejection")
	}
	if _, err := os.Stat(filepath.Join(dir, "host-network-session.json")); err != nil {
		t.Fatalf("session should remain: %v", err)
	}
}

func TestReleaseRouteRejectsPartialExternalProxyTakeover(t *testing.T) {
	dir := t.TempDir()
	f := &fakeHost{dns: map[string][]string{}, proxy: ProxySettings{}}
	m := newHostNetworkManager(dir, fakeHostOps(f))
	active := HostNetworkChange{Kind: HostNetworkChangeRoute, RouteMode: HostRouteProxy, Proxy: ProxySettings{Enabled: true, Server: "127.0.0.1:19080", Bypass: "<local>"}}
	if err := m.Apply(context.Background(), active); err != nil {
		t.Fatal(err)
	}
	f.proxy.Bypass = "external-change"
	if err := m.ReleaseRoute(context.Background(), active); err == nil {
		t.Fatal("expected external takeover rejection")
	}
	if got := f.proxy.Bypass; got != "external-change" {
		t.Fatalf("external bypass was clobbered: %q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "host-network-session.json")); err != nil {
		t.Fatalf("session should remain: %v", err)
	}
}

func TestReleaseRouteKeepsRecoveryRecordWhenRestoreFails(t *testing.T) {
	dir := t.TempDir()
	original := ProxySettings{Enabled: true, Server: "old.example:8080"}
	f := &fakeHost{dns: map[string][]string{}, proxy: original}
	ops := fakeHostOps(f)
	baseSet := ops.setProxy
	ops.setProxy = func(ctx context.Context, p *ProxySettings) error {
		if p.Enabled && p.Server == original.Server {
			return errors.New("restore denied")
		}
		return baseSet(ctx, p)
	}
	m := newHostNetworkManager(dir, ops)
	active := HostNetworkChange{Kind: HostNetworkChangeRoute, RouteMode: HostRouteProxy, Proxy: ProxySettings{Enabled: true, Server: "127.0.0.1:19080"}}
	if err := m.Apply(context.Background(), active); err != nil {
		t.Fatal(err)
	}
	if err := m.ReleaseRoute(context.Background(), active); err == nil {
		t.Fatal("expected restore failure")
	}
	if _, err := os.Stat(filepath.Join(dir, "host-network-session.json")); err != nil {
		t.Fatalf("recovery record lost: %v", err)
	}
}
