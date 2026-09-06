package system

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type fakeHost struct {
	proxy                ProxySettings
	dns                  map[string][]string
	ncsi                 NCSIConfig
	tun                  bool
	lease                *tunRouteLease
	failVerify           bool
	failRestore          bool
	rollbackSawCancelled bool
}

func fakeHostOps(f *fakeHost) hostNetworkOps {
	return hostNetworkOps{
		getProxy: func(context.Context) (*ProxySettings, error) { p := f.proxy; return &p, nil },
		setProxy: func(ctx context.Context, p *ProxySettings) error {
			if ctx.Err() != nil {
				f.rollbackSawCancelled = true
			}
			if f.failRestore && !p.Enabled {
				return errors.New("restore failed")
			}
			f.proxy = *p
			return nil
		},
		getDNS: func(context.Context, string) ([]string, error) { return append([]string(nil), f.dns["eth0"]...), nil },
		setDNS: func(ctx context.Context, iface string, servers []string) error {
			if ctx.Err() != nil {
				f.rollbackSawCancelled = true
			}
			f.dns[iface] = append([]string(nil), servers...)
			return nil
		},
		getNCSI: func() (*NCSIConfig, error) { n := f.ncsi; return &n, nil },
		setNCSI: func(ctx context.Context, n *NCSIConfig) error {
			if ctx.Err() != nil {
				f.rollbackSawCancelled = true
			}
			f.ncsi = *n
			return nil
		},
		startTun: func(context.Context, string, string, *tunRouteLease) (*tunRouteLease, error) {
			f.tun = true
			l := &tunRouteLease{DeviceName: "wintun0", ProxyAddress: "proxy:1080", Gateway: "192.0.2.1", CreatedProxyIPs: []string{"203.0.113.7"}, DefaultRoute: true}
			f.lease = l
			return l, nil
		},
		stopTun: func(context.Context, *tunRouteLease) error { f.tun = false; f.lease = nil; return nil },
		tunUp:   func() bool { return f.tun },
	}
}

func TestPersistentDNSChangeCommitsAndRemovesRecoveryRecord(t *testing.T) {
	dir := t.TempDir()
	f := &fakeHost{dns: map[string][]string{"eth0": {"1.1.1.1"}}}
	m := newHostNetworkManager(dir, fakeHostOps(f))
	if err := m.Apply(context.Background(), HostNetworkChange{Kind: HostNetworkChangeDNS, DNSInterface: "eth0", DNSServers: []string{"9.9.9.9"}}); err != nil {
		t.Fatal(err)
	}
	if got := f.dns["eth0"]; !reflect.DeepEqual(got, []string{"9.9.9.9"}) {
		t.Fatalf("dns=%v", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "host-network-operation.json")); !os.IsNotExist(err) {
		t.Fatalf("operation record remains: %v", err)
	}
}

func TestFailedPersistentChangeRollsBackWithFreshContext(t *testing.T) {
	dir := t.TempDir()
	f := &fakeHost{dns: map[string][]string{"eth0": {"1.1.1.1"}}}
	ops := fakeHostOps(f)
	origSet := ops.setDNS
	ops.setDNS = func(ctx context.Context, iface string, servers []string) error {
		if len(servers) > 0 && servers[0] == "9.9.9.9" {
			return context.Canceled
		}
		return origSet(ctx, iface, servers)
	}
	m := newHostNetworkManager(dir, ops)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.Apply(ctx, HostNetworkChange{Kind: HostNetworkChangeDNS, DNSInterface: "eth0", DNSServers: []string{"9.9.9.9"}}); err == nil {
		t.Fatal("want failure")
	}
	if got := f.dns["eth0"]; !reflect.DeepEqual(got, []string{"1.1.1.1"}) {
		t.Fatalf("rollback dns=%v", got)
	}
	if f.rollbackSawCancelled {
		t.Fatal("rollback reused cancelled operation context")
	}
}

func TestDNSVerificationFailureRestoresCapturedSnapshot(t *testing.T) {
	dir := t.TempDir()
	f := &fakeHost{dns: map[string][]string{"eth0": {"1.1.1.1"}}}
	ops := fakeHostOps(f)
	reads := 0
	ops.getDNS = func(context.Context, string) ([]string, error) {
		reads++
		if reads == 1 {
			return []string{"1.1.1.1"}, nil // snapshot
		}
		return []string{"203.0.113.53"}, nil // force verification failure
	}
	m := newHostNetworkManager(dir, ops)
	err := m.Apply(context.Background(), HostNetworkChange{
		Kind: HostNetworkChangeDNS, DNSInterface: "eth0", DNSServers: []string{"9.9.9.9"},
	})
	if err == nil {
		t.Fatal("want DNS verification failure")
	}
	if got := f.dns["eth0"]; !reflect.DeepEqual(got, []string{"1.1.1.1"}) {
		t.Fatalf("rollback dns=%v, want captured snapshot", got)
	}
}

func TestSessionKeepsOriginalSnapshotAndExactTunLeaseForRecovery(t *testing.T) {
	dir := t.TempDir()
	f := &fakeHost{dns: map[string][]string{}, proxy: ProxySettings{Enabled: true, Server: "old:8080"}}
	m := newHostNetworkManager(dir, fakeHostOps(f))
	if err := m.Apply(context.Background(), HostNetworkChange{Kind: HostNetworkChangeRoute, RouteMode: HostRouteTun, TunDevice: "wintun0", TunProxy: "proxy:1080"}); err != nil {
		t.Fatal(err)
	}
	if !f.tun {
		t.Fatal("tun not active")
	}
	// Simulate a fresh watchdog process using only the durable record.
	fresh := newHostNetworkManager(dir, fakeHostOps(f))
	if err := fresh.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.tun {
		t.Fatal("tun still active after recovery")
	}
	if !f.proxy.Enabled || f.proxy.Server != "old:8080" {
		t.Fatalf("proxy not restored: %+v", f.proxy)
	}
	if _, err := os.Stat(filepath.Join(dir, "host-network-session.json")); !os.IsNotExist(err) {
		t.Fatalf("session record remains: %v", err)
	}
}

func TestHostNetworkPlanCapturesDNSWithoutMutationOrStateFiles(t *testing.T) {
	dir := t.TempDir()
	f := &fakeHost{dns: map[string][]string{"eth0": {"1.1.1.1"}}}
	m := newHostNetworkManager(dir, fakeHostOps(f))

	plan, err := m.Plan(context.Background(), HostNetworkChange{
		Kind: HostNetworkChangeDNS, DNSInterface: "eth0", DNSServers: []string{"9.9.9.9"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.ApplyAuthorized {
		t.Fatal("preview must never grant apply authority")
	}
	if !plan.RollbackOwned || !plan.CrashRecoverable || !plan.ChangesState {
		t.Fatalf("unexpected plan flags: %+v", plan)
	}
	if got := f.dns["eth0"]; !reflect.DeepEqual(got, []string{"1.1.1.1"}) {
		t.Fatalf("preview mutated DNS: %v", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("preview created state files: %v", entries)
	}
}

func TestHostNetworkPlanUsesDaemonRouteSessionWithoutMutation(t *testing.T) {
	dir := t.TempDir()
	f := &fakeHost{dns: map[string][]string{}, proxy: ProxySettings{Enabled: true, Server: "native:8080"}}
	m := newHostNetworkManager(dir, fakeHostOps(f))
	active := HostNetworkChange{Kind: HostNetworkChangeRoute, RouteMode: HostRouteTun, TunDevice: "wintun0", TunProxy: "127.0.0.1:1080"}
	if err := os.WriteFile(m.sessionPath(), []byte(`{"version":1,"snapshot":{},"active":{"kind":"route","route_mode":"tun","tun_device":"wintun0","tun_proxy":"127.0.0.1:1080"}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	plan, err := m.Plan(context.Background(), HostNetworkChange{Kind: HostNetworkChangeRoute, RouteMode: HostRouteDirect})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plan.Current, active) {
		t.Fatalf("current=%+v want %+v", plan.Current, active)
	}
	if !f.proxy.Enabled || f.proxy.Server != "native:8080" {
		t.Fatalf("preview changed proxy: %+v", f.proxy)
	}
}

func TestHostNetworkPlanRejectsInvalidChangeBeforeObservation(t *testing.T) {
	dir := t.TempDir()
	f := &fakeHost{dns: map[string][]string{}}
	m := newHostNetworkManager(dir, fakeHostOps(f))
	if _, err := m.Plan(context.Background(), HostNetworkChange{Kind: HostNetworkChangeRoute, RouteMode: HostRouteProxy}); err == nil {
		t.Fatal("expected invalid proxy plan to fail")
	}
}

func TestHostNetworkPlanTreatsProxyCompatibilityFieldsSemantically(t *testing.T) {
	dir := t.TempDir()
	f := &fakeHost{dns: map[string][]string{}, proxy: ProxySettings{Enabled: true, Server: "127.0.0.1:1080", Bypass: "localhost"}}
	m := newHostNetworkManager(dir, fakeHostOps(f))
	plan, err := m.Plan(context.Background(), HostNetworkChange{Kind: HostNetworkChangeRoute, RouteMode: HostRouteProxy, Proxy: ProxySettings{Enabled: true, Server: "127.0.0.1:1080", HTTPServer: "127.0.0.1:1080", Bypass: "localhost", BypassList: "localhost"}})
	if err != nil {
		t.Fatal(err)
	}
	if plan.ChangesState {
		t.Fatalf("compatibility-only field duplication reported a mutation: %+v", plan)
	}
}
