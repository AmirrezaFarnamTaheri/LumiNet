package proxy

import (
	"errors"
	"testing"

	"github.com/maybeknott/luminet/internal/networking/proxyconfig"
)

type fakeSubscriptionInstance struct {
	running bool
	stopErr error
	stops   int
}

func (f *fakeSubscriptionInstance) Stop() error {
	f.stops++
	if f.stopErr != nil {
		return f.stopErr
	}
	f.running = false
	return nil
}
func (f *fakeSubscriptionInstance) IsRunning() bool { return f.running }

func testSubscriptionRuntime() (*SubscriptionRuntime, *[]*fakeSubscriptionInstance) {
	created := []*fakeSubscriptionInstance{}
	rt := newSubscriptionRuntime(func(_ *proxyconfig.ProxyConfig, _ int) (subscriptionRuntimeInstance, error) {
		inst := &fakeSubscriptionInstance{running: true}
		created = append(created, inst)
		return inst, nil
	})
	return rt, &created
}

func TestSubscriptionRuntimeOwnsExactlyOneNodeAndRequiresExactStopOwner(t *testing.T) {
	rt, made := testSubscriptionRuntime()
	cfg := &proxyconfig.ProxyConfig{Protocol: proxyconfig.ProtocolVLESS, Address: "one.example", Port: 443, UUID: "secret"}
	status, err := rt.Activate("p1", "n1", cfg, 10808)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Active || status.ProfileID != "p1" || status.NodeID != "n1" || status.SocksPort != 10808 {
		t.Fatalf("status=%+v", status)
	}
	if _, err := rt.Activate("p1", "n2", cfg, 10809); err == nil {
		t.Fatal("running node was silently replaced")
	}
	if err := rt.Stop("p1", "stale"); err == nil {
		t.Fatal("stale stop accepted")
	}
	if (*made)[0].stops != 0 {
		t.Fatal("stale stop touched process")
	}
	if err := rt.Stop("p1", "n1"); err != nil {
		t.Fatal(err)
	}
	if rt.Status().Active {
		t.Fatal("runtime remained active after exact stop")
	}
}

func TestSubscriptionRuntimeValidatesPortAndPublishesOnlySuccessfulStart(t *testing.T) {
	starts := 0
	rt := newSubscriptionRuntime(func(_ *proxyconfig.ProxyConfig, _ int) (subscriptionRuntimeInstance, error) {
		starts++
		return nil, errors.New("start failed")
	})
	cfg := &proxyconfig.ProxyConfig{Protocol: proxyconfig.ProtocolVLESS, Address: "one.example", Port: 443, UUID: "secret"}
	if _, err := rt.Activate("p1", "n1", cfg, 80); err == nil {
		t.Fatal("privileged port accepted")
	}
	if starts != 0 {
		t.Fatal("invalid port reached starter")
	}
	if _, err := rt.Activate("p1", "n1", cfg, 10808); err == nil {
		t.Fatal("start failure hidden")
	}
	if rt.Status().Active {
		t.Fatal("failed start published ownership")
	}
}

func TestSubscriptionRuntimeStopFailureRetainsOwnership(t *testing.T) {
	inst := &fakeSubscriptionInstance{running: true, stopErr: errors.New("cannot stop")}
	rt := newSubscriptionRuntime(func(_ *proxyconfig.ProxyConfig, _ int) (subscriptionRuntimeInstance, error) { return inst, nil })
	cfg := &proxyconfig.ProxyConfig{Protocol: proxyconfig.ProtocolVLESS, Address: "one.example", Port: 443, UUID: "secret"}
	if _, err := rt.Activate("p1", "n1", cfg, 10808); err != nil {
		t.Fatal(err)
	}
	if err := rt.Stop("p1", "n1"); err == nil {
		t.Fatal("stop failure hidden")
	}
	if !rt.Status().Active {
		t.Fatal("ownership cleared after failed stop")
	}
}

func TestSubscriptionRuntimeReapsDeadInstanceBeforeReplacement(t *testing.T) {
	first := &fakeSubscriptionInstance{running: false}
	second := &fakeSubscriptionInstance{running: true}
	calls := 0
	rt := newSubscriptionRuntime(func(_ *proxyconfig.ProxyConfig, _ int) (subscriptionRuntimeInstance, error) {
		calls++
		if calls == 1 {
			return first, nil
		}
		return second, nil
	})
	cfg := &proxyconfig.ProxyConfig{Protocol: proxyconfig.ProtocolVLESS, Address: "one.example", Port: 443, UUID: "secret"}
	if _, err := rt.Activate("p1", "n1", cfg, 10808); err != nil {
		t.Fatal(err)
	}
	if _, err := rt.Activate("p1", "n2", cfg, 10809); err != nil {
		t.Fatalf("dead runtime wedged replacement: %v", err)
	}
	st := rt.Status()
	if st.NodeID != "n2" || !st.Active {
		t.Fatalf("status=%+v", st)
	}
}
