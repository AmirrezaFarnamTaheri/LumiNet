package runtimecore

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

type fakeEngine struct {
	running   bool
	startErr  error
	stopStuck bool
	starts    int
	stops     int
}

func (e *fakeEngine) Start() error {
	e.starts++
	if e.startErr != nil {
		return e.startErr
	}
	e.running = true
	return nil
}
func (e *fakeEngine) Stop() {
	e.stops++
	if !e.stopStuck {
		e.running = false
	}
}
func (e *fakeEngine) IsRunning() bool { return e.running }

func TestManagerRejectsUnsupportedGenericEngines(t *testing.T) {
	m := newManagerWithFactory(func(Request) (engine, error) { t.Fatal("factory should not be called"); return nil, nil })
	for _, name := range []Engine{"sing-box", "tailscale", ""} {
		if _, err := m.Start(Request{Engine: name}); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("Start(%q) error=%v, want ErrInvalidRequest", name, err)
		}
	}
}

func TestManagerNormalizesPortsAndIsIdempotent(t *testing.T) {
	created := 0
	var got Request
	eng := &fakeEngine{}
	m := newManagerWithFactory(func(r Request) (engine, error) { created++; got = r; return eng, nil })
	st, err := m.Start(Request{Engine: EngineTor, SocksPort: 12000})
	if err != nil {
		t.Fatal(err)
	}
	if got.SocksPort != 12000 || got.ControlPort != 12001 {
		t.Fatalf("normalized request=%+v", got)
	}
	if !st.Running || st.SocksPort != 12000 {
		t.Fatalf("status=%+v", st)
	}
	if _, err := m.Start(Request{Engine: EngineTor, SocksPort: 12000}); err != nil {
		t.Fatal(err)
	}
	if created != 1 || eng.starts != 1 {
		t.Fatalf("idempotent start created=%d starts=%d", created, eng.starts)
	}
}

func TestManagerReplacesChangedConfiguration(t *testing.T) {
	var engines []*fakeEngine
	m := newManagerWithFactory(func(Request) (engine, error) { e := &fakeEngine{}; engines = append(engines, e); return e, nil })
	if _, err := m.Start(Request{Engine: EnginePsiphon, SocksPort: 10890}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Start(Request{Engine: EnginePsiphon, SocksPort: 12090, UpstreamProxy: "socks5://127.0.0.1:1080"}); err != nil {
		t.Fatal(err)
	}
	if len(engines) != 2 || engines[0].stops != 1 || engines[0].running {
		t.Fatalf("replacement engines=%d old=%+v", len(engines), engines[0])
	}
}

func TestManagerRestoresPreviousConfigurationWhenReplacementStartFails(t *testing.T) {
	current := &fakeEngine{}
	replacement := &fakeEngine{startErr: errors.New("replacement startup failed")}
	restored := &fakeEngine{}
	created := 0
	m := newManagerWithFactory(func(Request) (engine, error) {
		created++
		switch created {
		case 1:
			return current, nil
		case 2:
			return replacement, nil
		case 3:
			return restored, nil
		default:
			t.Fatalf("unexpected factory call %d", created)
			return nil, nil
		}
	})

	if _, err := m.Start(Request{Engine: EnginePsiphon, SocksPort: 10890}); err != nil {
		t.Fatal(err)
	}
	status, err := m.Start(Request{Engine: EnginePsiphon, SocksPort: 12090})
	if err == nil || !strings.Contains(err.Error(), "previous runtime-core psiphon configuration restored") {
		t.Fatalf("replacement error=%v, want restored-configuration error", err)
	}
	if !status.Running || status.SocksPort != 10890 {
		t.Fatalf("status=%+v, want restored previous configuration", status)
	}
	if current.stops != 1 || current.running {
		t.Fatalf("previous engine was not stopped exactly once: %+v", current)
	}
	if replacement.starts != 1 || replacement.stops != 1 || replacement.running {
		t.Fatalf("failed replacement was not cleaned up: %+v", replacement)
	}
	if restored.starts != 1 || !restored.running {
		t.Fatalf("previous configuration was not restarted: %+v", restored)
	}

	got, statusErr := m.Status(EnginePsiphon)
	if statusErr != nil {
		t.Fatal(statusErr)
	}
	if !got.Running || got.SocksPort != 10890 {
		t.Fatalf("authoritative status=%+v, want restored previous configuration", got)
	}
}

func TestManagerReportsReplacementAndRollbackFailure(t *testing.T) {
	current := &fakeEngine{}
	replacement := &fakeEngine{startErr: errors.New("replacement startup failed")}
	created := 0
	m := newManagerWithFactory(func(Request) (engine, error) {
		created++
		switch created {
		case 1:
			return current, nil
		case 2:
			return replacement, nil
		case 3:
			return nil, errors.New("rollback factory failed")
		default:
			t.Fatalf("unexpected factory call %d", created)
			return nil, nil
		}
	})

	if _, err := m.Start(Request{Engine: EnginePsiphon, SocksPort: 10890}); err != nil {
		t.Fatal(err)
	}
	status, err := m.Start(Request{Engine: EnginePsiphon, SocksPort: 12090})
	if err == nil || !strings.Contains(err.Error(), "replacement startup failed") || !strings.Contains(err.Error(), "rollback factory failed") {
		t.Fatalf("replacement error=%v, want both replacement and rollback causes", err)
	}
	if status.Running {
		t.Fatalf("status=%+v, want unavailable after rollback failure", status)
	}
	got, statusErr := m.Status(EnginePsiphon)
	if statusErr != nil {
		t.Fatal(statusErr)
	}
	if got.Running {
		t.Fatalf("authoritative status=%+v, want stopped after rollback failure", got)
	}
}

func TestManagerRejectsFalsePositiveStart(t *testing.T) {
	eng := &fakeEngine{}
	m := newManagerWithFactory(func(Request) (engine, error) { return startButNotRunning{eng}, nil })
	if _, err := m.Start(Request{Engine: EngineTor}); err == nil {
		t.Fatal("Start accepted adapter that is not running")
	}
	st, err := m.Status(EngineTor)
	if err != nil {
		t.Fatal(err)
	}
	if st.Running {
		t.Fatalf("status=%+v", st)
	}
}

type startButNotRunning struct{ *fakeEngine }

func (e startButNotRunning) Start() error { e.starts++; return nil }

func TestManagerStopFailureKeepsAuthoritativeState(t *testing.T) {
	eng := &fakeEngine{stopStuck: true}
	m := newManagerWithFactory(func(Request) (engine, error) { return eng, nil })
	if _, err := m.Start(Request{Engine: EngineTor}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Stop(EngineTor); err == nil {
		t.Fatal("Stop succeeded while adapter remained running")
	}
	st, err := m.Status(EngineTor)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Running {
		t.Fatalf("failed stop lost running state: %+v", st)
	}
}

func TestManagerCloseStopsEveryOwnedEngine(t *testing.T) {
	created := map[Engine]*fakeEngine{}
	m := newManagerWithFactory(func(r Request) (engine, error) { e := &fakeEngine{}; created[r.Engine] = e; return e, nil })
	if _, err := m.Start(Request{Engine: EngineTor}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Start(Request{Engine: EnginePsiphon}); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	for kind, e := range created {
		if e.running || e.stops != 1 {
			t.Fatalf("%s not stopped: %+v", kind, e)
		}
	}
}

func TestManagerTorTransportConfigurationIsPartOfIdentity(t *testing.T) {
	created := 0
	var requests []Request
	var engines []*fakeEngine
	m := newManagerWithFactory(func(r Request) (engine, error) {
		created++
		requests = append(requests, r)
		e := &fakeEngine{}
		engines = append(engines, e)
		return e, nil
	})
	first := Request{
		Engine:           EngineTor,
		Bridges:          []string{"snowflake 192.0.2.1:443 fingerprint"},
		TransportPlugins: []TorTransportPlugin{{Name: "snowflake", Executable: "snowflake-client", Args: []string{"-keep-local-addresses"}}},
	}
	if _, err := m.Start(first); err != nil {
		t.Fatal(err)
	}
	// Mutating caller-owned input must not mutate the manager's authoritative request.
	first.Bridges[0] = "tampered"
	first.TransportPlugins[0].Args[0] = "tampered"
	if requests[0].Bridges[0] == "tampered" || requests[0].TransportPlugins[0].Args[0] == "tampered" {
		t.Fatal("manager retained caller-owned Tor transport slices")
	}

	same := Request{
		Engine:           EngineTor,
		Bridges:          []string{"snowflake 192.0.2.1:443 fingerprint"},
		TransportPlugins: []TorTransportPlugin{{Name: "snowflake", Executable: "snowflake-client", Args: []string{"-keep-local-addresses"}}},
	}
	if _, err := m.Start(same); err != nil {
		t.Fatal(err)
	}
	if created != 1 {
		t.Fatalf("equivalent Tor transport request restarted engine: created=%d", created)
	}

	changed := same
	changed.Bridges = []string{"webtunnel 198.51.100.1:443 fingerprint url=https://bridge.invalid/"}
	changed.TransportPlugins = []TorTransportPlugin{{Name: "webtunnel", Executable: "webtunnel-client"}}
	if _, err := m.Start(changed); err != nil {
		t.Fatal(err)
	}
	if created != 2 || engines[0].stops != 1 {
		t.Fatalf("changed transport request did not replace engine: created=%d stops=%d", created, engines[0].stops)
	}
}

func TestManagerRejectsInvalidTorTransportBeforeStoppingCurrentEngine(t *testing.T) {
	eng := &fakeEngine{}
	created := 0
	m := newManagerWithFactory(func(Request) (engine, error) { created++; return eng, nil })
	if _, err := m.Start(Request{Engine: EngineTor}); err != nil {
		t.Fatal(err)
	}
	_, err := m.Start(Request{
		Engine:           EngineTor,
		Bridges:          []string{"obfs4 192.0.2.1:443 fingerprint"},
		TransportPlugins: []TorTransportPlugin{{Name: "obfs4\nSocksPort 0", Executable: "obfs4proxy"}},
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("invalid transport error=%v, want ErrInvalidRequest", err)
	}
	if !eng.running || eng.stops != 0 || created != 1 {
		t.Fatalf("invalid replacement disturbed live engine: running=%v stops=%d created=%d", eng.running, eng.stops, created)
	}
}

func TestManagerRejectsTorTransportFieldsOnOtherEngines(t *testing.T) {
	m := newManagerWithFactory(func(Request) (engine, error) { t.Fatal("factory should not be called"); return nil, nil })
	_, err := m.Start(Request{Engine: EnginePsiphon, Bridges: []string{"1.2.3.4:443"}})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("error=%v, want ErrInvalidRequest", err)
	}
}

func TestManagerRejectsArbitraryTorTransportExecutable(t *testing.T) {
	m := newManagerWithFactory(func(Request) (engine, error) { t.Fatal("factory should not be called"); return nil, nil })
	cases := []TorTransportPlugin{
		{Name: "snowflake", Executable: "/tmp/snowflake-client"},
		{Name: "snowflake", Executable: "sh"},
		{Name: "custom", Executable: "custom-client"},
	}
	for _, plugin := range cases {
		_, err := m.Start(Request{Engine: EngineTor, Bridges: []string{"snowflake 192.0.2.1:443 fingerprint"}, TransportPlugins: []TorTransportPlugin{plugin}})
		if !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("plugin %+v error=%v, want ErrInvalidRequest", plugin, err)
		}
	}
}

func TestManagerRejectsUnapprovedTorTransportArguments(t *testing.T) {
	m := newManagerWithFactory(func(Request) (engine, error) { t.Fatal("factory should not be called"); return nil, nil })
	_, err := m.Start(Request{
		Engine:           EngineTor,
		Bridges:          []string{"snowflake 192.0.2.1:443 fingerprint"},
		TransportPlugins: []TorTransportPlugin{{Name: "snowflake", Executable: "snowflake-client", Args: []string{"-log", "/tmp/transport.log"}}},
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("error=%v, want ErrInvalidRequest", err)
	}
}

func TestManagerAllowsNarrowSnowflakeClientArgument(t *testing.T) {
	var got Request
	m := newManagerWithFactory(func(r Request) (engine, error) { got = r; return &fakeEngine{}, nil })
	_, err := m.Start(Request{
		Engine:           EngineTor,
		Bridges:          []string{"snowflake 192.0.2.1:443 fingerprint ice=stun:stun.example:3478"},
		TransportPlugins: []TorTransportPlugin{{Name: "snowflake", Executable: "SNOWFLAKE-CLIENT", Args: []string{"-keep-local-addresses"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.TransportPlugins[0].Executable != "snowflake-client" || len(got.TransportPlugins[0].Args) != 1 || got.TransportPlugins[0].Args[0] != "-keep-local-addresses" {
		t.Fatalf("normalized plugin=%+v", got.TransportPlugins[0])
	}
}

func TestManagerDefaultsRegisteredTorTransportExecutable(t *testing.T) {
	var got Request
	m := newManagerWithFactory(func(r Request) (engine, error) { got = r; return &fakeEngine{}, nil })
	_, err := m.Start(Request{
		Engine:           EngineTor,
		Bridges:          []string{"obfs4 192.0.2.1:443 fingerprint"},
		TransportPlugins: []TorTransportPlugin{{Name: "OBFS4"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.TransportPlugins[0].Name != "obfs4" || got.TransportPlugins[0].Executable != "lyrebird" {
		t.Fatalf("normalized plugin=%+v", got.TransportPlugins[0])
	}
}

func TestManagerPreflightFailureDoesNotStopCurrentEngine(t *testing.T) {
	current := &fakeEngine{}
	created := 0
	m := newManagerWithFactoryAndPreflight(
		func(Request) (engine, error) { created++; return current, nil },
		func(req Request) (Request, error) {
			if req.SocksPort == 12000 {
				return Request{}, fmt.Errorf("missing registered transport binary")
			}
			return req, nil
		},
	)
	if _, err := m.Start(Request{Engine: EngineTor, SocksPort: 10950}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Start(Request{Engine: EngineTor, SocksPort: 12000}); err == nil {
		t.Fatal("replacement unexpectedly passed failing preflight")
	}
	if !current.running || current.stops != 0 || created != 1 {
		t.Fatalf("failed preflight disturbed live engine: running=%v stops=%d created=%d", current.running, current.stops, created)
	}
}
