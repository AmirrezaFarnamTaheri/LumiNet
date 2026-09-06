package system

import (
	"strings"
	"testing"
)

func TestTorConfigBuilder(t *testing.T) {
	builder := NewTorConfigBuilder().
		SocksPort(9050, true, true).
		ControlPort(9051).
		DataDirectory("/tmp/tor").
		CookieAuth("/tmp/tor/cookie").
		AvoidDiskWrites().
		ConnectionPadding(true).
		CircuitPadding(true, true).
		VirtualAddrNetwork().
		DormantPolicy().
		ReachableAddresses("*:80,*:443").
		IPv6Prefs(true, true).
		KeepAliveIsolateSOCKSAuth()

	config, err := builder.BuildValidated()
	if err != nil {
		t.Fatal(err)
	}
	expectedLines := []string{
		"SocksPort 127.0.0.1:9050 IsolateDestAddr IsolateDestPort",
		"ControlPort 127.0.0.1:9051",
		"DataDirectory /tmp/tor",
		"CookieAuthentication 1",
		"CookieAuthFile /tmp/tor/cookie",
		"AvoidDiskWrites 1",
		"ReducedConnectionPadding 1",
		"CircuitPadding 1",
		"ReducedCircuitPadding 1",
		"VirtualAddrNetwork 10.192.0.0/10",
		"AutomapHostsOnResolve 1",
		"DormantClientTimeout 10 minutes",
		"DormantCanceledByStartup 1",
		"ReachableAddresses *:80,*:443",
		"IPv6Traffic 1",
		"PreferIPv6 1",
		"NoIPv4Traffic 1",
		"KeepAliveIsolateSOCKSAuth 1",
	}
	for _, line := range expectedLines {
		if !strings.Contains(config, line) {
			t.Errorf("expected config to contain %q, got:\n%s", line, config)
		}
	}
}

func TestTorConfigBuilder_PluggableTransports(t *testing.T) {
	cfg, err := NewTorConfigBuilder().BridgesWithTransports(
		[]string{
			"obfs4 192.0.2.10:443 cert=abc iat-mode=0",
			"snowflake 192.0.2.11:443 fingerprint=xyz",
			"webtunnel 192.0.2.12:443 fingerprint=qrs url=https://example.com/secret",
		},
		[]TorTransportPlugin{
			{Name: "obfs4", Executable: "/opt/lyrebird"},
			{Name: "snowflake", Executable: "/opt/snowflake-client", Args: []string{"-keep-local-addresses"}},
			{Name: "webtunnel", Executable: "/opt/lyrebird"},
		},
	).BuildValidated()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"UseBridges 1",
		"ClientTransportPlugin obfs4 exec /opt/lyrebird",
		"ClientTransportPlugin snowflake exec /opt/snowflake-client -keep-local-addresses",
		"ClientTransportPlugin webtunnel exec /opt/lyrebird",
		"Bridge webtunnel 192.0.2.12:443 fingerprint=qrs url=https://example.com/secret",
	} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("missing %q in:\n%s", want, cfg)
		}
	}
}

func TestTorConfigBuilder_RejectsDirectiveInjection(t *testing.T) {
	cases := []*TorConfigBuilder{
		NewTorConfigBuilder().Bridges([]string{"obfs4 1.2.3.4:443\nSocksPort 0.0.0.0:9999"}, "/opt/obfs4proxy"),
		NewTorConfigBuilder().BridgesWithTransports([]string{"obfs4 1.2.3.4:443"}, []TorTransportPlugin{{Name: "obfs4\nUseBridges", Executable: "/opt/x"}}),
		NewTorConfigBuilder().BridgesWithTransports([]string{"obfs4 1.2.3.4:443"}, []TorTransportPlugin{{Name: "obfs4", Executable: "/opt/evil\nSocksPort"}}),
	}
	for i, builder := range cases {
		if _, err := builder.BuildValidated(); err == nil {
			t.Fatalf("case %d accepted unsafe torrc material", i)
		}
	}
}

func TestTorConfigBuilder_BoundsDynamicTransportMaterial(t *testing.T) {
	bridges := make([]string, maxTorBridges+1)
	for i := range bridges {
		bridges[i] = "obfs4 192.0.2.1:443 cert=x"
	}
	if _, err := NewTorConfigBuilder().BridgesWithTransports(bridges, nil).BuildValidated(); err == nil {
		t.Fatal("unbounded bridges were accepted")
	}
}

func TestTorConfigBuilderQuotesSpecialTransportTokens(t *testing.T) {
	got, err := NewTorConfigBuilder().BridgesWithTransports(
		[]string{"snowflake 192.0.2.1:443 fingerprint"},
		[]TorTransportPlugin{{Name: "snowflake", Executable: `/opt/Lumi Net/client#1`, Args: []string{`-log=/tmp/a#b`, `say\"hello`}}},
	).BuildValidated()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `ClientTransportPlugin snowflake exec "/opt/Lumi Net/client#1" "-log=/tmp/a#b" "say\\\"hello"`) {
		t.Fatalf("special tokens not safely quoted:\n%s", got)
	}
}
