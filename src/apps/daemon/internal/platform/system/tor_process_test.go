package system

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTorProcessWriteTorrc_PluggableTransport(t *testing.T) {
	dir := t.TempDir()
	p := NewTorProcess(TorProcessConfig{
		DataDir:     dir,
		SocksPort:   9050,
		ControlPort: 9051,
		Bridges:     []string{"snowflake 192.0.2.10:443 fingerprint=abc"},
		TransportPlugins: []TorTransportPlugin{{
			Name:       "snowflake",
			Executable: "/opt/snowflake-client",
			Args:       []string{"-keep-local-addresses"},
		}},
	})
	p.configPath = filepath.Join(dir, "torrc")
	if err := p.writeTorrc(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(p.configPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		"AvoidDiskWrites 1",
		"ClientTransportPlugin snowflake exec /opt/snowflake-client -keep-local-addresses",
		"Bridge snowflake 192.0.2.10:443 fingerprint=abc",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("torrc missing %q:\n%s", want, text)
		}
	}
}

func TestTorProcessWriteTorrc_RejectsInjectedBridge(t *testing.T) {
	dir := t.TempDir()
	p := NewTorProcess(TorProcessConfig{
		DataDir:        dir,
		SocksPort:      9050,
		ControlPort:    9051,
		Bridges:        []string{"obfs4 192.0.2.10:443\nControlPort 0.0.0.0:9999"},
		Obfs4ProxyPath: "/opt/obfs4proxy",
	})
	p.configPath = filepath.Join(dir, "torrc")
	if err := p.writeTorrc(); err == nil {
		t.Fatal("unsafe bridge material was accepted")
	}
	if _, err := os.Stat(p.configPath); !os.IsNotExist(err) {
		t.Fatalf("invalid torrc should not be published, stat err=%v", err)
	}
}
