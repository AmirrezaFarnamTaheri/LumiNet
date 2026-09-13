//go:build !windows

package runtimecore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeRuntimeFake(t *testing.T, dir, name, captureEnv string) {
	t.Helper()
	path := filepath.Join(dir, name)
	body := "#!/bin/sh\n/bin/cp \"$2\" \"$" + captureEnv + "\"\n/bin/sleep 5\n"
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestManagerPassesTorAndPsiphonConfigurationToProcesses(t *testing.T) {
	dir := t.TempDir()
	torCapture := filepath.Join(dir, "tor.conf")
	psiCapture := filepath.Join(dir, "psiphon.json")
	writeRuntimeFake(t, dir, "tor", "CAPTURE_TOR")
	writeRuntimeFake(t, dir, "psiphon-tunnel-core", "CAPTURE_PSIPHON")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("CAPTURE_TOR", torCapture)
	t.Setenv("CAPTURE_PSIPHON", psiCapture)

	factory := func(req Request) (engine, error) {
		eng, err := productionFactory(req)
		if err != nil {
			return nil, err
		}
		if tor, ok := eng.(*torEngine); ok {
			// The fake process captures argv/config but intentionally does not
			// implement Tor's control protocol. Preserve the production factory
			// while injecting only the readiness probe seam for this fixture.
			tor.bootstrapProbe = func(string, string) (int, error) { return 100, nil }
		}
		return eng, nil
	}
	m := newManagerWithFactoryAndPreflight(factory, productionPreflight)
	defer m.Close()
	if _, err := m.Start(Request{Engine: EngineTor, SocksPort: 19350, ControlPort: 19351}); err != nil {
		t.Fatal(err)
	}
	torData, err := os.ReadFile(torCapture)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(torData), "SocksPort 127.0.0.1:19350") || !strings.Contains(string(torData), "ControlPort 127.0.0.1:19351") {
		t.Fatalf("Tor config did not receive requested ports:\n%s", torData)
	}
	if _, err := m.Stop(EngineTor); err != nil {
		t.Fatal(err)
	}

	upstream := "socks5://127.0.0.1:1080"
	if _, err := m.Start(Request{Engine: EnginePsiphon, SocksPort: 19390, UpstreamProxy: upstream}); err != nil {
		t.Fatal(err)
	}
	psiData, err := os.ReadFile(psiCapture)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(psiData, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["LocalSocksProxyPort"] != float64(19390) || cfg["UpstreamProxyURL"] != upstream {
		t.Fatalf("Psiphon config=%v", cfg)
	}
}
