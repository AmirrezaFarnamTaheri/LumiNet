package controlui

import (
	"bytes"
	"io/fs"
	"testing"
)

func TestDistIsSafeBootstrapOrCurrentBundle(t *testing.T) {
	assets := Dist()
	index, err := fs.ReadFile(assets, "index.html")
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	if len(index) == 0 {
		t.Fatal("index.html is empty")
	}
	if _, err := fs.Stat(assets, "favicon.svg"); err != nil {
		t.Fatalf("stat favicon.svg: %v", err)
	}

	const bootstrap = `data-luminet-bootstrap="unbuilt"`
	if bytes.Contains(index, []byte(bootstrap)) {
		if bytes.Contains(index, []byte("localhost:9090")) {
			t.Fatal("tracked bootstrap must not contain legacy backend endpoints")
		}
		return
	}

	matches, err := fs.Glob(assets, "assets/*.js")
	if err != nil {
		t.Fatalf("glob built JS assets: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("dist is neither fail-closed bootstrap nor generated JS bundle")
	}
	var js []byte
	for _, name := range matches {
		part, err := fs.ReadFile(assets, name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		js = append(js, part...)
	}
	for _, legacy := range [][]byte{[]byte("localhost:9090"), []byte("ws://localhost:9090"), []byte("/api/v1/telemetry/stream")} {
		if bytes.Contains(js, legacy) {
			t.Fatalf("generated bundle contains legacy backend marker %q", legacy)
		}
	}
	if !bytes.Contains(js, []byte("Desktop session discovery failed; refusing direct HTTP fallback.")) {
		t.Fatal("generated bundle does not contain current Wails fail-closed session behavior")
	}
	if !bytes.Contains(js, []byte("/api/session/ws")) {
		t.Fatal("generated bundle does not contain current WebSocket session transport")
	}
	if bytes.Contains(js, []byte("ExecuteDiagnosticRun")) {
		t.Fatal("generated bundle contains retired Wails diagnostic shortcut")
	}
}
