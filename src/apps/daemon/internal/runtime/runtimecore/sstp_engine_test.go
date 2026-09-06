package runtimecore

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSSTPCommandArgsPreserveProfileOptions(t *testing.T) {
	eng := newSSTPEngine(Request{Engine: EngineSSTP, Server: "vpn.example:443", Username: "alice", Password: "secret", UpstreamProxy: "http://127.0.0.1:8080", CACert: "/tmp/ca.pem", AllowCertWarning: true, PPPOptions: []string{"usepeerdns", "defaultroute"}})
	args := strings.Join(eng.commandArgs(), " ")
	for _, want := range []string{"--user alice", "--password secret", "--proxy http://127.0.0.1:8080", "--ca-cert /tmp/ca.pem", "--cert-warn", "vpn.example:443", "usepeerdns defaultroute"} {
		if !strings.Contains(args, want) {
			t.Fatalf("args %q missing %q", args, want)
		}
	}
}

func TestSSTPEngineStartsAndStopsExternalClient(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture is unix-only")
	}
	dir := t.TempDir()
	capture := filepath.Join(dir, "args.txt")
	script := filepath.Join(dir, "sstpc")
	body := "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$SSTP_CAPTURE\"\nwhile :; do sleep 1; done\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("SSTP_CAPTURE", capture)
	eng := newSSTPEngine(Request{Engine: EngineSSTP, Server: "vpn.example:443", Username: "alice", Password: "secret"})
	if err := eng.Start(); err != nil {
		t.Fatal(err)
	}
	if !eng.IsRunning() {
		t.Fatal("SSTP engine not running after start")
	}
	eng.Stop()
	deadline := time.Now().Add(2 * time.Second)
	for eng.IsRunning() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if eng.IsRunning() {
		t.Fatal("SSTP engine remained running after stop")
	}
	data, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "vpn.example:443") || !strings.Contains(string(data), "require-mschap-v2") {
		t.Fatalf("captured args=%q", data)
	}
}
