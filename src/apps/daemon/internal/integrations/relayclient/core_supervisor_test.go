package relayclient

import (
	"strings"
	"testing"
	"time"
)

func TestWSLNoiseDetection(t *testing.T) {
	if !IsWSLNoise("wsl: A localhost proxy is listening on port 1080") {
		t.Errorf("expected true for wsl prefix")
	}
	if !IsWSLNoise("NAT mode does not support port forwarding") {
		t.Errorf("expected true for NAT mode")
	}
	if !IsWSLNoise("Port not mirrored into WSL") {
		t.Errorf("expected true for mirrored into WSL")
	}
	if IsWSLNoise("Fatal error: connection refused") {
		t.Errorf("genuine error falsely flagged as WSL noise")
	}
}

func TestBinaryInfoPattern(t *testing.T) {
	if !IsBinaryInfoPattern("CARRIER INFO relay ok: 200 OK") {
		t.Errorf("expected true for CARRIER INFO")
	}
	if !IsBinaryInfoPattern("2026/09/04 18:00:00 [FlowDriver] Tunnel up") {
		t.Errorf("expected true for Go timestamp format")
	}
	if !IsBinaryInfoPattern("Zero-Config storage initialized") {
		t.Errorf("expected true for Zero-Config")
	}
	if IsBinaryInfoPattern("bind: address already in use") {
		t.Errorf("genuine error falsely flagged as binary info")
	}
}

func TestExtractOAuthURL(t *testing.T) {
	line := "Please visit https://accounts.google.com/o/oauth2/auth?client_id=xyz&response_type=code to authorize"
	url, ok := ExtractOAuthURL(line)
	if !ok {
		t.Fatalf("expected OAuth URL extraction")
	}
	if !strings.HasPrefix(url, "https://accounts.google.com/o/oauth2/auth") {
		t.Errorf("unexpected extracted URL: %s", url)
	}

	_, ok = ExtractOAuthURL("regular log message")
	if ok {
		t.Errorf("expected false for line without OAuth URL")
	}
}

func TestClassifyStderrLine(t *testing.T) {
	sev, _ := ClassifyStderrLine("wsl: localhost proxy attached")
	if sev != LogInfo {
		t.Errorf("expected LogInfo for WSL noise, got %s", sev)
	}

	sev, _ = ClassifyStderrLine("CARRIER INFO relay returned 200")
	if sev != LogInfo {
		t.Errorf("expected LogInfo for CARRIER INFO, got %s", sev)
	}

	sev, _ = ClassifyStderrLine("panic: nil pointer dereference")
	if sev != LogError {
		t.Errorf("expected LogError for panic, got %s", sev)
	}

	sev, url := ClassifyStderrLine("Authorize here: https://accounts.google.com/o/oauth2/v2/auth?scope=drive")
	if sev != LogOAuth {
		t.Errorf("expected LogOAuth, got %s", sev)
	}
	if url == "" {
		t.Errorf("expected extracted OAuth URL")
	}
}

func TestCoreSupervisorLifecycle(t *testing.T) {
	sup := NewCoreSupervisor()

	stdinCaptured := ""
	stdinFn := func(input string) error {
		stdinCaptured = input
		return nil
	}

	core := sup.RegisterCore("core-1", EngineDriveStorage, 1234, stdinFn)
	if core.State != StateRunning {
		t.Errorf("expected running state, got %s", core.State)
	}

	ch, unsub, err := sup.Subscribe("core-1")
	if err != nil {
		t.Fatalf("subscribe error: %v", err)
	}
	defer unsub()

	// Push OAuth log line
	sup.PushLog("core-1", true, "Open link: https://accounts.google.com/o/oauth2/auth?client_id=123")
	if core.OAuthState != OAuthWaitingForInput {
		t.Errorf("expected OAuthWaitingForInput, got %s", core.OAuthState)
	}

	// Verify channel received event
	select {
	case entry := <-ch:
		if entry.Level != LogOAuth {
			t.Errorf("expected LogOAuth, got %s", entry.Level)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timeout waiting for subscriber entry")
	}

	// Send stdin (callback URL)
	err = sup.SendStdin("core-1", "http://localhost/?code=xyz")
	if err != nil {
		t.Fatalf("SendStdin error: %v", err)
	}
	if stdinCaptured != "http://localhost/?code=xyz" {
		t.Errorf("unexpected stdin captured: %s", stdinCaptured)
	}
	if core.OAuthState != OAuthDone {
		t.Errorf("expected OAuthDone, got %s", core.OAuthState)
	}

	// Push request forward line
	sup.PushLog("core-1", false, "relay request forwarded")
	if core.RequestCount != 1 {
		t.Errorf("expected RequestCount 1, got %d", core.RequestCount)
	}

	// Check recent logs
	recent := sup.GetRecentLogs("core-1", 10)
	if len(recent) < 2 {
		t.Errorf("expected at least 2 logs, got %d", len(recent))
	}

	// Unregister
	sup.UnregisterCore("core-1")
	dead := sup.GetRecentLogs("core-1", 10)
	if len(dead) < 2 {
		t.Errorf("expected dead logs preserved, got %d", len(dead))
	}
}

func TestRelayConfigGenerators(t *testing.T) {
	appsScriptJSON, err := GenerateAppsScriptConfigJSON(AppsScriptRelayConfig{
		SocksHost:  "127.0.0.1",
		SocksPort:  1080,
		GoogleHost: "216.239.38.120",
		SNI:        []string{"www.google.com", "mail.google.com"},
		ScriptKeys: []string{"AKfycb123"},
		TunnelKey:  "secret-tunnel",
		SocksUser:  "proxyuser",
		SocksPass:  "proxypass",
	})
	if err != nil {
		t.Fatalf("GenerateAppsScriptConfigJSON error: %v", err)
	}
	if !strings.Contains(string(appsScriptJSON), "\"socks_port\": 1080") {
		t.Errorf("missing socks_port in AppsScript JSON")
	}
	if !strings.Contains(string(appsScriptJSON), "\"socks_user\": \"proxyuser\"") {
		t.Errorf("missing socks_user in AppsScript JSON")
	}

	driveStorageJSON, err := GenerateDriveStorageConfigJSON(DriveStorageRelayConfig{
		ListenAddr:     "127.0.0.1:1080",
		GoogleFolderID: "drive-folder-456",
		RefreshRateMs:  250,
		FlushRateMs:    350,
		Transport: DriveStorageTransport{
			TargetIP:   "216.239.38.120:443",
			SNI:        "google.com",
			HostHeader: "www.googleapis.com",
		},
	})
	if err != nil {
		t.Fatalf("GenerateDriveStorageConfigJSON error: %v", err)
	}
	if !strings.Contains(string(driveStorageJSON), "\"storage_type\": \"google\"") {
		t.Errorf("missing storage_type in DriveStorage JSON")
	}
	if !strings.Contains(string(driveStorageJSON), "\"google_folder_id\": \"drive-folder-456\"") {
		t.Errorf("missing google_folder_id in DriveStorage JSON")
	}
}
