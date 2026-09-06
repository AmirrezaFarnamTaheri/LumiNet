package proxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestCoreManager_ValidateConfig_NonExistentBinary(t *testing.T) {
	mgr := NewCoreManager(CoreTypeSingBox, "/nonexistent/binary")
	err := mgr.ValidateConfig("some_config.json", true)
	if err == nil {
		t.Error("Expected error when validating config with a non-existent binary, got nil")
	}
}

func TestCoreManager_ValidateConfig_DummySuccess(t *testing.T) {
	// Use the current test binary or go executable as a dummy binary to simulate a command that runs.
	// Since standard commands won't recognize "check -c" or "-test", we expect they might fail,
	// but we can test that it executes.
	goBin := "go"
	mgr := NewCoreManager(CoreTypeSingBox, goBin)

	// Create a temp config file
	tmpFile, err := os.CreateTemp("", "dummy-cfg-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	err = mgr.ValidateConfig(tmpFile.Name(), true)
	// 'go check -c' will fail because check is not a go command, which is expected.
	// We just want to check that the error output is parsed.
	if err == nil {
		t.Error("Expected error because 'go' does not support 'check', but got nil")
	}
}

func TestProxyTester_StartBatch_ErrorOnLaunch(t *testing.T) {
	// Starting batch testing with a non-existent binary should fail during initialization
	mgr := NewCoreManager(CoreTypeSingBox, "/nonexistent/binary")
	config := TestConfig{
		Concurrency: 2,
		Timeout:     1,
	}
	tester := NewProxyTester(config, mgr)

	proxies := []*proxyConfig{
		{
			Protocol: protocolTrojan,
			Address:  "127.0.0.1",
			Port:     1080,
			Password: "pwd",
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := tester.StartBatch(ctx, proxies)
	if err == nil {
		t.Error("Expected error when starting batch test with nonexistent binary, got nil")
	}
}

func TestProxyTester_StartBatch_EmptyAddress(t *testing.T) {
	// A proxy with empty address should return a quick error status
	// We can write a test for testSingleOnPortInternal with skipSpawn=true
	mgr := NewCoreManager(CoreTypeSingBox, "")
	tester := NewProxyTester(TestConfig{}, mgr)

	res := tester.testSingleOnPortInternal(context.Background(), &proxyConfig{Address: ""}, 25000, true)
	if res.Status != "error" || res.Error != "empty proxy address" {
		t.Errorf("Expected 'error' and 'empty proxy address', got status='%s' and err='%s'", res.Status, res.Error)
	}
}

func TestProxyTester_MullvadCheck(t *testing.T) {
	// Start local mock HTTP server that simulates Mullvad connection status API
	mux := http.NewServeMux()
	mux.HandleFunc("/generate_204", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/mullvad_json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ip":"185.213.154.131","mullvad":true,"mullvad_server":"se-sto-wg-001"}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	// Start minimal SOCKS5 proxy
	socksAddr, cleanup := startMockSocks5(t)
	defer cleanup()

	_, portStr, err := net.SplitHostPort(socksAddr)
	if err != nil {
		t.Fatalf("failed to split host port: %v", err)
	}
	socksPort, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("failed to parse port: %v", err)
	}

	mgr := NewCoreManager(CoreTypeSingBox, "")
	config := TestConfig{
		TestURLs:   []string{server.URL + "/generate_204"},
		MullvadURL: server.URL + "/mullvad_json",
		Timeout:    2,
	}
	tester := NewProxyTester(config, mgr)

	// Since we mock dialer checks, construct a config with direct loopback IP
	proxy := &proxyConfig{
		Protocol: protocolSOCKS5,
		Address:  "127.0.0.1",
		Port:     socksPort,
	}

	res := tester.testSingleOnPortInternal(context.Background(), proxy, socksPort, true)
	if res.Status != "working" {
		t.Fatalf("expected status 'working', got '%s', err: %s", res.Status, res.Error)
	}

	if !res.Mullvad {
		t.Error("expected Mullvad to be true, got false")
	}

	if res.MullvadServer != "se-sto-wg-001" {
		t.Errorf("expected MullvadServer 'se-sto-wg-001', got '%s'", res.MullvadServer)
	}
}
