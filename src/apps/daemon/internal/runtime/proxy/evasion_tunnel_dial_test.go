package proxy

import (
	"context"
	"testing"
)

const testGoogleAccessToken = "test-access-token"

func TestEvasionTunnelDial_GDrive(t *testing.T) {
	mgr := &EvasionTunnelManager{}
	mgr.config.Store(&EvasionConfig{
		CovertMode:             "gdrive",
		CovertGdocsFolderId:    "folder-gdrive-123",
		CovertGdocsAccessToken: testGoogleAccessToken,
	})

	cfg := mgr.GetConfig()
	conn, err := mgr.dialWithEvasion(context.Background(), "example.com", 443, cfg)
	if err != nil {
		t.Fatalf("dialWithEvasion failed for gdrive covert mode: %v", err)
	}
	defer conn.Close()
	if _, ok := conn.(*gdriveConn); !ok {
		t.Fatalf("expected gdrive virtual connection, got %T", conn)
	}

	// Construction must validate credentials without performing a live Google
	// API call. Data-plane upload/download behavior is covered by transport tests
	// with controlled HTTP clients rather than by this routing test.
	cfg.CovertGdocsAccessToken = ""
	if _, err := mgr.dialWithEvasion(context.Background(), "example.com", 443, cfg); err == nil {
		t.Fatal("expected gdrive covert mode to reject a missing access token")
	}
}

func TestEvasionTunnelDial_GDocs(t *testing.T) {
	mgr := &EvasionTunnelManager{}
	mgr.config.Store(&EvasionConfig{
		CovertMode:             "gdocs",
		CovertGdocsFolderId:    "folder-gdocs-456",
		CovertGdocsAccessToken: testGoogleAccessToken,
	})

	cfg := mgr.GetConfig()
	conn, err := mgr.dialWithEvasion(context.Background(), "example.com", 443, cfg)
	if err != nil {
		t.Fatalf("dialWithEvasion failed for gdocs covert mode: %v", err)
	}
	defer conn.Close()
	if _, ok := conn.(*gdocsConn); !ok {
		t.Fatalf("expected gdocs virtual connection, got %T", conn)
	}

	// Keep this test hermetic: exercise the routing/credential contract here,
	// not Google Drive itself. Transport HTTP behavior has its own fixtures.
	cfg.CovertGdocsAccessToken = ""
	if _, err := mgr.dialWithEvasion(context.Background(), "example.com", 443, cfg); err == nil {
		t.Fatal("expected gdocs covert mode to reject a missing access token")
	}
}
