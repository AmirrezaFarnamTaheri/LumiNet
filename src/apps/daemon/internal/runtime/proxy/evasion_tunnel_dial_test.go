package proxy

import (
	"context"
	"io"
	"testing"
)

func TestEvasionTunnelDial_GDrive(t *testing.T) {
	mgr := &EvasionTunnelManager{}
	mgr.config.Store(&EvasionConfig{
		CovertMode:             "gdrive",
		CovertGdocsFolderId:    "folder-gdrive-123",
		CovertGdocsAccessToken: "",
	})

	cfg := mgr.GetConfig()
	conn, err := mgr.dialWithEvasion(context.Background(), "example.com", 443, cfg)
	if err != nil {
		t.Fatalf("dialWithEvasion failed for gdrive covert mode: %v", err)
	}
	defer conn.Close()

	// Write payload
	n, err := conn.Write([]byte("gdrive test payload"))
	if err != nil {
		t.Fatalf("Failed to write to gdrive connection: %v", err)
	}
	if n != 19 {
		t.Errorf("Expected to write 19 bytes, wrote %d", n)
	}

	// Read from connection (simulator returns io.EOF)
	buf := make([]byte, 10)
	rn, err := conn.Read(buf)
	if err != io.EOF {
		t.Errorf("Expected EOF read on simulator connection, got %v", err)
	}
	if rn != 0 {
		t.Errorf("Expected 0 bytes read, got %d", rn)
	}
}

func TestEvasionTunnelDial_GDocs(t *testing.T) {
	mgr := &EvasionTunnelManager{}
	mgr.config.Store(&EvasionConfig{
		CovertMode:             "gdocs",
		CovertGdocsFolderId:    "folder-gdocs-456",
		CovertGdocsAccessToken: "",
	})

	cfg := mgr.GetConfig()
	conn, err := mgr.dialWithEvasion(context.Background(), "example.com", 443, cfg)
	if err != nil {
		t.Fatalf("dialWithEvasion failed for gdocs covert mode: %v", err)
	}
	defer conn.Close()

	// Write payload
	n, err := conn.Write([]byte("gdocs test payload"))
	if err != nil {
		t.Fatalf("Failed to write to gdocs connection: %v", err)
	}
	if n != 18 {
		t.Errorf("Expected to write 18 bytes, wrote %d", n)
	}

	// Read from connection (simulator returns io.EOF)
	buf := make([]byte, 10)
	rn, err := conn.Read(buf)
	if err != io.EOF {
		t.Errorf("Expected EOF read on simulator connection, got %v", err)
	}
	if rn != 0 {
		t.Errorf("Expected 0 bytes read, got %d", rn)
	}
}
