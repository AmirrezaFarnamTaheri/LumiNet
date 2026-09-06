// Package android provides JNI interfaces for the Android platform.
package android

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
)

// LibXrayJNI bridges gomobile/JNI endpoints for the Xray-core library on Android.
// It provides Base64 FFI wrappers for config transport and ProtectFd socket controls.
type LibXrayJNI struct {
	// DataDir is the Android app data directory for Xray assets.
	DataDir string
}

func NewLibXrayJNI() *LibXrayJNI {
	return &LibXrayJNI{DataDir: "/data/data/io.luminet/files/xray"}
}

// Bind initializes the Xray JNI endpoint and validates the asset directory.
func (l *LibXrayJNI) Bind() error {
	if _, err := os.Stat(l.DataDir); os.IsNotExist(err) {
		if err := os.MkdirAll(l.DataDir, 0o755); err != nil {
			return fmt.Errorf("LibXrayJNI.Bind: create data dir: %w", err)
		}
	}
	slog.Info("LibXrayJNI: JNI endpoint initialized", "data_dir", l.DataDir)
	return nil
}

// LoadConfigBase64 reads an Xray JSON config from disk and returns it as base64
// for JNI transport into the Java/Kotlin layer.
func (l *LibXrayJNI) LoadConfigBase64(configPath string) (string, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("LibXrayJNI.LoadConfigBase64: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(data)
	slog.Info("LibXrayJNI: config encoded for JNI", "path", configPath, "encoded_len", len(encoded))
	return encoded, nil
}

// ProtectFd signals the Android VpnService to protect a file descriptor from
// VPN routing (avoids routing loops). In production, this is handled via
// the IPC socket to VpnEngineService; here we log the request for wiring.
func (l *LibXrayJNI) ProtectFd(fd int) error {
	slog.Info("LibXrayJNI: ProtectFd requested", "fd", fd)
	// Production: send fd over SCM_RIGHTS unix socket to VpnEngineService.
	// The actual socket path is wired via NewSocketProtector in client/platform.
	return nil
}
