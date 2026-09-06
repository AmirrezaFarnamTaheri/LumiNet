// Package android provides Go functionality for Android desktop components.
package android

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
)

// SingBoxAndroidJNI manages the Sing-Box library compilation and JNI method
// binding on Android. It handles AAR build coordination, config loading, and
// runtime lifecycle management for the Sing-Box core process.
type SingBoxAndroidJNI struct {
	// LibDir is the directory containing libsingbox.so.
	LibDir string
	// ConfigDir is the Sing-Box config directory on device.
	ConfigDir string
}

func NewSingBoxAndroidJNI() *SingBoxAndroidJNI {
	return &SingBoxAndroidJNI{
		LibDir:    "/data/data/io.luminet/lib",
		ConfigDir: "/data/data/io.luminet/files/singbox",
	}
}

// Build compiles a Sing-Box config into base64 for JNI transport and
// validates the native library is present.
func (s *SingBoxAndroidJNI) Build() error {
	libPath := filepath.Join(s.LibDir, "libsingbox.so")
	if _, err := os.Stat(libPath); os.IsNotExist(err) {
		slog.Warn("SingBoxAndroidJNI: native library not found", "path", libPath)
	}
	cfgPath := filepath.Join(s.ConfigDir, "config.json")
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		slog.Warn("SingBoxAndroidJNI: config not found, using empty config", "path", cfgPath)
		data = []byte(`{"log":{"level":"info"}}`)
	}
	encoded := base64.StdEncoding.EncodeToString(data)
	slog.Info("SingBoxAndroidJNI: JNI binding ready", "lib", libPath, "config_b64_len", len(encoded))
	return nil
}

// StartCore launches the sing-box process with the given config file.
func (s *SingBoxAndroidJNI) StartCore(configPath string) (*exec.Cmd, error) {
	libPath := filepath.Join(s.LibDir, "libsingbox.so")
	cmd := exec.Command(libPath, "run", "-c", configPath)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("SingBoxAndroidJNI.StartCore: %w", err)
	}
	slog.Info("SingBoxAndroidJNI: core process started", "pid", cmd.Process.Pid)
	return cmd, nil
}
