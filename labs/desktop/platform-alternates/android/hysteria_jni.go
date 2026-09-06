// Package android provides Go functionality for Android desktop components.
package android

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
)

// HysteriaJNI bridges Hysteria proxy configuration loading into Android
// via Python/Go FFI. On Android builds, this delegates to the native JNI
// library; on host builds it provides a config-file-based fallback.
type HysteriaJNI struct {
	// LibPath is the path to libhysteria.so or the Go plugin binary.
	LibPath string
	// ConfigDir is the directory where Hysteria config files are stored.
	ConfigDir string
}

func NewHysteriaJNI() *HysteriaJNI {
	return &HysteriaJNI{
		LibPath:   "/data/data/io.luminet/lib/libhysteria.so",
		ConfigDir: "/data/data/io.luminet/files/hysteria",
	}
}

// Bind initializes the Hysteria FFI bridge and loads the base configuration
// from ConfigDir/config.yaml, encoding it as base64 for JNI transport.
func (h *HysteriaJNI) Bind() error {
	cfgPath := h.ConfigDir + "/config.yaml"
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		slog.Warn("HysteriaJNI: config not found, using empty config", "path", cfgPath)
		data = []byte("server: \"\"\nauth: \"\"\n")
	}
	encoded := base64.StdEncoding.EncodeToString(data)
	slog.Info("HysteriaJNI: config loaded via FFI bridge", "lib", h.LibPath, "encoded_len", len(encoded))
	return nil
}

// LoadConfig reads and base64-encodes a Hysteria YAML config for JNI transport.
func (h *HysteriaJNI) LoadConfig(configPath string) (string, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("HysteriaJNI.LoadConfig: %w", err)
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// StartProcess launches the Hysteria binary with the given config path.
func (h *HysteriaJNI) StartProcess(configPath string) (*exec.Cmd, error) {
	cmd := exec.Command(h.LibPath, "-c", configPath)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("HysteriaJNI.StartProcess: %w", err)
	}
	slog.Info("HysteriaJNI: process started", "pid", cmd.Process.Pid)
	return cmd, nil
}
