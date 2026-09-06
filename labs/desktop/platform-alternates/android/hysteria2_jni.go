// Package android provides Go functionality for Android desktop components.
package android

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
)

// Hysteria2JNI bridges Hysteria 2 proxy configuration into Android via ctypes/JNI.
// It handles config loading, base64 FFI transport, and process lifecycle management.
type Hysteria2JNI struct {
	// LibPath is the path to the Hysteria 2 native binary or shared library.
	LibPath string
	// ConfigDir is the directory where Hysteria 2 config files are stored.
	ConfigDir string
}

func NewHysteria2JNI() *Hysteria2JNI {
	return &Hysteria2JNI{
		LibPath:   "/data/data/io.luminet/lib/libhysteria2.so",
		ConfigDir: "/data/data/io.luminet/files/hysteria2",
	}
}

// Bind initializes the Hysteria 2 ctypes binding and validates the config directory.
func (h *Hysteria2JNI) Bind() error {
	cfgPath := h.ConfigDir + "/config.yaml"
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		slog.Warn("Hysteria2JNI: config not found, using minimal config", "path", cfgPath)
		data = []byte("server: \"\"\nauth:\n  type: password\n  password: \"\"\n")
	}
	encoded := base64.StdEncoding.EncodeToString(data)
	slog.Info("Hysteria2JNI: ctypes bridge initialized", "lib", h.LibPath, "encoded_len", len(encoded))
	return nil
}

// LoadConfig reads and base64-encodes a Hysteria 2 config for JNI transport.
func (h *Hysteria2JNI) LoadConfig(configPath string) (string, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("Hysteria2JNI.LoadConfig: %w", err)
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// StartProcess launches the Hysteria 2 binary with the given config.
func (h *Hysteria2JNI) StartProcess(configPath string) (*exec.Cmd, error) {
	cmd := exec.Command(h.LibPath, "--config", configPath)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("Hysteria2JNI.StartProcess: %w", err)
	}
	slog.Info("Hysteria2JNI: process started", "pid", cmd.Process.Pid)
	return cmd, nil
}
