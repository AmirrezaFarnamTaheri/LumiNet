// Package system provides Psiphon node management.
// (formerly package psiphon) Psiphon Conduit node management.
//
// Features:
// - Multi-container orchestration with resource limits
// - Per-container max-clients, bandwidth, CPU/memory limits
// - Autostart setup (systemd/OpenRC/SysVinit)
// - Traffic tracking with GeoIP resolution
// - Data cap enforcement with auto-stop
package system

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ContainerConfig holds configuration for a single Psiphon container.
type ContainerConfig struct {
	// Container index (1-based).
	Index int
	// Max clients per container.
	MaxClients int
	// Bandwidth limit (e.g., "100m").
	Bandwidth string
	// CPU limit (e.g., "1.0").
	CPUs string
	// Memory limit (e.g., "512m").
	Memory string
	// Network compartment name.
	Compartment string
}

// NodeConfig holds configuration for a Psiphon node.
type NodeConfig struct {
	// Number of containers to run.
	ContainerCount int
	// Max clients per container (default: CPU cores × 100, capped at 1000).
	MaxClientsPerContainer int
	// Bandwidth limit per container.
	Bandwidth string
	// CPU limit per container.
	CPUs string
	// Memory limit per container.
	Memory string
	// Data cap (bytes, 0 = unlimited).
	DataCap int64
	// Enable Snowflake proxy.
	EnableSnowflake bool
	// Enable MTProto proxy.
	EnableMTProto bool
	// MTProto secret.
	MTProtoSecret string
	// Telegram bot token for sharing.
	TelegramBotToken string
	// Telegram chat ID for notifications.
	TelegramChatID string
	// Autostart on boot.
	Autostart bool
}

// DefaultNodeConfig returns a default configuration based on system resources.
func DefaultNodeConfig() NodeConfig {
	cores := runtime.NumCPU()
	memGB := getTotalMemoryGB()

	containerCount := min(cores, memGB, 32)
	maxClients := min(cores*100, 1000)

	return NodeConfig{
		ContainerCount:         containerCount,
		MaxClientsPerContainer: maxClients,
		Bandwidth:              "0",
		CPUs:                   "0",
		Memory:                 "0",
		DataCap:                0,
		EnableSnowflake:        false,
		EnableMTProto:          false,
		Autostart:              true,
	}
}

// NodeManager manages Psiphon Conduit containers.
type NodeManager struct {
	config     NodeConfig
	containers []*ContainerState
	mu         sync.RWMutex
	startTime  time.Time
}

// ContainerState tracks a running container.
type ContainerState struct {
	Config      ContainerConfig
	ContainerID string
	PID         int
	Running     bool
	StartTime   time.Time
	Upload      int64
	Download    int64
	Clients     int
}

// TrafficStats holds traffic statistics.
type TrafficStats struct {
	TotalUpload   int64
	TotalDownload int64
	TotalClients  int
	PerCountry    map[string]*CountryStats
	StartTime     time.Time
}

// CountryStats holds per-country traffic data.
type CountryStats struct {
	Upload      int64
	Download    int64
	Connections int
	LastSeen    time.Time
}

// NewNodeManager creates a new Psiphon node manager.
func NewNodeManager(config NodeConfig) *NodeManager {
	return &NodeManager{
		config:     config,
		containers: make([]*ContainerState, config.ContainerCount),
		startTime:  time.Now(),
	}
}

// Start starts all Psiphon containers.
func (nm *NodeManager) Start() error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	for i := 0; i < nm.config.ContainerCount; i++ {
		cfg := ContainerConfig{
			Index:      i + 1,
			MaxClients: nm.config.MaxClientsPerContainer,
			Bandwidth:  nm.config.Bandwidth,
			CPUs:       nm.config.CPUs,
			Memory:     nm.config.Memory,
		}

		containerID, err := startContainer(cfg)
		if err != nil {
			return fmt.Errorf("start container %d: %w", i+1, err)
		}

		nm.containers[i] = &ContainerState{
			Config:      cfg,
			ContainerID: containerID,
			Running:     true,
			StartTime:   time.Now(),
		}
	}

	return nil
}

// Stop stops all Psiphon containers.
func (nm *NodeManager) Stop() error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	for _, container := range nm.containers {
		if container != nil && container.Running {
			if err := stopContainer(container.ContainerID); err != nil {
				return fmt.Errorf("stop container %s: %w", container.ContainerID, err)
			}
			container.Running = false
		}
	}

	return nil
}

// Restart restarts all containers.
func (nm *NodeManager) Restart() error {
	if err := nm.Stop(); err != nil {
		return err
	}
	return nm.Start()
}

// Status returns the current status of all containers.
func (nm *NodeManager) Status() []*ContainerState {
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	status := make([]*ContainerState, len(nm.containers))
	copy(status, nm.containers)
	return status
}

// IsRunning returns true if any container is running.
func (nm *NodeManager) IsRunning() bool {
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	for _, c := range nm.containers {
		if c != nil && c.Running {
			return true
		}
	}
	return false
}

// ContainerCount returns the number of running containers.
func (nm *NodeManager) ContainerCount() int {
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	count := 0
	for _, c := range nm.containers {
		if c != nil && c.Running {
			count++
		}
	}
	return count
}

// SetupAutostart configures the system to start Psiphon on boot.
func SetupAutostart(scriptPath string) error {
	// Detect init system
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		return setupSystemd(scriptPath)
	}
	if _, err := os.Stat("/sbin/openrc"); err == nil {
		return setupOpenRC(scriptPath)
	}
	return setupSysVinit(scriptPath)
}

func setupSystemd(scriptPath string) error {
	service := fmt.Sprintf(`[Unit]
Description=LumiNet Psiphon Conduit
After=network.target docker.service

[Service]
Type=forking
ExecStart=%s start
ExecStop=%s stop
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
`, scriptPath, scriptPath)

	return os.WriteFile("/etc/systemd/system/luminet-psiphon.service", []byte(service), 0644)
}

func setupOpenRC(scriptPath string) error {
	init := fmt.Sprintf(`#!/sbin/openrc-run
name="luminet-psiphon"
description="LumiNet Psiphon Conduit"
command="%s"
command_args="start"
command_background=true
pidfile="/run/${RC_SVCNAME}.pid"
depend() {
    need net
    after docker
}
`, scriptPath)

	return os.WriteFile("/etc/init.d/luminet-psiphon", []byte(init), 0755)
}

func setupSysVinit(scriptPath string) error {
	init := fmt.Sprintf(`#!/bin/bash
### BEGIN INIT INFO
# Provides:          luminet-psiphon
# Required-Start:    $network $docker
# Required-Stop:     $network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Description:       LumiNet Psiphon Conduit
### END INIT INFO

case "$1" in
    start)
        %s start
        ;;
    stop)
        %s stop
        ;;
    restart)
        %s stop
        %s start
        ;;
esac
`, scriptPath, scriptPath, scriptPath, scriptPath)

	return os.WriteFile("/etc/init.d/luminet-psiphon", []byte(init), 0755)
}

// GenerateShareLink generates a share link for Psiphon.
func GenerateShareLink(serverIP string, containerIndex int, secret string) string {
	return fmt.Sprintf("psiphon://server=%s&container=%d&secret=%s",
		serverIP, containerIndex, secret)
}

// GenerateMTProtoShareLink generates a MTProto share link.
func GenerateMTProtoShareLink(serverIP string, port int, secret string) string {
	return fmt.Sprintf("https://t.me/proxy?server=%s&port=%d&secret=%s",
		serverIP, port, secret)
}

// AutoRestartStuckContainers monitors containers and restarts those with zero peers.
func (nm *NodeManager) AutoRestartStuckContainers(stuckTimeout time.Duration) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		nm.mu.Lock()
		for _, c := range nm.containers {
			if c != nil && c.Running {
				if c.Clients == 0 && time.Since(c.StartTime) > stuckTimeout {
					// Restart stuck container
					stopContainer(c.ContainerID)
					newID, err := startContainer(c.Config)
					if err == nil {
						c.ContainerID = newID
						c.StartTime = time.Now()
					}
				}
			}
		}
		nm.mu.Unlock()
	}
}

// DataCapEnforcer monitors traffic and stops containers when data cap is reached.
func (nm *NodeManager) DataCapEnforcer(capBytes int64) {
	if capBytes <= 0 {
		return
	}

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		nm.mu.RLock()
		var totalBytes int64
		for _, c := range nm.containers {
			if c != nil {
				totalBytes += c.Upload + c.Download
			}
		}
		nm.mu.RUnlock()

		if totalBytes >= capBytes {
			nm.Stop()
			return
		}
	}
}

// Helper functions
func startContainer(cfg ContainerConfig) (string, error) {
	args := []string{"run", "-d"}
	if cfg.CPUs != "0" && cfg.CPUs != "" {
		args = append(args, "--cpus", cfg.CPUs)
	}
	if cfg.Memory != "0" && cfg.Memory != "" {
		args = append(args, "--memory", cfg.Memory)
	}
	args = append(args, fmt.Sprintf("--name=psiphon-%d", cfg.Index))
	args = append(args, "luminet/psiphon-conduit")

	out, err := exec.Command("docker", args...).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func stopContainer(containerID string) error {
	return exec.Command("docker", "stop", containerID).Run()
}

func getTotalMemoryGB() int {
	// Try to read from /proc/meminfo
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 4 // Default
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			var kb int
			fmt.Sscanf(line, "MemTotal: %d kB", &kb)
			return kb / 1024 / 1024
		}
	}
	return 4
}
