// Package main implements LumiNet's independent crash-recovery watchdog.
// The watchdog owns no network-reset algorithm of its own: the durable
// host-network record is the handoff and system.RecoverHostNetworkInDir is the
// single recovery implementation used by both clean and crash shutdown.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/maybeknott/luminet/contracts/buildinfo"
	"github.com/maybeknott/luminet/internal/platform/system"
)

type watchdogConfig struct {
	parentPID int
	dataDir   string
}

func main() {
	if len(os.Args) == 2 && (os.Args[1] == "--version" || os.Args[1] == "version") {
		fmt.Println(buildinfo.Version)
		return
	}

	cfg, err := parseWatchdogArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := monitorParent(context.Background(), cfg.parentPID, cfg.dataDir, time.Second, checkProcessLiveness, system.RecoverHostNetworkInDir); err != nil {
		fmt.Fprintf(os.Stderr, "watchdog recovery failed: %v\n", err)
		os.Exit(1)
	}
}

func parseWatchdogArgs(args []string) (watchdogConfig, error) {
	fs := flag.NewFlagSet("watchdog", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var cfg watchdogConfig
	fs.IntVar(&cfg.parentPID, "parent-pid", 0, "PID of the LumiNet daemon to monitor")
	fs.StringVar(&cfg.dataDir, "data-dir", "", "LumiNet data directory containing durable host-network state")
	if err := fs.Parse(args); err != nil {
		return watchdogConfig{}, err
	}
	if cfg.parentPID <= 0 {
		return watchdogConfig{}, errors.New("--parent-pid must be a positive PID")
	}
	if cfg.dataDir == "" {
		return watchdogConfig{}, errors.New("--data-dir is required")
	}
	return cfg, nil
}

func monitorParent(
	ctx context.Context,
	parentPID int,
	dataDir string,
	interval time.Duration,
	parentAlive func(int) bool,
	recoverState func(context.Context, string) error,
) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if parentAlive(parentPID) {
				continue
			}
			recoverCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			err := recoverState(recoverCtx, dataDir)
			cancel()
			return err
		}
	}
}
