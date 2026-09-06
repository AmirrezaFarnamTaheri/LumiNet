//go:build linux

package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/landlock-lsm/go-landlock/landlock"
)

func initSandbox(secureDir string, dataDir string, cfgFile string) error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	exeDir := filepath.Dir(exePath)

	filterPaths := func(paths []string) []string {
		var filtered []string
		for _, p := range paths {
			if _, err := os.Stat(p); err == nil {
				filtered = append(filtered, p)
			}
		}
		return filtered
	}

	rwDirs := filterPaths([]string{secureDir, dataDir, os.TempDir(), filepath.Dir(cfgFile)})
	rwFiles := filterPaths([]string{cfgFile, "/dev/net/tun", "/dev/tpm0", "/dev/tpmrm0"})
	roDirs := filterPaths([]string{"/etc", "/usr", "/lib", "/lib64", "/sys", "/proc", exeDir})

	var rules []landlock.Rule
	if len(rwDirs) > 0 {
		rules = append(rules, landlock.RWDirs(rwDirs...))
	}
	if len(rwFiles) > 0 {
		rules = append(rules, landlock.RWFiles(rwFiles...))
	}
	if len(roDirs) > 0 {
		rules = append(rules, landlock.RODirs(roDirs...))
	}

	// Apply Landlock sandboxing using best effort
	err = landlock.V8.BestEffort().RestrictPaths(rules...)
	if err != nil {
		return fmt.Errorf("failed to restrict filesystem via Landlock: %w", err)
	}

	return nil
}
