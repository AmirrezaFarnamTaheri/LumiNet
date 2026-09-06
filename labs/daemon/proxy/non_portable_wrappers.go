package proxy

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// RunRouteSetupScript executes platform-specific scripts (like .bat files on Windows or .sh on Linux)
// to set up routes for tun2socks.
func RunRouteSetupScript(ctx context.Context, scriptPath string) error {
	if _, err := os.Stat(scriptPath); err != nil {
		return fmt.Errorf("script not found: %w", err)
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd.exe", "/c", scriptPath)
	} else {
		cmd = exec.CommandContext(ctx, "bash", scriptPath)
	}

	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("script execution failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// LaunchSystemTrayGUI launches the Windows/Linux native system tray GUI process.
func LaunchSystemTrayGUI(ctx context.Context, guiPath string) error {
	if _, err := os.Stat(guiPath); err != nil {
		return fmt.Errorf("GUI binary not found: %w", err)
	}

	cmd := exec.CommandContext(ctx, guiPath)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start GUI: %w", err)
	}

	// Let it run in background
	go func() {
		_ = cmd.Wait()
	}()

	return nil
}

// RunPythonScraper launches a Python script (like the Node/Psiphon backup scrapers).
func RunPythonScraper(ctx context.Context, scriptPath string, args ...string) error {
	if _, err := os.Stat(scriptPath); err != nil {
		return fmt.Errorf("scraper script not found: %w", err)
	}

	// Find python interpreter
	pyCmd := "python"
	if _, err := exec.LookPath("python3"); err == nil {
		pyCmd = "python3"
	}

	cmdArgs := append([]string{scriptPath}, args...)
	cmd := exec.CommandContext(ctx, pyCmd, cmdArgs...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("scraper execution failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}

	return nil
}
