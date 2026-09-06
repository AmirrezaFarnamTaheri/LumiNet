//go:build windows

package process

import (
	"fmt"
	"os/exec"
	"strconv"
)

// KillDaemonProcess terminates the process tree rooted at cmd.
func KillDaemonProcess(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	kill := exec.Command("taskkill", "/F", "/T", "/PID", strconv.Itoa(cmd.Process.Pid))
	kill.SysProcAttr = GetHideWindowSysProcAttr()
	if out, err := kill.CombinedOutput(); err != nil {
		if processErr := cmd.Process.Kill(); processErr != nil {
			return fmt.Errorf("taskkill failed: %v (%s); process kill failed: %w", err, out, processErr)
		}
	}
	return nil
}
