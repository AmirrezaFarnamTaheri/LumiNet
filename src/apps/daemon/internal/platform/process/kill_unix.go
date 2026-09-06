//go:build !windows

package process

import (
	"os/exec"
	"syscall"
)

// KillDaemonProcess terminates the daemon process group created by
// GetDaemonSysProcAttr. It falls back to killing only the process when group
// discovery is unavailable.
func KillDaemonProcess(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	pid := cmd.Process.Pid
	if pgid, err := syscall.Getpgid(pid); err == nil && pgid > 0 {
		if err := syscall.Kill(-pgid, syscall.SIGKILL); err == nil {
			return nil
		}
	}
	return cmd.Process.Kill()
}
