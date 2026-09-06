package proxy

import (
	"fmt"
	"os"
	"os/exec"
	"sync"
)

// managedConfigProcess owns the shared lifecycle used by external proxy-engine
// binaries. Engine-specific wrappers retain their public configuration APIs.
type managedConfigProcess struct {
	mu         sync.Mutex
	cmd        *exec.Cmd
	configPath string
}

func (p *managedConfigProcess) start(binaryPath, configPattern string, config []byte, alreadyRunning string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cmd != nil && p.cmd.Process != nil {
		return fmt.Errorf("%s", alreadyRunning)
	}

	configFile, err := os.CreateTemp("", configPattern)
	if err != nil {
		return err
	}
	p.configPath = configFile.Name()
	if _, err := configFile.Write(config); err != nil {
		_ = configFile.Close()
		_ = os.Remove(p.configPath)
		p.configPath = ""
		return err
	}
	if err := configFile.Close(); err != nil {
		_ = os.Remove(p.configPath)
		p.configPath = ""
		return err
	}

	cmd := exec.Command(binaryPath, "-config", p.configPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		_ = os.Remove(p.configPath)
		p.configPath = ""
		return err
	}
	p.cmd = cmd
	return nil
}

func (p *managedConfigProcess) stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cmd == nil || p.cmd.Process == nil {
		return nil
	}
	err := p.cmd.Process.Kill()
	_, _ = p.cmd.Process.Wait()
	p.cmd = nil
	if p.configPath != "" {
		_ = os.Remove(p.configPath)
		p.configPath = ""
	}
	return err
}
