//go:build !linux

package cmd

func initSandbox(secureDir string, dataDir string, cfgFile string) error {
	return nil
}
