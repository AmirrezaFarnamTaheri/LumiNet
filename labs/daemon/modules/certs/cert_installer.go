package certs

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	FXMarker = "// luminet: auto-added, safe to strip with --remove-cert"
	FXPref   = `user_pref("security.enterprise_roots.enabled", true);`
)

// InstallRootCA installs a PEM-encoded CA certificate to the system trust store of the current OS
// and best-effort NSS/Firefox user profile configurations.
func InstallRootCA(certPEM []byte, commonName string) error {
	var err error
	switch runtime.GOOS {
	case "windows":
		err = InstallRootCAToWindows(certPEM)
	case "darwin":
		err = InstallRootCAToMac(certPEM, commonName)
	case "linux":
		err = InstallRootCAToLinux(certPEM, commonName)
	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}

	// Flipping enterprise_roots enables auto-importing OS roots for Firefox/LibreWolf.
	_ = EnableMozillaEnterpriseRoots()

	// Best-effort certutil-based insertion for direct NSS stores.
	_ = InstallNssStores(certPEM, commonName)

	return err
}

// RemoveRootCA removes the CA certificate from the system trust store of the current OS
// and cleans up NSS/Firefox configurations.
func RemoveRootCA(commonName string) error {
	var err error
	switch runtime.GOOS {
	case "windows":
		err = RemoveRootCAFromWindows(commonName)
	case "darwin":
		err = RemoveRootCAFromMac(commonName)
	case "linux":
		err = RemoveRootCAFromLinux(commonName)
	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}

	_ = DisableMozillaEnterpriseRoots()
	_ = RemoveNssStores(commonName)

	return err
}

// InstallRootCAToWindows installs a PEM-encoded CA certificate into the Windows Trusted Root Certification Authorities store.
func InstallRootCAToWindows(certPEM []byte) error {
	if runtime.GOOS != "windows" {
		return errors.New("installation is only supported on Windows")
	}

	tmpFile, err := os.CreateTemp("", "luminet_ca_*.crt")
	if err != nil {
		return fmt.Errorf("failed to create temp cert file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := tmpFile.Write(certPEM); err != nil {
		return fmt.Errorf("failed to write temp cert file: %w", err)
	}

	// Try user store first (no admin required)
	cmd := exec.Command("certutil", "-addstore", "-user", "Root", tmpFile.Name())
	if output, err := cmd.CombinedOutput(); err == nil {
		return nil
	} else {
		// Fallback to system store (needs admin)
		cmdSystem := exec.Command("certutil", "-addstore", "Root", tmpFile.Name())
		if outputSystem, err := cmdSystem.CombinedOutput(); err != nil {
			return fmt.Errorf("certutil addstore failed: %w, user-output: %s, system-output: %s", err, string(output), string(outputSystem))
		}
	}

	return nil
}

// RemoveRootCAFromWindows removes a CA certificate from the Windows Trusted Root store by its Common Name (subject).
func RemoveRootCAFromWindows(commonName string) error {
	if runtime.GOOS != "windows" {
		return errors.New("removal is only supported on Windows")
	}

	// Try removing from user store
	cmdUser := exec.Command("certutil", "-delstore", "-user", "Root", commonName)
	_ = cmdUser.Run()

	// Try removing from system store
	cmdSystem := exec.Command("certutil", "-delstore", "Root", commonName)
	_ = cmdSystem.Run()

	return nil
}

// InstallRootCAToMac installs a PEM-encoded CA certificate into macOS Keychain.
func InstallRootCAToMac(certPEM []byte, commonName string) error {
	if runtime.GOOS != "darwin" {
		return errors.New("installation is only supported on macOS")
	}

	tmpFile, err := os.CreateTemp("", "luminet_ca_*.crt")
	if err != nil {
		return fmt.Errorf("failed to create temp cert file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := tmpFile.Write(certPEM); err != nil {
		return fmt.Errorf("failed to write temp cert file: %w", err)
	}

	home := os.Getenv("HOME")
	loginKC := filepath.Join(home, "Library/Keychains/login.keychain-db")
	if _, err := os.Stat(loginKC); os.IsNotExist(err) {
		loginKC = filepath.Join(home, "Library/Keychains/login.keychain")
	}

	// Try login keychain (no password required)
	cmd := exec.Command("security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", loginKC, tmpFile.Name())
	if err := cmd.Run(); err == nil {
		return nil
	}

	// Fallback to System keychain (requires sudo/elevation)
	cmdSudo := exec.Command("sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", tmpFile.Name())
	if output, err := cmdSudo.CombinedOutput(); err != nil {
		return fmt.Errorf("macOS keychain install failed: %w, output: %s", err, string(output))
	}

	return nil
}

// RemoveRootCAFromMac removes a CA certificate from the macOS keychain.
func RemoveRootCAFromMac(commonName string) error {
	if runtime.GOOS != "darwin" {
		return errors.New("removal is only supported on macOS")
	}

	home := os.Getenv("HOME")
	loginKC := filepath.Join(home, "Library/Keychains/login.keychain-db")
	if _, err := os.Stat(loginKC); os.IsNotExist(err) {
		loginKC = filepath.Join(home, "Library/Keychains/login.keychain")
	}

	cmd := exec.Command("security", "delete-certificate", "-c", commonName, loginKC)
	_ = cmd.Run()

	// Check if system keychain has it, if so delete via sudo
	cmdCheck := exec.Command("security", "find-certificate", "-a", "-c", commonName, "/Library/Keychains/System.keychain")
	if err := cmdCheck.Run(); err == nil {
		cmdSudo := exec.Command("sudo", "security", "delete-certificate", "-c", commonName, "/Library/Keychains/System.keychain")
		_ = cmdSudo.Run()
	}

	return nil
}

// InstallRootCAToLinux installs a PEM-encoded CA certificate to Linux system stores.
func InstallRootCAToLinux(certPEM []byte, commonName string) error {
	if runtime.GOOS != "linux" {
		return errors.New("installation is only supported on Linux")
	}

	tmpFile, err := os.CreateTemp("", "luminet_ca_*.crt")
	if err != nil {
		return fmt.Errorf("failed to create temp cert file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := tmpFile.Write(certPEM); err != nil {
		return fmt.Errorf("failed to write temp cert file: %w", err)
	}

	distro := detectLinuxDistro()
	safeName := strings.ReplaceAll(commonName, " ", "_")

	var destPath string
	var refreshCmd [][]string

	switch distro {
	case "debian":
		destPath = fmt.Sprintf("/usr/local/share/ca-certificates/%s.crt", safeName)
		refreshCmd = [][]string{{"update-ca-certificates"}}
	case "rhel":
		destPath = fmt.Sprintf("/etc/pki/ca-trust/source/anchors/%s.crt", safeName)
		refreshCmd = [][]string{{"update-ca-trust", "extract"}}
	case "arch":
		destPath = fmt.Sprintf("/etc/ca-certificates/trust-source/anchors/%s.crt", safeName)
		refreshCmd = [][]string{{"trust", "extract-compat"}}
	default:
		return fmt.Errorf("unsupported Linux distro family: %s", distro)
	}

	// Try direct copy first
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err == nil {
		if err := copyFile(tmpFile.Name(), destPath); err == nil {
			allOk := true
			for _, args := range refreshCmd {
				cmd := exec.Command(args[0], args[1:]...)
				if err := cmd.Run(); err != nil {
					allOk = false
					break
				}
			}
			if allOk {
				return nil
			}
		}
	}

	// Fallback to sudo
	cmdCp := exec.Command("sudo", "cp", tmpFile.Name(), destPath)
	if err := cmdCp.Run(); err != nil {
		return fmt.Errorf("failed to copy cert via sudo: %w", err)
	}

	for _, args := range refreshCmd {
		sudoArgs := append([]string{args[0]}, args[1:]...)
		cmd := exec.Command("sudo", sudoArgs...)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to execute refresh command %v via sudo: %w", args, err)
		}
	}

	return nil
}

// RemoveRootCAFromLinux removes a CA certificate from Linux system stores.
func RemoveRootCAFromLinux(commonName string) error {
	if runtime.GOOS != "linux" {
		return errors.New("removal is only supported on Linux")
	}

	safeName := strings.ReplaceAll(commonName, " ", "_")
	anchors := []struct {
		dir     string
		refresh []string
	}{
		{dir: "/usr/local/share/ca-certificates", refresh: []string{"update-ca-certificates"}},
		{dir: "/etc/pki/ca-trust/source/anchors", refresh: []string{"update-ca-trust", "extract"}},
		{dir: "/etc/ca-certificates/trust-source/anchors", refresh: []string{"trust", "extract-compat"}},
	}

	for _, anchor := range anchors {
		if _, err := os.Stat(anchor.dir); os.IsNotExist(err) {
			continue
		}
		path := filepath.Join(anchor.dir, safeName+".crt")
		if _, err := os.Stat(path); err == nil {
			if err := os.Remove(path); err != nil {
				// Fallback to sudo
				_ = exec.Command("sudo", "rm", "-f", path).Run()
			}
		}

		// Always refresh
		cmd := exec.Command(anchor.refresh[0], anchor.refresh[1:]...)
		if err := cmd.Run(); err != nil {
			sudoArgs := append([]string{anchor.refresh[0]}, anchor.refresh[1:]...)
			_ = exec.Command("sudo", sudoArgs...).Run()
		}
	}

	return nil
}

// EnableMozillaEnterpriseRoots enables enterprise roots in Firefox and LibreWolf profiles.
func EnableMozillaEnterpriseRoots() error {
	dirs := mozillaFamilyProfileDirs()
	for _, p := range dirs {
		userJS := filepath.Join(p, "user.js")
		existingBytes, _ := os.ReadFile(userJS)
		existing := string(existingBytes)

		if strings.Contains(existing, FXMarker) {
			continue // Already enabled
		}
		if strings.Contains(existing, "security.enterprise_roots.enabled") {
			continue // User owned, do not overwrite
		}

		var newContent string
		if len(existing) > 0 && !strings.HasSuffix(existing, "\n") {
			newContent = existing + "\n" + FXMarker + "\n" + FXPref + "\n"
		} else {
			newContent = existing + FXMarker + "\n" + FXPref + "\n"
		}
		_ = os.WriteFile(userJS, []byte(newContent), 0644)
	}
	return nil
}

// DisableMozillaEnterpriseRoots disables enterprise roots in Firefox and LibreWolf profiles.
func DisableMozillaEnterpriseRoots() error {
	dirs := mozillaFamilyProfileDirs()
	for _, p := range dirs {
		userJS := filepath.Join(p, "user.js")
		existingBytes, err := os.ReadFile(userJS)
		if err != nil {
			continue
		}
		existing := string(existingBytes)
		if !strings.Contains(existing, FXMarker) {
			continue
		}

		// Parse and strip the block
		lines := strings.Split(existing, "\n")
		var out []string
		for i := 0; i < len(lines); i++ {
			trimmed := strings.TrimSpace(lines[i])
			if trimmed == FXMarker {
				if i+1 < len(lines) && strings.TrimSpace(lines[i+1]) == FXPref {
					i++
					continue
				}
			}
			out = append(out, lines[i])
		}
		newContent := strings.Join(out, "\n")
		_ = os.WriteFile(userJS, []byte(newContent), 0644)
	}
	return nil
}

// InstallNssStores installs the CA cert into discovered NSS profile and Chromium DBs.
func InstallNssStores(certPEM []byte, commonName string) error {
	if !hasNssCertutil() {
		return nil
	}

	tmpFile, err := os.CreateTemp("", "luminet_nss_ca_*.crt")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()
	_, _ = tmpFile.Write(certPEM)

	// Firefox / LibreWolf profiles
	profiles := mozillaFamilyProfileDirs()
	for _, p := range profiles {
		installNssInProfile(p, tmpFile.Name(), commonName)
	}

	// Chromium shared DB (Linux only)
	if runtime.GOOS == "linux" {
		home := os.Getenv("HOME")
		nssdb := filepath.Join(home, ".pki/nssdb")
		if _, err := os.Stat(nssdb); err == nil {
			dirArg := "sql:" + nssdb
			installNssInDir(dirArg, tmpFile.Name(), commonName)
		}
	}

	return nil
}

// RemoveNssStores removes the CA cert from discovered NSS profile and Chromium DBs.
func RemoveNssStores(commonName string) error {
	if !hasNssCertutil() {
		return nil
	}

	profiles := mozillaFamilyProfileDirs()
	for _, p := range profiles {
		removeNssInProfile(p, commonName)
	}

	if runtime.GOOS == "linux" {
		home := os.Getenv("HOME")
		nssdb := filepath.Join(home, ".pki/nssdb")
		if _, err := os.Stat(nssdb); err == nil {
			dirArg := "sql:" + nssdb
			removeNssInDir(dirArg, commonName)
		}
	}

	return nil
}

func installNssInProfile(profile string, certPath string, commonName string) bool {
	prefix := ""
	if _, err := os.Stat(filepath.Join(profile, "cert9.db")); err == nil {
		prefix = "sql:"
	} else if _, err := os.Stat(filepath.Join(profile, "cert8.db")); err == nil {
		prefix = ""
	} else {
		return false
	}
	dirArg := prefix + profile
	return installNssInDir(dirArg, certPath, commonName)
}

func removeNssInProfile(profile string, commonName string) bool {
	prefix := ""
	if _, err := os.Stat(filepath.Join(profile, "cert9.db")); err == nil {
		prefix = "sql:"
	} else if _, err := os.Stat(filepath.Join(profile, "cert8.db")); err == nil {
		prefix = ""
	} else {
		return false
	}
	dirArg := prefix + profile
	return removeNssInDir(dirArg, commonName)
}

func installNssInDir(dirArg string, certPath string, commonName string) bool {
	// Clear stale first
	_ = exec.Command("certutil", "-D", "-n", commonName, "-d", dirArg).Run()
	cmd := exec.Command("certutil", "-A", "-n", commonName, "-t", "C,,", "-d", dirArg, "-i", certPath)
	return cmd.Run() == nil
}

func removeNssInDir(dirArg string, commonName string) bool {
	cmd := exec.Command("certutil", "-D", "-n", commonName, "-d", dirArg)
	return cmd.Run() == nil
}

func detectLinuxDistro() string {
	if _, err := os.Stat("/etc/openwrt_release"); err == nil {
		return "openwrt"
	}
	if _, err := os.Stat("/etc/debian_version"); err == nil {
		return "debian"
	}
	if _, err := os.Stat("/etc/redhat-release"); err == nil {
		return "rhel"
	}
	if _, err := os.Stat("/etc/fedora-release"); err == nil {
		return "rhel"
	}
	if _, err := os.Stat("/etc/arch-release"); err == nil {
		return "arch"
	}
	if bytes, err := os.ReadFile("/etc/os-release"); err == nil {
		content := string(bytes)
		if strings.Contains(content, "ubuntu") || strings.Contains(content, "debian") || strings.Contains(content, "mint") {
			return "debian"
		}
		if strings.Contains(content, "fedora") || strings.Contains(content, "rhel") || strings.Contains(content, "centos") || strings.Contains(content, "rocky") {
			return "rhel"
		}
		if strings.Contains(content, "arch") || strings.Contains(content, "manjaro") {
			return "arch"
		}
	}
	return "unknown"
}

func mozillaFamilyProfileDirs() []string {
	var roots []string
	home := os.Getenv("HOME")
	appdata := os.Getenv("APPDATA")

	switch runtime.GOOS {
	case "darwin":
		roots = []string{
			filepath.Join(home, "Library/Application Support/Firefox/Profiles"),
			filepath.Join(home, "Library/Application Support/LibreWolf/Profiles"),
		}
	case "linux":
		roots = []string{
			filepath.Join(home, ".mozilla/firefox"),
			filepath.Join(home, "snap/firefox/common/.mozilla/firefox"),
			filepath.Join(home, ".librewolf"),
			filepath.Join(home, ".config/librewolf/librewolf"),
			filepath.Join(home, ".var/app/io.gitlab.librewolf-community/.librewolf"),
			filepath.Join(home, ".var/app/io.gitlab.librewolf-community/.config/librewolf/librewolf"),
			filepath.Join(home, ".mozilla/icecat"),
		}
	case "windows":
		if appdata != "" {
			roots = []string{
				filepath.Join(appdata, "Mozilla\\Firefox\\Profiles"),
				filepath.Join(appdata, "LibreWolf\\Profiles"),
			}
		}
	}

	var dirs []string
	for _, r := range roots {
		entries, err := os.ReadDir(r)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			p := filepath.Join(r, e.Name())
			if _, err := os.Stat(filepath.Join(p, "cert9.db")); err == nil {
				dirs = append(dirs, p)
			} else if _, err := os.Stat(filepath.Join(p, "cert8.db")); err == nil {
				dirs = append(dirs, p)
			}
		}
	}
	return dirs
}

func hasNssCertutil() bool {
	// Look for a certutil binary that supports NSS-specific flags
	cmd := exec.Command("certutil", "--help")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(output)), "nickname")
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// GenerateCertPEM utility converts an x509 certificate to PEM bytes.
func GenerateCertPEM(cert *x509.Certificate) []byte {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	return pem.EncodeToMemory(block)
}

// UpstreamChainingConfig generates Xray outbound routing pointing to Psiphon upstream proxy
type UpstreamChainingConfig struct {
	InboundPort  int
	UpstreamPort int
	CDNServer    string
	TargetSNI    string
	ALPN         []string
}

// ConfigureUpstreamMitmRules generates local mixed-port configurations redirecting traffic through Xray MITM layer.
func ConfigureUpstreamMitmRules(cfg UpstreamChainingConfig) string {
	// Returns a snippet of Xray configuration JSON routing rules
	return fmt.Sprintf(`{
  "inbounds": [
    {
      "tag": "mixed_inbound",
      "port": %d,
      "protocol": "mixed",
      "settings": {
        "sns": ["%s"]
      }
    }
  ],
  "outbounds": [
    {
      "tag": "upstream_psiphon",
      "protocol": "socks",
      "settings": {
        "servers": [
          {
            "address": "127.0.0.1",
            "port": %d
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "serverName": "%s",
          "alpn": %v,
          "allowInsecure": true
        }
      }
    }
  ]
}`, cfg.InboundPort, cfg.TargetSNI, cfg.UpstreamPort, cfg.CDNServer, serializeALPN(cfg.ALPN))
}

func serializeALPN(alpn []string) string {
	if len(alpn) == 0 {
		return `["h2", "http/1.1"]`
	}
	var res []string
	for _, val := range alpn {
		res = append(res, fmt.Sprintf("%q", val))
	}
	return fmt.Sprintf("[%s]", strings.Join(res, ", "))
}
