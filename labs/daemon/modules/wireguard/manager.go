// Package wireguard provides management of WireGuard (wg) and AmneziaWG (awg) interfaces,
// configurations, keys, and NDP proxying.
// Ported from 3ax-ui-main/wg/ and 3ax-ui-main/awg/.
package wireguard

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
)

// Default config directories
const (
	WgConfigDir  = "/etc/wireguard"
	AwgConfigDir = "/etc/amnezia/amneziawg"

	ndppdConfigPath = "/etc/ndppd.conf"
	wgSectionBegin  = "# --- BEGIN WG ---"
	wgSectionEnd    = "# --- END WG ---"
)

// PeerStatus holds runtime stats for one peer parsed from `wg show` or `awg show`.
type PeerStatus struct {
	PublicKey           string `json:"publicKey"`
	Endpoint            string `json:"endpoint"`
	LatestHandshake     int64  `json:"latestHandshake"` // unix timestamp
	TransferRx          int64  `json:"transferRx"`      // bytes received
	TransferTx          int64  `json:"transferTx"`      // bytes transmitted
	PersistentKeepalive int    `json:"persistentKeepalive"`
}

// ── Key Generation (PL-002) ──────────────────────────────────────────────────

// GeneratePrivateKey generates a random X25519 private key (WireGuard format).
func GeneratePrivateKey() (string, error) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return "", err
	}
	// Clamp the key per X25519/WireGuard spec
	key[0] &= 248
	key[31] = (key[31] & 127) | 64
	return base64.StdEncoding.EncodeToString(key[:]), nil
}

// PublicKeyFromPrivate derives an X25519 public key from a private key.
func PublicKeyFromPrivate(privKeyBase64 string) (string, error) {
	privBytes, err := base64.StdEncoding.DecodeString(privKeyBase64)
	if err != nil {
		return "", err
	}
	pubBytes, err := curve25519.X25519(privBytes, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pubBytes), nil
}

// GenerateKeyPair generates a WireGuard private/public key pair.
func GenerateKeyPair() (privateKey, publicKey string, err error) {
	privateKey, err = GeneratePrivateKey()
	if err != nil {
		return
	}
	publicKey, err = PublicKeyFromPrivate(privateKey)
	return
}

// GeneratePresharedKey generates a random 256-bit preshared key.
func GeneratePresharedKey() (string, error) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key[:]), nil
}

// ── WireGuard & AmneziaWG Management ──────────────────────────────────────────

// WriteConfig writes the interface config string to the appropriate config directory.
func WriteConfig(isAmnezia bool, interfaceName string, config string) error {
	dir := WgConfigDir
	if isAmnezia {
		dir = AwgConfigDir
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	path := filepath.Join(dir, interfaceName+".conf")
	return os.WriteFile(path, []byte(config), 0600)
}

// RemoveConfig deletes the config file for the given interface from disk.
func RemoveConfig(isAmnezia bool, interfaceName string) error {
	dir := WgConfigDir
	if isAmnezia {
		dir = AwgConfigDir
	}
	path := filepath.Join(dir, interfaceName+".conf")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// InterfaceUp brings the interface up using wg-quick or awg-quick.
func InterfaceUp(isAmnezia bool, interfaceName string) error {
	tool := "wg-quick"
	dir := WgConfigDir
	if isAmnezia {
		tool = "awg-quick"
		dir = AwgConfigDir
	}
	configPath := filepath.Join(dir, interfaceName+".conf")
	cmd := exec.Command(tool, "up", configPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s up failed: %s: %w", tool, string(output), err)
	}
	return nil
}

// InterfaceDown takes the interface down using wg-quick or awg-quick.
func InterfaceDown(isAmnezia bool, interfaceName string) error {
	tool := "wg-quick"
	dir := WgConfigDir
	if isAmnezia {
		tool = "awg-quick"
		dir = AwgConfigDir
	}
	configPath := filepath.Join(dir, interfaceName+".conf")
	cmd := exec.Command(tool, "down", configPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s down failed: %s: %w", tool, string(output), err)
	}
	return nil
}

// SyncConfig applies config changes without dropping existing connections.
func SyncConfig(isAmnezia bool, interfaceName string) error {
	toolQuick := "wg-quick"
	toolBin := "wg"
	dir := WgConfigDir
	if isAmnezia {
		toolQuick = "awg-quick"
		toolBin = "awg"
		dir = AwgConfigDir
	}

	configPath := filepath.Join(dir, interfaceName+".conf")
	stripped, err := exec.Command(toolQuick, "strip", configPath).Output()
	if err != nil {
		return RestartInterface(isAmnezia, interfaceName)
	}

	syncCmd := exec.Command(toolBin, "syncconf", interfaceName, "/dev/stdin")
	syncCmd.Stdin = strings.NewReader(string(stripped))
	if output, err := syncCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("syncconf failed: %s: %w", string(output), err)
	}
	return nil
}

// RestartInterface performs a full down+up cycle.
func RestartInterface(isAmnezia bool, interfaceName string) error {
	_ = InterfaceDown(isAmnezia, interfaceName)
	time.Sleep(500 * time.Millisecond)
	return InterfaceUp(isAmnezia, interfaceName)
}

// IsInterfaceUp checks if the interface exists in the system.
func IsInterfaceUp(isAmnezia bool, interfaceName string) bool {
	tool := "wg"
	if isAmnezia {
		tool = "awg"
	}
	err := exec.Command(tool, "show", interfaceName).Run()
	return err == nil
}

// GetPeerStats parses show dump to get per-peer traffic stats.
func GetPeerStats(isAmnezia bool, interfaceName string) ([]PeerStatus, error) {
	tool := "wg"
	if isAmnezia {
		tool = "awg"
	}
	output, err := exec.Command(tool, "show", interfaceName, "dump").Output()
	if err != nil {
		return nil, fmt.Errorf("%s show dump failed: %w", tool, err)
	}

	var peers []PeerStatus
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	if scanner.Scan() {
		// Skip first line (interface info)
	}
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, "\t")
		if len(fields) < 8 {
			continue
		}
		handshake, _ := strconv.ParseInt(fields[4], 10, 64)
		rx, _ := strconv.ParseInt(fields[5], 10, 64)
		tx, _ := strconv.ParseInt(fields[6], 10, 64)
		keepalive, _ := strconv.Atoi(fields[7])

		peers = append(peers, PeerStatus{
			PublicKey:           fields[0],
			Endpoint:            fields[2],
			LatestHandshake:     handshake,
			TransferRx:          rx,
			TransferTx:          tx,
			PersistentKeepalive: keepalive,
		})
	}
	return peers, nil
}

// ── NDP Proxying & ndppd.conf Management ──────────────────────────────────────

var wgSectionRegex = regexp.MustCompile(`(?s)` + regexp.QuoteMeta(wgSectionBegin) + `.*?` + regexp.QuoteMeta(wgSectionEnd))

// ApplyNdppdConfig updates only the managed section in ndppd.conf.
func ApplyNdppdConfig(externalIface, tunnelIface, ipv6Pool string) error {
	newSection := fmt.Sprintf(`%s
proxy %s {
    router yes
    timeout 500
    ttl 30000
    rule %s {
        iface %s
    }
}
%s`, wgSectionBegin, externalIface, ipv6Pool, tunnelIface, wgSectionEnd)

	existing, err := os.ReadFile(ndppdConfigPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read ndppd config: %w", err)
	}

	var result string
	if len(existing) > 0 && wgSectionRegex.Match(existing) {
		result = wgSectionRegex.ReplaceAllString(string(existing), newSection)
	} else if len(existing) > 0 {
		result = strings.TrimRight(string(existing), "\n") + "\n\n" + newSection + "\n"
	} else {
		result = "route-ttl 30000\n\n" + newSection + "\n"
	}

	if err := os.WriteFile(ndppdConfigPath, []byte(result), 0644); err != nil {
		return fmt.Errorf("write ndppd config: %w", err)
	}

	if err := exec.Command("systemctl", "restart", "ndppd").Run(); err != nil {
		if err2 := exec.Command("service", "ndppd", "restart").Run(); err2 != nil {
			return fmt.Errorf("restart ndppd: %w", err2)
		}
	}
	return nil
}

// StopNdppd removes the managed section from ndppd.conf and stops ndppd.
func StopNdppd() {
	existing, err := os.ReadFile(ndppdConfigPath)
	if err != nil {
		_ = exec.Command("systemctl", "stop", "ndppd").Run()
		return
	}
	cleaned := strings.TrimSpace(wgSectionRegex.ReplaceAllString(string(existing), ""))
	if cleaned == "" || cleaned == "route-ttl 30000" {
		_ = os.Remove(ndppdConfigPath)
		_ = exec.Command("systemctl", "stop", "ndppd").Run()
	} else {
		_ = os.WriteFile(ndppdConfigPath, []byte(cleaned+"\n"), 0644)
		_ = exec.Command("systemctl", "restart", "ndppd").Run()
	}
}

// ── IPAM Allocation Helper ────────────────────────────────────────────────────

// AllocateIP finds the next free IP address in the CIDR pool.
func AllocateIP(pool string, serverAddr string, usedIPs []string, isIPv6 bool) (string, error) {
	_, ipNet, err := net.ParseCIDR(pool)
	if err != nil {
		return "", err
	}
	used := make(map[string]bool)
	if serverAddr != "" {
		used[stripMask(serverAddr)] = true
	}
	for _, a := range usedIPs {
		used[stripMask(a)] = true
	}

	if !isIPv6 {
		ip := ipNet.IP.To4()
		if ip == nil {
			return "", fmt.Errorf("not a valid IPv4 pool: %s", pool)
		}
		ipInt := binaryBigEndianUint32(ip)
		ones, bits := ipNet.Mask.Size()
		hostCount := uint32(1) << uint(bits-ones)

		for i := uint32(2); i < hostCount-1; i++ {
			candidate := make(net.IP, 4)
			binaryBigEndianPutUint32(candidate, ipInt+i)
			if !used[candidate.String()] {
				return candidate.String() + "/32", nil
			}
		}
	} else {
		baseIP := ipNet.IP.To16()
		if baseIP == nil {
			return "", fmt.Errorf("not a valid IPv6 pool: %s", pool)
		}
		// Allocate sequentially (limit search to 65536 for speed)
		for i := int64(2); i < 65536; i++ {
			ip := make(net.IP, 16)
			copy(ip, baseIP)
			// Simple low-order byte increment for IPv6 host allocation
			ip[15] += byte(i)
			if !used[ip.String()] {
				return ip.String() + "/128", nil
			}
		}
	}
	return "", fmt.Errorf("no free addresses in pool %s", pool)
}

func stripMask(addr string) string {
	if idx := strings.IndexByte(addr, '/'); idx >= 0 {
		return addr[:idx]
	}
	return addr
}

func binaryBigEndianUint32(b []byte) uint32 {
	return uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
}

func binaryBigEndianPutUint32(b []byte, v uint32) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}

// AddPeer adds or updates a peer on the running interface using `wg set` (no interface restart).
func AddPeer(isAmnezia bool, interfaceName, peerPublicKey, allowedIPs string) error {
	tool := "wg"
	if isAmnezia {
		tool = "awg"
	}
	cmd := exec.Command(tool, "set", interfaceName, "peer", peerPublicKey, "allowed-ips", allowedIPs)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add peer: %s: %w", string(output), err)
	}
	return nil
}

// RemovePeer removes a peer from the running interface using `wg set` (no interface restart).
func RemovePeer(isAmnezia bool, interfaceName, peerPublicKey string) error {
	tool := "wg"
	if isAmnezia {
		tool = "awg"
	}
	cmd := exec.Command(tool, "set", interfaceName, "peer", peerPublicKey, "remove")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to remove peer: %s: %w", string(output), err)
	}
	return nil
}
