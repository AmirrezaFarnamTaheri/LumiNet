package xray

// REALITY protocol key generation and SNI selection.
// Source: WhiteDNS-Wizard-main/internal/secrets/generator.go
//         WhiteDNS-Wizard-main/internal/xui/reality_sni.go
//         WhiteDNS-Wizard-main/internal/xui/protocols.go
//
// WhiteDNS-Wizard is a tool for automatically provisioning x-ui (3x-ui panel)
// with Cloudflare DNS. The most valuable portable concepts:
// 1. REALITY X25519 key pair generation (exact clamping bits)
// 2. ML-KEM 768+X25519 hybrid post-quantum key format
// 3. REALITY SNI selection with TLS 1.3 validation and shuffle
// 4. x-ui inbound config generation for VLESS/Trojan/Hysteria2/Shadowsocks
// 5. Ordered URL query builder (preserves parameter order)
// 6. shortSubID: first 16 chars of stripped UUID (sub-subscription ID)

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
)

// ---------------------------------------------------------------------------
// REALITY Key Generation
// Source: WhiteDNS-Wizard/internal/secrets/generator.go realityKeyPair()
// ---------------------------------------------------------------------------

// GenerateRealityKeyPair generates a REALITY-compatible X25519 key pair.
// Uses the exact bit-clamping required by the REALITY/X25519 Diffie-Hellman spec:
//   - privateKey[0]  &= 248  (clear bottom 3 bits: cofactor clearing)
//   - privateKey[31] &= 127  (clear top bit: ensure scalar is < 2^255)
//   - privateKey[31] |= 64   (set bit 254: ensure scalar is >= 2^254)
//
// Returns (privateKeyBase64, publicKeyBase64, error).
// Both keys are encoded as base64url without padding (RawURLEncoding).
//
// Source: WhiteDNS-Wizard/internal/secrets/generator.go realityKeyPair()
func GenerateRealityKeyPair() (privateKey, publicKey string, err error) {
	priv := make([]byte, curve25519.ScalarSize)
	if _, err = rand.Read(priv); err != nil {
		return "", "", fmt.Errorf("generate reality private key: %w", err)
	}
	// X25519 clamping (RFC 7748 §5)
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return "", "", fmt.Errorf("generate reality public key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(priv),
		base64.RawURLEncoding.EncodeToString(pub),
		nil
}

// GenerateRealityShortID generates a random 8-byte hex short ID for REALITY.
// Source: WhiteDNS-Wizard/internal/secrets/generator.go randomHex(8)
func GenerateRealityShortID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate reality short ID: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// ---------------------------------------------------------------------------
// ML-KEM 768+X25519 Post-Quantum Hybrid Key Format
// Source: WhiteDNS-Wizard/internal/secrets/generator.go realityMLKEMValue()
// ---------------------------------------------------------------------------

// GenerateRealityMLKEMDecryption generates the ML-KEM decryption key value.
// Format: "mlkem768x25519plus.native.600s.<base64url-32-bytes>"
// The "600s" mode indicates 600-second validity window (decryption side).
// Source: WhiteDNS-Wizard/internal/secrets/generator.go realityMLKEMValue("600s")
func GenerateRealityMLKEMDecryption() (string, error) {
	return realityMLKEMValue("600s")
}

// GenerateRealityMLKEMEncryption generates the ML-KEM encryption key value.
// Format: "mlkem768x25519plus.native.0rtt.<base64url-32-bytes>"
// The "0rtt" mode indicates 0-RTT encryption (client-side key).
// Source: WhiteDNS-Wizard/internal/secrets/generator.go realityMLKEMValue("0rtt")
func GenerateRealityMLKEMEncryption() (string, error) {
	return realityMLKEMValue("0rtt")
}

// GenerateRealityMLDSA65Seed generates a random seed for ML-DSA-65 (Dilithium-level-3)
// post-quantum digital signature. The seed is 32 random bytes encoded as base64url.
// Source: WhiteDNS-Wizard/internal/secrets/generator.go randomToken(32)
func GenerateRealityMLDSA65Seed() (string, error) {
	return randomBase64URLToken(32)
}

func realityMLKEMValue(mode string) (string, error) {
	token, err := randomBase64URLToken(32)
	if err != nil {
		return "", err
	}
	return "mlkem768x25519plus.native." + mode + "." + token, nil
}

func randomBase64URLToken(bytesLen int) (string, error) {
	b := make([]byte, bytesLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// RandomBase64StdToken generates a random token of bytesLen bytes, encoded as
// standard base64 (with padding). Used for Shadowsocks 2022 passwords.
// Source: WhiteDNS-Wizard/internal/secrets/generator.go randomBase64Token()
func RandomBase64StdToken(bytesLen int) (string, error) {
	b := make([]byte, bytesLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate base64 token: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// RandomHex generates a random hex string of bytesLen bytes.
// Source: WhiteDNS-Wizard/internal/secrets/generator.go randomHex()
func RandomHex(bytesLen int) (string, error) {
	b := make([]byte, bytesLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate hex: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// RandomWSPath generates a random WebSocket path: "/tp-<8hexchars>".
// Source: WhiteDNS-Wizard/internal/secrets/generator.go randomPath()
func RandomWSPath() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate websocket path: %w", err)
	}
	return "/tp-" + hex.EncodeToString(b[:]), nil
}

// ---------------------------------------------------------------------------
// REALITY SNI Selection and TLS 1.3 Validation
// Source: WhiteDNS-Wizard/internal/xui/reality_sni.go
// ---------------------------------------------------------------------------

// RealitySNICandidates is the curated list of SNI candidates for REALITY.
// These are high-traffic TLS 1.3 servers suitable for fronting REALITY traffic.
// Source: WhiteDNS-Wizard/internal/secrets/generator.go realitySNICandidates
var RealitySNICandidates = []string{
	"apple.com",
	"docker.com",
}

// FallbackRealitySNI is the default SNI if all candidates fail validation.
// Source: WhiteDNS-Wizard/internal/xui/reality_sni.go fallbackRealitySNI
const FallbackRealitySNI = "apple.com"

// SelectRealitySNI validates the current REALITY SNI against the server and
// picks a working replacement if the current one fails or is empty.
//
// Algorithm:
//  1. If current SNI is non-empty and in the allowed candidates, validate it.
//     If valid → return it unchanged.
//     If invalid → try shuffled candidates.
//  2. If current is empty or not in the list, try shuffled candidates.
//  3. If all candidates fail, return FallbackRealitySNI.
//
// Validation: attempts a TLS 1.3 connection to hostname:443 with 4s timeout.
// Source: WhiteDNS-Wizard/internal/xui/reality_sni.go realitySNISelector.Select()
func SelectRealitySNI(ctx context.Context, current string, candidates []string) (selected string, changed bool, err error) {
	if len(candidates) == 0 {
		candidates = RealitySNICandidates
	}
	// Normalize candidates
	normalized := normalizeRealityCandidates(candidates)

	// Validate current if it's in the allowed set
	current = strings.TrimSpace(current)
	if current != "" {
		inSet := false
		for _, c := range normalized {
			if c == current {
				inSet = true
				break
			}
		}
		if inSet {
			if err := validateRealitySNI(ctx, current, 4*time.Second); err == nil {
				return current, false, nil
			}
		}
	}

	// Shuffle candidates and try each
	shuffled := append([]string(nil), normalized...)
	shuffleStrings(shuffled)
	for _, candidate := range shuffled {
		if candidate == current {
			continue
		}
		if err := validateRealitySNI(ctx, candidate, 4*time.Second); err == nil {
			return candidate, candidate != current, nil
		}
	}

	// All failed — use fallback
	return FallbackRealitySNI, FallbackRealitySNI != current, nil
}

// validateRealitySNI attempts a TLS 1.3 connection to hostname:443.
// Returns nil if the connection succeeds with TLS 1.3.
// Source: WhiteDNS-Wizard/internal/xui/reality_sni.go tlsRealitySNIValidator.Validate()
func validateRealitySNI(ctx context.Context, hostname string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dialer := &tls.Dialer{Config: &tls.Config{
		ServerName: hostname,
		MinVersion: tls.VersionTLS13,
	}}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(hostname, "443"))
	if err != nil {
		return err
	}
	defer conn.Close()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return fmt.Errorf("not a TLS connection")
	}
	if tlsConn.ConnectionState().Version != tls.VersionTLS13 {
		return fmt.Errorf("TLS version is not 1.3")
	}
	return nil
}

func normalizeRealityCandidates(candidates []string) []string {
	seen := map[string]bool{}
	normalized := make([]string, 0, len(candidates)+1)
	for _, c := range candidates {
		c = strings.TrimSpace(c)
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		normalized = append(normalized, c)
	}
	if !seen[FallbackRealitySNI] {
		normalized = append(normalized, FallbackRealitySNI)
	}
	return normalized
}

// shuffleStrings shuffles a string slice using crypto/rand (unbiased Fisher-Yates).
// Source: WhiteDNS-Wizard/internal/xui/reality_sni.go shuffleStrings()
func shuffleStrings(values []string) {
	for i := len(values) - 1; i > 0; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return
		}
		j := int(n.Int64())
		values[i], values[j] = values[j], values[i]
	}
}

// ---------------------------------------------------------------------------
// x-ui / 3x-ui Inbound Config Helpers
// Source: WhiteDNS-Wizard/internal/xui/protocols.go
// ---------------------------------------------------------------------------

// XUIRealityStreamSettings builds the Xray realitySettings block for a
// TCP Vision inbound (protocol: vless, flow: xtls-rprx-vision).
//
// Source: WhiteDNS-Wizard/internal/xui/protocols.go realityTCPVisionStream()
func XUIRealityStreamSettings(privateKey, publicKey, shortID, mldsa65Seed, sni string) map[string]any {
	if sni == "" {
		sni = FallbackRealitySNI
	}
	return map[string]any{
		"network":  "tcp",
		"security": "reality",
		"tcpSettings": map[string]any{
			"acceptProxyProtocol": false,
			"header":              map[string]any{"type": "none"},
		},
		"sockopt": map[string]any{
			"trustedXForwardedFor": []string{"WhiteDNS-No-Trusted-XFF"},
		},
		"realitySettings": map[string]any{
			"show":          false,
			"xver":          0,
			"target":        sni + ":443",
			"serverNames":   []string{sni},
			"privateKey":    privateKey,
			"minClientVer":  "",
			"maxClientVer":  "",
			"maxTimediff":   0,
			"shortIds":      []string{shortID},
			"mldsa65Seed":   mldsa65Seed,
			"settings": map[string]any{
				"publicKey":   publicKey,
				"fingerprint": "chrome",
				"serverName":  "",
				"spiderX":     "/",
			},
		},
	}
}

// XUIWSTLSStreamSettings builds the Xray WebSocket+TLS stream settings block.
// Source: WhiteDNS-Wizard/internal/xui/protocols.go wsTLSStream()
func XUIWSTLSStreamSettings(hostname, path, certPath, keyPath string) map[string]any {
	return map[string]any{
		"network":  "ws",
		"security": "tls",
		"wsSettings": map[string]any{
			"path": path,
			"host": hostname,
		},
		"tlsSettings": XUITLSSettings(hostname, certPath, keyPath, []string{"h2", "http/1.1"}),
		"sockopt": map[string]any{
			"trustedXForwardedFor": []string{"WhiteDNS-No-Trusted-XFF"},
		},
	}
}

// XUITLSSettings builds the Xray TLS settings block with file-based certificates.
// Source: WhiteDNS-Wizard/internal/xui/protocols.go tlsSettingsWithALPN()
func XUITLSSettings(serverName, certPath, keyPath string, alpn []string) map[string]any {
	return map[string]any{
		"serverName": serverName,
		"minVersion": "1.2",
		"alpn":       alpn,
		"certificates": []map[string]any{
			{
				"certificateFile": certPath,
				"keyFile":         keyPath,
			},
		},
	}
}

// XUIHysteria2StreamSettings builds the x-ui Hysteria2 stream settings with
// Salamander obfuscation and BBR congestion control.
// Source: WhiteDNS-Wizard/internal/xui/protocols.go hysteria2_direct case
func XUIHysteria2StreamSettings(hostname, obfsPassword, certPath, keyPath string) map[string]any {
	return map[string]any{
		"network":       "hysteria",
		"security":      "tls",
		"externalProxy": []any{},
		"hysteriaSettings": map[string]any{
			"version":        2,
			"udpIdleTimeout": 60,
		},
		"finalmask": map[string]any{
			"udp": []map[string]any{
				{
					"type": "salamander",
					"settings": map[string]any{
						"password": obfsPassword,
					},
				},
			},
			"quicParams": map[string]any{
				"congestion": "bbr",
			},
		},
		"tlsSettings": XUITLSSettings(hostname, certPath, keyPath, []string{"h3"}),
	}
}

// XUIBaseInbound builds the base Xray inbound object for x-ui.
// Source: WhiteDNS-Wizard/internal/xui/protocols.go baseInbound()
func XUIBaseInbound(remark, tag string, port int, protocol string) map[string]any {
	return map[string]any{
		"remark":         remark,
		"enable":         true,
		"port":           port,
		"protocol":       protocol,
		"tag":            tag,
		"settings":       map[string]any{},
		"streamSettings": map[string]any{},
		"sniffing": map[string]any{
			"enabled":      true,
			"destOverride": []string{"http", "tls", "quic", "fakedns"},
		},
	}
}

// XUIVLESSClient builds the x-ui VLESS client entry.
// Source: WhiteDNS-Wizard/internal/xui/protocols.go vlessClient()
func XUIVLESSClient(uuid, email, comment string, visionFlow bool) map[string]any {
	flow := ""
	if visionFlow {
		flow = "xtls-rprx-vision"
	}
	return map[string]any{
		"id":         uuid,
		"flow":       flow,
		"email":      email,
		"limitIp":    0,
		"totalGB":    0,
		"expiryTime": 0,
		"enable":     true,
		"tgId":       0,
		"subId":      XUIShortSubID(uuid),
		"comment":    comment,
		"reset":      0,
	}
}

// XUIShortSubID extracts the first 16 characters of a UUID/password string
// (after removing dashes and underscores) to use as a subscription sub-ID.
// Source: WhiteDNS-Wizard/internal/xui/protocols.go shortSubID()
func XUIShortSubID(value string) string {
	value = strings.NewReplacer("-", "", "_", "").Replace(value)
	if len(value) > 16 {
		return value[:16]
	}
	return value
}

// XUIDefaultSniffing returns the standard x-ui sniffing config.
func XUIDefaultSniffing() map[string]any {
	return map[string]any{
		"enabled":      true,
		"destOverride": []string{"http", "tls", "quic", "fakedns"},
	}
}

// ShadowsocksDefaultMethod returns the Shadowsocks method used by WhiteDNS.
// Source: WhiteDNS-Wizard/internal/xui/protocols.go shadowsocksMethod()
func ShadowsocksDefaultMethod() string {
	return "2022-blake3-aes-256-gcm"
}

// XUIPanelPort is the default port for the 3x-ui panel.
// Source: WhiteDNS-Wizard/internal/xui/protocols.go PanelPort
const XUIPanelPort = 2053
