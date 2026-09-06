// Package warp provides Cloudflare WARP account registration and WireGuard config generation.
//
// Features:
// - X25519 key pair generation
// - Cloudflare WARP account registration
// - WireGuard config generation for multiple clients
// - Warp-on-Warp (WoW) double-tunnel configs
package warp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/maybeknott/luminet/internal/foundation/remoteaction"
	"golang.org/x/crypto/curve25519"
)

const maxWARPRegistrationResponseBytes = 1 << 20

// WARPKey holds a registered WARP account's key material.
type WARPKey struct {
	PrivateKey    string `json:"private_key"`
	PublicKey     string `json:"public_key"`
	PeerPublicKey string `json:"peer_public_key"`
	Address       string `json:"address"`
	IPv6Address   string `json:"ipv6_address,omitempty"`
	Reserved      []int  `json:"reserved"`
	ClientID      string `json:"client_id,omitempty"`
	Endpoint      string `json:"endpoint"`
}

// CloudflareWarpPublicKey is the standard Cloudflare WARP public key.
const CloudflareWarpPublicKey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="

// RegisterWarpAccount registers a new WARP account with Cloudflare.
func RegisterWarpAccount() (*WARPKey, error) {
	return RegisterWarpAccountWithClient(context.Background(), nil)
}

// RegisterWarpAccountWithClient registers a WARP account with a caller-owned
// context and optional HTTP client. It exists so the production network
// boundary can be cancelled and deterministically exercised in tests.
func RegisterWarpAccountWithClient(ctx context.Context, client *http.Client) (*WARPKey, error) {
	if ctx == nil {
		return nil, errors.New("WARP registration context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Generate X25519 key pair
	privKey, pubKey, err := generateX25519KeyPair()
	if err != nil {
		return nil, fmt.Errorf("key generation failed: %w", err)
	}

	// Register with Cloudflare API
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	registrationURL := "https://api.cloudflareclient.com/v0a4005/reg"

	reqBody := fmt.Sprintf(`{"key":"%s","install_id":"","fcm_token":"","tos":"%s","model":"wireguard"}`,
		pubKey, time.Now().Format("2006-01-02T15:04:05.000Z"))

	// Registration creates account/device state without a readback identity that
	// can safely reconcile an ambiguous write. Keep it explicitly single-shot;
	// the shared remote-action owner prevents this POST from inheriting a broad
	// retry policy later.
	policy := remoteaction.DefaultPolicy("warp.account.register", remoteaction.SingleAttempt)
	policy.RateLimitScope = "provider.cloudflare-warp"
	outcome, err := remoteaction.Do(ctx, client, policy, func(ctx context.Context, _ int) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, registrationURL, strings.NewReader(reqBody))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "okhttp/3.12.1")
		return req, nil
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("registration failed: %w", err)
	}
	resp := outcome.Response
	if resp == nil {
		return nil, errors.New("WARP registration completed without response")
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("WARP registration returned HTTP status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxWARPRegistrationResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read WARP registration response: %w", err)
	}
	if len(body) > maxWARPRegistrationResponseBytes {
		return nil, fmt.Errorf("WARP registration response exceeds %d bytes", maxWARPRegistrationResponseBytes)
	}

	var result struct {
		Config struct {
			PrivateKey string `json:"private_key"`
			Peers      []struct {
				PublicKey string `json:"public_key"`
				Endpoint  struct {
					Host string `json:"host"`
				} `json:"endpoint"`
			} `json:"peers"`
			Interface struct {
				Addresses struct {
					V4 string `json:"v4"`
					V6 string `json:"v6"`
				} `json:"addresses"`
			} `json:"interface"`
			ClientID string `json:"client_id"`
		} `json:"config"`
		Account struct {
			AccountID string `json:"account_id"`
		} `json:"account"`
		Reserved []int `json:"reserved"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	if result.Config.Interface.Addresses.V4 == "" {
		return nil, errors.New("WARP registration response omitted IPv4 address")
	}

	reserved := result.Reserved
	if len(reserved) == 0 && result.Config.ClientID != "" {
		if decoded, err := base64.StdEncoding.DecodeString(result.Config.ClientID); err == nil {
			reserved = make([]int, len(decoded))
			for i, b := range decoded {
				reserved[i] = int(b)
			}
		}
	}
	// Fallback to [0, 0, 0] if still empty
	if len(reserved) < 3 {
		reserved = []int{0, 0, 0}
	}

	endpoint := "162.159.192.1:2408"
	peerPublicKey := ""
	if len(result.Config.Peers) > 0 && result.Config.Peers[0].Endpoint.Host != "" {
		endpoint = result.Config.Peers[0].Endpoint.Host
		peerPublicKey = result.Config.Peers[0].PublicKey
	}
	ipv6Address := ""
	if result.Config.Interface.Addresses.V6 != "" {
		ipv6Address = result.Config.Interface.Addresses.V6 + "/128"
	}

	return &WARPKey{
		PrivateKey:    privKey,
		PublicKey:     pubKey,
		PeerPublicKey: peerPublicKey,
		Address:       result.Config.Interface.Addresses.V4 + "/32",
		IPv6Address:   ipv6Address,
		Reserved:      reserved,
		ClientID:      result.Config.ClientID,
		Endpoint:      endpoint,
	}, nil
}

// GenerateWireGuardConfig generates a WireGuard .conf file content.
func GenerateWireGuardConfig(key *WARPKey, name string) string {
	var cfg strings.Builder

	cfg.WriteString("[Interface]\n")
	cfg.WriteString(fmt.Sprintf("PrivateKey = %s\n", key.PrivateKey))
	cfg.WriteString(fmt.Sprintf("Address = %s\n", key.Address))
	cfg.WriteString("DNS = 1.1.1.1, 2606:4700:4700::1111\n")
	cfg.WriteString("MTU = 1280\n")
	cfg.WriteString("\n")
	cfg.WriteString("[Peer]\n")
	cfg.WriteString(fmt.Sprintf("PublicKey = %s\n", CloudflareWarpPublicKey))
	cfg.WriteString(fmt.Sprintf("Endpoint = %s\n", key.Endpoint))
	cfg.WriteString("AllowedIPs = 0.0.0.0/0, ::/0\n")
	cfg.WriteString("PersistentKeepalive = 25\n")

	return cfg.String()
}

// GenerateV2RayWireGuardURL generates a wireguard:// URL for V2rayNG/MahsaNG.
func GenerateV2RayWireGuardURL(key *WARPKey, name string) string {
	reserved := normalizedReserved(key.Reserved)
	params := fmt.Sprintf("address=%s&publickey=%s&privatekey=%s&reserved=%d,%d,%d&mtu=1280&wnoise=10-20&wnoisecount=15&wnoisedelay=1-3&keepalive=25",
		key.Address,
		CloudflareWarpPublicKey,
		key.PrivateKey,
		reserved[0], reserved[1], reserved[2],
	)

	return fmt.Sprintf("wireguard://%%s@%s?%s#%s",
		key.Endpoint,
		params,
		url.PathEscape(name),
	)
}

// GenerateSingBoxWireGuardConfig generates a sing-box JSON WireGuard outbound.
func GenerateSingBoxWireGuardConfig(key *WARPKey, name string) map[string]interface{} {
	host, port := endpointHostPort(key.Endpoint)
	return map[string]interface{}{
		"type":            "wireguard",
		"tag":             name,
		"server":          host,
		"server_port":     port,
		"local_address":   []string{key.Address},
		"private_key":     key.PrivateKey,
		"peer_public_key": CloudflareWarpPublicKey,
		"reserved":        key.Reserved,
		"mtu":             1280,
		"fake_packets":    "10-20",
	}
}

// GenerateHiddifyConfig generates a Hiddify-compatible WireGuard JSON config.
func GenerateHiddifyConfig(key *WARPKey, name string) map[string]interface{} {
	host, port := endpointHostPort(key.Endpoint)
	return map[string]interface{}{
		"outbounds": []map[string]interface{}{
			{
				"type":            "wireguard",
				"tag":             name,
				"server":          host,
				"server_port":     port,
				"local_address":   []string{key.Address},
				"private_key":     key.PrivateKey,
				"peer_public_key": CloudflareWarpPublicKey,
				"reserved":        key.Reserved,
				"mtu":             1280,
				"fake_packets":    "10-20",
			},
		},
	}
}

// PingEndpoint verifies that a WARP endpoint completes a WireGuard handshake.
// A UDP socket connect is deliberately not considered a successful probe: UDP
// is connectionless and cannot prove that a WARP peer received or accepted it.
func PingEndpoint(endpoint string, timeout time.Duration) (time.Duration, error) {
	addr, err := netip.ParseAddrPort(endpoint)
	if err != nil {
		return 0, fmt.Errorf("invalid WARP endpoint %q: %w", endpoint, err)
	}
	if timeout <= 0 {
		return 0, errors.New("WARP endpoint timeout must be positive")
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	results := NewWarpScanner(WarpScannerOptions{
		ConcurrentScanners: 1,
		ConnectionTimeout:  timeout,
		HandshakeTimeout:   timeout,
	}).Scan(ctx, []netip.AddrPort{addr})
	if len(results) != 1 {
		return 0, errors.New("WARP endpoint probe produced no result")
	}
	if !results[0].Success {
		if results[0].Error == "" {
			return 0, errors.New("WARP endpoint handshake was not accepted")
		}
		return 0, fmt.Errorf("WARP endpoint handshake failed: %s", results[0].Error)
	}
	return results[0].RTT, nil
}

// ScanEndpoints scans multiple WARP endpoints and returns sorted by latency.
func ScanEndpoints(endpoints []string, timeout time.Duration) []EndpointResult {
	type result struct {
		Endpoint string
		Latency  time.Duration
		Error    error
	}

	ch := make(chan result, len(endpoints))
	for _, ep := range endpoints {
		go func(e string) {
			lat, err := PingEndpoint(e, timeout)
			ch <- result{e, lat, err}
		}(ep)
	}

	var results []EndpointResult
	for range endpoints {
		r := <-ch
		if r.Error == nil {
			results = append(results, EndpointResult{
				Endpoint: r.Endpoint,
				Latency:  r.Latency,
			})
		}
	}

	// Sort by latency
	for i := 0; i < len(results); i++ {
		for j := i + 1; j < len(results); j++ {
			if results[j].Latency < results[i].Latency {
				results[i], results[j] = results[j], results[i]
			}
		}
	}

	return results
}

// EndpointResult holds a scan result.
type EndpointResult struct {
	Endpoint string        `json:"endpoint"`
	Latency  time.Duration `json:"latency"`
}

// Helper: generate X25519 key pair using golang.org/x/crypto/curve25519
// GenerateWireGuardKeyPair returns a fresh X25519 WireGuard key pair in public/private order.
// Mobile and other adapters use this owner instead of reconstructing WARP key generation.
func GenerateWireGuardKeyPair() (publicKey, privateKey string, err error) {
	privateKey, publicKey, err = generateX25519KeyPair()
	return publicKey, privateKey, err
}

func generateX25519KeyPair() (privKey, pubKey string, err error) {
	var privateKey [32]byte
	if _, err := rand.Read(privateKey[:]); err != nil {
		return "", "", err
	}
	// Clamp private key
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return base64.StdEncoding.EncodeToString(privateKey[:]),
		base64.StdEncoding.EncodeToString(publicKey[:]),
		nil
}

func normalizedReserved(reserved []int) [3]int {
	var normalized [3]int
	copy(normalized[:], reserved)
	return normalized
}

func endpointHostPort(endpoint string) (string, int) {
	host, rawPort, err := net.SplitHostPort(endpoint)
	if err != nil {
		return endpoint, 2408
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil || port < 1 || port > 65535 {
		return host, 2408
	}
	return host, port
}
