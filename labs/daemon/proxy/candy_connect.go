// Package proxy implements proxy protocols and connection utilities for LumiNet.
// Ported from: CandyConnect (Tauri Config Builder & WireGuard Loops)
// Target path: server/internal/proxy/candy_connect.go
package proxy

import (
	"encoding/json"
	"fmt"
)

// CandyConfigBuilder implements automated configuration generation for sing-box routing modes.
type CandyConfigBuilder struct{}

// NewCandyConfigBuilder creates a new config builder.
func NewCandyConfigBuilder() *CandyConfigBuilder {
	return &CandyConfigBuilder{}
}

// BuildModeTunSocks generates a sing-box configuration block that attaches a TUN interface
// using the gVisor stack and routes all traffic to a local SOCKS5 proxy.
func (b *CandyConfigBuilder) BuildModeTunSocks(socksPort int) (string, error) {
	config := map[string]interface{}{
		"log": map[string]interface{}{
			"level": "warn",
		},
		"inbounds": []map[string]interface{}{
			{
				"type":                     "tun",
				"tag":                      "tun-in",
				"interface_name":           "tun0",
				"stack":                    "gvisor",
				"mtu":                      9000,
				"auto_route":               true,
				"strict_route":             true,
				"endpoint_independent_nat": true,
			},
		},
		"outbounds": []map[string]interface{}{
			{
				"type":        "socks",
				"tag":         "socks-out",
				"server":      "127.0.0.1",
				"server_port": socksPort,
			},
		},
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal tun socks config: %w", err)
	}
	return string(data), nil
}

// BuildModeWireguardProxy generates a config that receives SOCKS5 incoming connections
// and forwards them directly to a remote WireGuard endpoint.
func (b *CandyConfigBuilder) BuildModeWireguardProxy(socksPort int, privateKey, peerPublicKey, endpoint string) (string, error) {
	config := map[string]interface{}{
		"inbounds": []map[string]interface{}{
			{
				"type":        "socks",
				"tag":         "socks-in",
				"listen":      "127.0.0.1",
				"listen_port": socksPort,
			},
		},
		"outbounds": []map[string]interface{}{
			{
				"type":            "wireguard",
				"tag":             "wireguard-out",
				"server":          endpoint,
				"server_port":     51820,
				"private_key":     privateKey,
				"peer_public_key": peerPublicKey,
				"local_address":   []string{"10.0.0.2/32"},
			},
		},
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal wireguard proxy config: %w", err)
	}
	return string(data), nil
}

// BuildModeWireguardTunFull generates a full-device TUN config routing all traffic over WireGuard,
// adding dedicated routing rules to prevent loops by directing the endpoint to "direct-out".
func (b *CandyConfigBuilder) BuildModeWireguardTunFull(privateKey, peerPublicKey, endpoint string, localAddresses []string) (string, error) {
	config := map[string]interface{}{
		"inbounds": []map[string]interface{}{
			{
				"type":                     "tun",
				"tag":                      "tun-in",
				"interface_name":           "tun0",
				"stack":                    "gvisor",
				"mtu":                      1420,
				"auto_route":               true,
				"strict_route":             true,
				"endpoint_independent_nat": true,
			},
		},
		"outbounds": []map[string]interface{}{
			{
				"type":            "wireguard",
				"tag":             "wireguard-out",
				"server":          endpoint,
				"server_port":     51820,
				"private_key":     privateKey,
				"peer_public_key": peerPublicKey,
				"local_address":   localAddresses,
			},
			{
				"type": "direct",
				"tag":  "direct-out",
			},
		},
		"route": map[string]interface{}{
			"rules": []map[string]interface{}{
				{
					"ip":          []string{endpoint},
					"outbound":    "direct-out",
					"description": "prevent routing loop for wireguard server itself",
				},
			},
		},
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal full wireguard tun config: %w", err)
	}
	return string(data), nil
}
