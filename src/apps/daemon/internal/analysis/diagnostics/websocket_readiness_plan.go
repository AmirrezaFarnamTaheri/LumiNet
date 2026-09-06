package diagnostics

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"strings"
)

type WebSocketReadinessRequest struct {
	TCPReachable    bool              `json:"tcp_reachable"`
	StatusCode      int               `json:"status_code"`
	Headers         map[string]string `json:"headers"`
	SecWebSocketKey string            `json:"sec_websocket_key"`
	TLSExpected     bool              `json:"tls_expected,omitempty"`
	TLSVerified     bool              `json:"tls_verified,omitempty"`
}

type WebSocketReadinessPlan struct {
	Ready             bool     `json:"ready"`
	TCPReachable      bool     `json:"tcp_reachable"`
	UpgradeValid      bool     `json:"upgrade_valid"`
	ConnectionValid   bool     `json:"connection_valid"`
	AcceptValid       bool     `json:"accept_valid"`
	TLSValid          bool     `json:"tls_valid"`
	Reasons           []string `json:"reasons"`
	PerformsNetworkIO bool     `json:"performs_network_io"`
	Invariants        []string `json:"invariants"`
}

func BuildWebSocketReadinessPlan(req WebSocketReadinessRequest) (WebSocketReadinessPlan, error) {
	key := strings.TrimSpace(req.SecWebSocketKey)
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(raw) != 16 {
		return WebSocketReadinessPlan{}, fmt.Errorf("sec_websocket_key must be a base64 16-byte nonce")
	}
	get := func(name string) string {
		for k, v := range req.Headers {
			if strings.EqualFold(k, name) {
				return strings.TrimSpace(v)
			}
		}
		return ""
	}
	acceptDigest := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	expected := base64.StdEncoding.EncodeToString(acceptDigest[:])
	p := WebSocketReadinessPlan{TCPReachable: req.TCPReachable, UpgradeValid: req.StatusCode == 101 && strings.EqualFold(get("Upgrade"), "websocket"), ConnectionValid: tokenContains(get("Connection"), "upgrade"), AcceptValid: get("Sec-WebSocket-Accept") == expected, TLSValid: !req.TLSExpected || req.TLSVerified}
	if !p.TCPReachable {
		p.Reasons = append(p.Reasons, "TCP endpoint was not reachable")
	}
	if req.StatusCode != 101 {
		p.Reasons = append(p.Reasons, "HTTP response is not 101 Switching Protocols")
	}
	if !p.UpgradeValid {
		p.Reasons = append(p.Reasons, "Upgrade: websocket evidence is missing or invalid")
	}
	if !p.ConnectionValid {
		p.Reasons = append(p.Reasons, "Connection header does not contain upgrade")
	}
	if !p.AcceptValid {
		p.Reasons = append(p.Reasons, "Sec-WebSocket-Accept does not match the request nonce")
	}
	if !p.TLSValid {
		p.Reasons = append(p.Reasons, "TLS was expected but strict verification evidence is absent")
	}
	p.Ready = p.TCPReachable && p.UpgradeValid && p.ConnectionValid && p.AcceptValid && p.TLSValid
	p.Invariants = []string{"an open TCP port alone is never WebSocket readiness", "readiness requires an authentic HTTP 101 upgrade handshake", "Sec-WebSocket-Accept is verified against the caller-supplied request nonce", "TLS readiness requires verified TLS evidence when TLS is expected", "the planner performs no network request"}
	return p, nil
}

func tokenContains(header, want string) bool {
	for _, p := range strings.Split(header, ",") {
		if strings.EqualFold(strings.TrimSpace(p), want) {
			return true
		}
	}
	return false
}
