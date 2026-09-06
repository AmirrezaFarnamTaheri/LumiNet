// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package diagnostics

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SocksProbeConfig specifies target and timeout configurations for SOCKS probes.
type SocksProbeConfig struct {
	ProbeHost      string        `json:"probe_host"`
	ProbePort      uint16        `json:"probe_port"`
	ProbePath      string        `json:"probe_path"`
	ConnectTimeout time.Duration `json:"connect_timeout"`
	IOTimeout      time.Duration `json:"io_timeout"`
}

// DefaultSocksProbeConfig returns default configuration matching Oblivion probe settings.
func DefaultSocksProbeConfig() *SocksProbeConfig {
	return &SocksProbeConfig{
		ProbeHost:      "connectivity.cloudflareclient.com",
		ProbePort:      80,
		ProbePath:      "/cdn-cgi/trace",
		ConnectTimeout: 4 * time.Second,
		IOTimeout:      4 * time.Second,
	}
}

// CloudflareTraceResult holds key metadata parsed from a /cdn-cgi/trace response.
type CloudflareTraceResult struct {
	FL          string `json:"fl,omitempty"`
	H           string `json:"h,omitempty"`
	IP          string `json:"ip,omitempty"`
	TS          string `json:"ts,omitempty"`
	VisitScheme string `json:"visit_scheme,omitempty"`
	UAG         string `json:"uag,omitempty"`
	Colo        string `json:"colo,omitempty"`
	Sliver      string `json:"sliver,omitempty"`
	HTTP        string `json:"http,omitempty"`
	Loc         string `json:"loc,omitempty"`
	TLS         string `json:"tls,omitempty"`
	SNI         string `json:"sni,omitempty"`
	Warp        string `json:"warp,omitempty"`
	IsWarpOK    bool   `json:"is_warp_ok"`
	Raw         string `json:"raw"`
}

// BuildSocksGreeting constructs an RFC 1928 SOCKS5 initial greeting packet.
func BuildSocksGreeting() []byte {
	return []byte{0x05, 0x01, 0x00}
}

// VerifySocksGreeting checks if a server accepted the SOCKS5 greeting.
func VerifySocksGreeting(reply []byte) bool {
	return len(reply) >= 2 && reply[0] == 0x05 && reply[1] == 0x00
}

// BuildSocksConnect constructs an RFC 1928 SOCKS5 CONNECT command targeting a domain name.
func BuildSocksConnect(host string, port uint16) []byte {
	hostBytes := []byte(host)
	buf := make([]byte, 5+len(hostBytes)+2)
	buf[0] = 0x05 // VER
	buf[1] = 0x01 // CMD = CONNECT
	buf[2] = 0x00 // RSV
	buf[3] = 0x03 // ATYP = Domain name
	buf[4] = byte(len(hostBytes))
	copy(buf[5:], hostBytes)
	binary.BigEndian.PutUint16(buf[5+len(hostBytes):], port)
	return buf
}

// VerifySocksConnect inspects the first 4 bytes of a SOCKS5 CONNECT response.
// Returns the count of trailing address/port bytes expected.
func VerifySocksConnect(head []byte) (int, error) {
	if len(head) < 4 {
		return 0, errors.New("incomplete socks connect reply header")
	}
	if head[0] != 0x05 {
		return 0, fmt.Errorf("invalid socks version: 0x%02x", head[0])
	}
	if head[1] != 0x00 {
		return 0, fmt.Errorf("socks connect rejected by proxy: status 0x%02x", head[1])
	}

	switch head[3] {
	case 0x01:
		return 4 + 2, nil // IPv4: 4 bytes IP + 2 bytes port
	case 0x04:
		return 16 + 2, nil // IPv6: 16 bytes IP + 2 bytes port
	case 0x03:
		return 1, nil // Domain: 1 byte len prefix, then dynamic read
	default:
		return 0, fmt.Errorf("unsupported atyp in socks reply: 0x%02x", head[3])
	}
}

// BuildHttpProbeRequest formats an HTTP/1.1 probe request.
func BuildHttpProbeRequest(host, path, userAgent string) string {
	return fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n",
		path, host, userAgent)
}

// ParseTraceBody parses line-delimited key=value pairs into a CloudflareTraceResult.
func ParseTraceBody(body string) *CloudflareTraceResult {
	res := &CloudflareTraceResult{
		Raw: body,
	}

	lines := strings.Split(body, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		parts := strings.SplitN(trimmed, "=", 2)
		if len(parts) == 2 {
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])

			switch k {
			case "fl":
				res.FL = v
			case "h":
				res.H = v
			case "ip":
				res.IP = v
			case "ts":
				res.TS = v
			case "visit_scheme":
				res.VisitScheme = v
			case "uag":
				res.UAG = v
			case "colo":
				res.Colo = v
			case "sliver":
				res.Sliver = v
			case "http":
				res.HTTP = v
			case "loc":
				res.Loc = v
			case "tls":
				res.TLS = v
			case "sni":
				res.SNI = v
			case "warp":
				res.Warp = v
				res.IsWarpOK = (v == "on" || v == "plus")
			}
		}
	}

	return res
}

// AttemptStage represents an attempt in the connection ladder.
type AttemptStage struct {
	Label     string `json:"label"`
	Noize     string `json:"noize"`
	Scan      string `json:"scan"`
	BudgetSec int    `json:"budget_sec"`
}

// CalculateValidationBudget computes the timeout budget in seconds for a scan mode.
// Matches Oblivion supervisor validation_budget function.
func CalculateValidationBudget(scanMode string) int {
	var scanBudget int
	switch strings.ToLower(strings.TrimSpace(scanMode)) {
	case "turbo", "fast":
		scanBudget = 45
	case "thorough", "deep", "pro":
		scanBudget = 300
	case "stealth", "quiet":
		scanBudget = 180
	case "ironclad", "real", "verify", "guaranteed":
		scanBudget = 180
	default:
		scanBudget = 120
	}
	headroom := 60
	return scanBudget + headroom
}

// BuildAttemptLadder creates the sequence of stages for connection escalation.
func BuildAttemptLadder(scanMode, noizeProfile string, fastFirstConnect, usesPsiphon bool) []AttemptStage {
	configured := AttemptStage{
		Label:     "configured",
		Noize:     noizeProfile,
		Scan:      scanMode,
		BudgetSec: CalculateValidationBudget(scanMode),
	}

	if usesPsiphon || !fastFirstConnect {
		return []AttemptStage{configured}
	}

	fast := AttemptStage{
		Label:     "fast",
		Noize:     "off",
		Scan:      "turbo",
		BudgetSec: 30,
	}

	if fast.Noize == configured.Noize && fast.Scan == configured.Scan {
		return []AttemptStage{configured}
	}

	return []AttemptStage{fast, configured}
}
