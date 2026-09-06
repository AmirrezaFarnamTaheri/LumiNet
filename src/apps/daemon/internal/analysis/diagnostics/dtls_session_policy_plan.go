package diagnostics

import (
	"fmt"
	"strings"
)

type DTLSSessionPolicyRequest struct {
	Role                     string   `json:"role"`
	IdentityMode             string   `json:"identity_mode"`
	CertificateConfigured    bool     `json:"certificate_configured"`
	PSKConfigured            bool     `json:"psk_configured"`
	InsecureSkipVerify       bool     `json:"insecure_skip_verify"`
	InsecureSkipVerifyHello  bool     `json:"insecure_skip_verify_hello"`
	InsecureHashes           bool     `json:"insecure_hashes"`
	ExtendedMasterSecret     string   `json:"extended_master_secret,omitempty"`
	MTU                      int      `json:"mtu,omitempty"`
	ReplayProtectionWindow   int      `json:"replay_protection_window,omitempty"`
	FlightIntervalMillis     int      `json:"flight_interval_ms,omitempty"`
	DisableRetransmitBackoff bool     `json:"disable_retransmit_backoff"`
	KeyLogEnabled            bool     `json:"key_log_enabled"`
	SupportedProtocols       []string `json:"supported_protocols,omitempty"`
	ConnectionIDLength       int      `json:"connection_id_length,omitempty"`
	MaxPaddingBytes          int      `json:"max_padding_bytes,omitempty"`
	SessionResumption        bool     `json:"session_resumption"`
}

type DTLSSessionPolicyPlan struct {
	Role                   string   `json:"role"`
	IdentityMode           string   `json:"identity_mode"`
	MTU                    int      `json:"mtu"`
	ReplayProtectionWindow int      `json:"replay_protection_window"`
	FlightIntervalMillis   int      `json:"flight_interval_ms"`
	RetransmitBackoff      bool     `json:"retransmit_backoff"`
	ExtendedMasterSecret   string   `json:"extended_master_secret"`
	SupportedProtocols     []string `json:"supported_protocols"`
	ConnectionIDLength     int      `json:"connection_id_length"`
	MaxPaddingBytes        int      `json:"max_padding_bytes"`
	SessionResumption      bool     `json:"session_resumption"`
	Warnings               []string `json:"warnings"`
	PerformsHandshake      bool     `json:"performs_handshake"`
	WritesKeyLog           bool     `json:"writes_key_log"`
	ReadOnly               bool     `json:"read_only"`
	Invariants             []string `json:"invariants"`
}

func BuildDTLSSessionPolicyPlan(req DTLSSessionPolicyRequest) (DTLSSessionPolicyPlan, error) {
	role := strings.ToLower(strings.TrimSpace(req.Role))
	if role == "" {
		role = "client"
	}
	if role != "client" && role != "server" {
		return DTLSSessionPolicyPlan{}, fmt.Errorf("DTLS role must be client or server")
	}
	mode := strings.ToLower(strings.TrimSpace(req.IdentityMode))
	if mode == "" {
		mode = "certificate"
	}
	if mode != "certificate" && mode != "psk" {
		return DTLSSessionPolicyPlan{}, fmt.Errorf("DTLS identity_mode must be certificate or psk")
	}
	if mode == "certificate" && !req.CertificateConfigured {
		return DTLSSessionPolicyPlan{}, fmt.Errorf("certificate identity requires certificate evidence")
	}
	if mode == "psk" && !req.PSKConfigured {
		return DTLSSessionPolicyPlan{}, fmt.Errorf("PSK identity requires PSK evidence")
	}
	if req.InsecureSkipVerify || req.InsecureHashes {
		return DTLSSessionPolicyPlan{}, fmt.Errorf("insecure certificate verification or hash policy is not admitted")
	}
	if role == "server" && req.InsecureSkipVerifyHello {
		return DTLSSessionPolicyPlan{}, fmt.Errorf("server hello-verify bypass is not admitted")
	}
	if req.KeyLogEnabled {
		return DTLSSessionPolicyPlan{}, fmt.Errorf("DTLS master-secret key logging is not admitted")
	}
	ems := strings.ToLower(strings.TrimSpace(req.ExtendedMasterSecret))
	if ems == "" {
		ems = "require"
	}
	if ems != "require" && ems != "request" {
		return DTLSSessionPolicyPlan{}, fmt.Errorf("extended master secret must be require or request")
	}
	mtu := req.MTU
	if mtu == 0 {
		mtu = 1200
	}
	if mtu < 576 || mtu > 9000 {
		return DTLSSessionPolicyPlan{}, fmt.Errorf("DTLS MTU must be 576..9000")
	}
	replay := req.ReplayProtectionWindow
	if replay == 0 {
		replay = 64
	}
	if replay < 1 || replay > 4096 {
		return DTLSSessionPolicyPlan{}, fmt.Errorf("replay protection window must be 1..4096")
	}
	flight := req.FlightIntervalMillis
	if flight == 0 {
		flight = 1000
	}
	if flight < 100 || flight > 60000 {
		return DTLSSessionPolicyPlan{}, fmt.Errorf("flight interval must be 100..60000 ms")
	}
	if req.DisableRetransmitBackoff {
		return DTLSSessionPolicyPlan{}, fmt.Errorf("retransmit backoff cannot be disabled")
	}
	if len(req.SupportedProtocols) > 16 {
		return DTLSSessionPolicyPlan{}, fmt.Errorf("ALPN protocol count exceeds 16")
	}
	protocols := make([]string, 0, len(req.SupportedProtocols))
	seen := map[string]bool{}
	for _, raw := range req.SupportedProtocols {
		p := strings.TrimSpace(raw)
		if p == "" || len(p) > 64 {
			return DTLSSessionPolicyPlan{}, fmt.Errorf("invalid ALPN protocol")
		}
		if !seen[p] {
			seen[p] = true
			protocols = append(protocols, p)
		}
	}
	if req.ConnectionIDLength < 0 || req.ConnectionIDLength > 32 {
		return DTLSSessionPolicyPlan{}, fmt.Errorf("connection ID length must be 0..32")
	}
	if req.MaxPaddingBytes < 0 || req.MaxPaddingBytes > 4096 {
		return DTLSSessionPolicyPlan{}, fmt.Errorf("DTLS padding bound must be 0..4096")
	}
	warnings := []string{}
	if mode == "psk" && req.CertificateConfigured {
		warnings = append(warnings, "certificate evidence is present but PSK is the declared identity mode")
	}
	return DTLSSessionPolicyPlan{Role: role, IdentityMode: mode, MTU: mtu, ReplayProtectionWindow: replay, FlightIntervalMillis: flight, RetransmitBackoff: true, ExtendedMasterSecret: ems, SupportedProtocols: protocols, ConnectionIDLength: req.ConnectionIDLength, MaxPaddingBytes: req.MaxPaddingBytes, SessionResumption: req.SessionResumption, Warnings: warnings, PerformsHandshake: false, WritesKeyLog: false, ReadOnly: true, Invariants: []string{
		"certificate verification and secure hash policy cannot be bypassed",
		"server hello verification remains enabled as a denial-of-service resistance boundary",
		"replay window, MTU, retransmit interval, connection ID, ALPN, and padding are explicitly bounded",
		"master-secret key logging is rejected rather than represented as normal observability",
		"the planner performs no DTLS handshake and owns no session-resumption store",
	}}, nil
}
