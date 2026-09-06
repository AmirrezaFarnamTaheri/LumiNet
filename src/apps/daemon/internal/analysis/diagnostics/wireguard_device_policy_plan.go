package diagnostics

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

const (
	maxWireGuardPolicyPeers       = 128
	maxWireGuardPolicyAllowedIPs  = 1024
	wireGuardReplayWindowCounters = 8128
)

type WireGuardPolicyPeer struct {
	ID                         string   `json:"id"`
	PublicKey                  string   `json:"public_key"`
	AllowedIPs                 []string `json:"allowed_ips"`
	PersistentKeepaliveSeconds int      `json:"persistent_keepalive_seconds,omitempty"`
}

type WireGuardReceiverIndexMapping struct {
	ReceiverIndex  uint32    `json:"receiver_index"`
	SourceIdentity string    `json:"source_identity"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type WireGuardDevicePolicyRequest struct {
	Peers                     []WireGuardPolicyPeer           `json:"peers"`
	UnderLoad                 bool                            `json:"under_load,omitempty"`
	CookieGateEnabled         bool                            `json:"cookie_gate_enabled,omitempty"`
	HandshakeRatePerSecond    int                             `json:"handshake_rate_per_second,omitempty"`
	HandshakeBurst            int                             `json:"handshake_burst,omitempty"`
	ReplayWindowCounters      int                             `json:"replay_window_counters,omitempty"`
	ReceiverIndexMappings     []WireGuardReceiverIndexMapping `json:"receiver_index_mappings,omitempty"`
	PacketObfuscation         bool                            `json:"packet_obfuscation,omitempty"`
	EphemeralPeerRetryAttempt int                             `json:"ephemeral_peer_retry_attempt,omitempty"`
	AsOf                      time.Time                       `json:"as_of,omitempty"`
}

type WireGuardPolicyPeerPlan struct {
	ID             string   `json:"id"`
	AllowedIPs     []string `json:"allowed_ips"`
	DefaultRouteV4 bool     `json:"default_route_v4"`
	DefaultRouteV6 bool     `json:"default_route_v6"`
}

type WireGuardSessionLifecyclePlan struct {
	RekeyAfterSeconds           int `json:"rekey_after_seconds"`
	RekeyAttemptSeconds         int `json:"rekey_attempt_seconds"`
	RekeyTimeoutSeconds         int `json:"rekey_timeout_seconds"`
	RejectAfterSeconds          int `json:"reject_after_seconds"`
	KeepaliveTimeoutSeconds     int `json:"keepalive_timeout_seconds"`
	CookieRefreshSeconds        int `json:"cookie_refresh_seconds"`
	MaxRetransmitHandshakes     int `json:"max_retransmit_handshakes"`
	ZeroKeyMaterialAfterSeconds int `json:"zero_key_material_after_seconds"`
	UnderLoadRetentionSeconds   int `json:"under_load_retention_seconds"`
}

type WireGuardDevicePolicyPlan struct {
	Peers                       []WireGuardPolicyPeerPlan       `json:"peers"`
	ReplayWindowCounters        int                             `json:"replay_window_counters"`
	HandshakeRatePerSecond      int                             `json:"handshake_rate_per_second"`
	HandshakeBurst              int                             `json:"handshake_burst"`
	SessionLifecycle            WireGuardSessionLifecyclePlan   `json:"session_lifecycle"`
	ReceiverIndexMappings       []WireGuardReceiverIndexMapping `json:"receiver_index_mappings,omitempty"`
	ObfuscationClass            string                          `json:"obfuscation_class,omitempty"`
	EphemeralPeerTimeoutSeconds int                             `json:"ephemeral_peer_timeout_seconds"`
	EphemeralPeerTimeoutCapped  bool                            `json:"ephemeral_peer_timeout_capped"`
	Warnings                    []string                        `json:"warnings"`
	Invariants                  []string                        `json:"invariants"`
	ReadOnly                    bool                            `json:"read_only"`
}

func BuildWireGuardDevicePolicyPlan(req WireGuardDevicePolicyRequest) (WireGuardDevicePolicyPlan, error) {
	if len(req.Peers) == 0 || len(req.Peers) > maxWireGuardPolicyPeers {
		return WireGuardDevicePolicyPlan{}, fmt.Errorf("WireGuard peer count must be between 1 and %d", maxWireGuardPolicyPeers)
	}
	rate := req.HandshakeRatePerSecond
	if rate == 0 {
		rate = 20
	}
	burst := req.HandshakeBurst
	if burst == 0 {
		burst = 5
	}
	if rate < 1 || rate > 1000 || burst < 1 || burst > 100 {
		return WireGuardDevicePolicyPlan{}, fmt.Errorf("WireGuard handshake rate/burst must be within 1..1000 and 1..100")
	}
	replayWindow := req.ReplayWindowCounters
	if replayWindow == 0 {
		replayWindow = wireGuardReplayWindowCounters
	}
	if replayWindow < 1024 || replayWindow > 65536 {
		return WireGuardDevicePolicyPlan{}, fmt.Errorf("WireGuard replay window must be between 1024 and 65536 counters")
	}
	if req.UnderLoad && !req.CookieGateEnabled {
		return WireGuardDevicePolicyPlan{}, fmt.Errorf("WireGuard under-load admission requires cookie/MAC2 anti-abuse gating")
	}
	if req.EphemeralPeerRetryAttempt < 0 || req.EphemeralPeerRetryAttempt > 16 {
		return WireGuardDevicePolicyPlan{}, fmt.Errorf("WireGuard ephemeral peer retry attempt must be between 0 and 16")
	}
	asOf := req.AsOf
	if asOf.IsZero() {
		asOf = time.Now().UTC()
	}
	if len(req.ReceiverIndexMappings) > 1024 {
		return WireGuardDevicePolicyPlan{}, fmt.Errorf("WireGuard receiver-index mapping count exceeds 1024")
	}
	seenReceiver := map[uint32]bool{}
	for i, mapping := range req.ReceiverIndexMappings {
		if mapping.ReceiverIndex == 0 || seenReceiver[mapping.ReceiverIndex] {
			return WireGuardDevicePolicyPlan{}, fmt.Errorf("WireGuard receiver-index mapping %d has invalid or duplicate receiver index", i)
		}
		seenReceiver[mapping.ReceiverIndex] = true
		if strings.TrimSpace(mapping.SourceIdentity) == "" || len(mapping.SourceIdentity) > 256 {
			return WireGuardDevicePolicyPlan{}, fmt.Errorf("WireGuard receiver-index mapping %d requires bounded source identity", i)
		}
		if mapping.ExpiresAt.IsZero() || !mapping.ExpiresAt.After(asOf) {
			return WireGuardDevicePolicyPlan{}, fmt.Errorf("WireGuard receiver-index mapping %d must expire in the future", i)
		}
		if mapping.ExpiresAt.Sub(asOf) > 24*time.Hour {
			return WireGuardDevicePolicyPlan{}, fmt.Errorf("WireGuard receiver-index mapping %d lifetime exceeds 24 hours", i)
		}
	}

	ids := map[string]bool{}
	keys := map[string]bool{}
	owner := map[netip.Prefix]string{}
	prefixesByPeer := make(map[string][]netip.Prefix, len(req.Peers))
	totalPrefixes := 0
	for index, peer := range req.Peers {
		id := strings.TrimSpace(peer.ID)
		if id == "" || len(id) > 64 {
			return WireGuardDevicePolicyPlan{}, fmt.Errorf("WireGuard peer %d id must be 1..64 bytes", index)
		}
		if ids[id] {
			return WireGuardDevicePolicyPlan{}, fmt.Errorf("duplicate WireGuard peer id %q", id)
		}
		ids[id] = true
		key := strings.TrimSpace(peer.PublicKey)
		if key == "" {
			return WireGuardDevicePolicyPlan{}, fmt.Errorf("WireGuard peer %q requires an explicit public key", id)
		}
		if keys[key] {
			return WireGuardDevicePolicyPlan{}, fmt.Errorf("WireGuard public key is assigned to more than one peer")
		}
		keys[key] = true
		if peer.PersistentKeepaliveSeconds < 0 || peer.PersistentKeepaliveSeconds > 65535 {
			return WireGuardDevicePolicyPlan{}, fmt.Errorf("WireGuard peer %q persistent keepalive must be 0..65535 seconds", id)
		}
		if len(peer.AllowedIPs) == 0 {
			return WireGuardDevicePolicyPlan{}, fmt.Errorf("WireGuard peer %q has no AllowedIPs", id)
		}
		for _, raw := range peer.AllowedIPs {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
			if err != nil {
				return WireGuardDevicePolicyPlan{}, fmt.Errorf("WireGuard peer %q invalid AllowedIP %q: %w", id, raw, err)
			}
			prefix = prefix.Masked()
			if existing, ok := owner[prefix]; ok && existing != id {
				return WireGuardDevicePolicyPlan{}, fmt.Errorf("WireGuard AllowedIP %s has conflicting exact owners %q and %q", prefix, existing, id)
			}
			owner[prefix] = id
			prefixesByPeer[id] = append(prefixesByPeer[id], prefix)
			totalPrefixes++
			if totalPrefixes > maxWireGuardPolicyAllowedIPs {
				return WireGuardDevicePolicyPlan{}, fmt.Errorf("WireGuard AllowedIP count exceeds %d", maxWireGuardPolicyAllowedIPs)
			}
		}
	}

	timeout := 8
	for i := 0; i < req.EphemeralPeerRetryAttempt && timeout < 48; i++ {
		timeout *= 2
		if timeout > 48 {
			timeout = 48
		}
	}
	plan := WireGuardDevicePolicyPlan{
		ReplayWindowCounters:   replayWindow,
		HandshakeRatePerSecond: rate,
		HandshakeBurst:         burst,
		SessionLifecycle: WireGuardSessionLifecyclePlan{
			RekeyAfterSeconds:           120,
			RekeyAttemptSeconds:         90,
			RekeyTimeoutSeconds:         5,
			RejectAfterSeconds:          180,
			KeepaliveTimeoutSeconds:     10,
			CookieRefreshSeconds:        120,
			MaxRetransmitHandshakes:     18,
			ZeroKeyMaterialAfterSeconds: 540,
			UnderLoadRetentionSeconds:   1,
		},
		ReceiverIndexMappings:       append([]WireGuardReceiverIndexMapping(nil), req.ReceiverIndexMappings...),
		EphemeralPeerTimeoutSeconds: timeout,
		EphemeralPeerTimeoutCapped:  timeout == 48 && req.EphemeralPeerRetryAttempt >= 3,
		ReadOnly:                    true,
	}
	if req.PacketObfuscation {
		plan.ObfuscationClass = "traffic-shape-modification-only"
	}
	for _, peer := range req.Peers {
		id := strings.TrimSpace(peer.ID)
		prefixes := prefixesByPeer[id]
		sort.Slice(prefixes, func(i, j int) bool {
			if prefixes[i].Addr().BitLen() == prefixes[j].Addr().BitLen() && prefixes[i].Bits() != prefixes[j].Bits() {
				return prefixes[i].Bits() > prefixes[j].Bits()
			}
			return prefixes[i].String() < prefixes[j].String()
		})
		pp := WireGuardPolicyPeerPlan{ID: id}
		for _, prefix := range prefixes {
			pp.AllowedIPs = append(pp.AllowedIPs, prefix.String())
			if prefix.String() == "0.0.0.0/0" {
				pp.DefaultRouteV4 = true
			}
			if prefix.String() == "::/0" {
				pp.DefaultRouteV6 = true
			}
		}
		plan.Peers = append(plan.Peers, pp)
	}

	// Different-length overlaps are legal and rely on longest-prefix routing,
	// but they deserve explicit operator visibility because exact-prefix
	// conflicts were rejected above.
	all := make([]struct {
		prefix netip.Prefix
		peer   string
	}, 0, totalPrefixes)
	for peer, prefixes := range prefixesByPeer {
		for _, prefix := range prefixes {
			all = append(all, struct {
				prefix netip.Prefix
				peer   string
			}{prefix: prefix, peer: peer})
		}
	}
	for i := 0; i < len(all); i++ {
		for j := i + 1; j < len(all); j++ {
			if all[i].peer == all[j].peer || all[i].prefix.Addr().BitLen() != all[j].prefix.Addr().BitLen() {
				continue
			}
			if all[i].prefix.Contains(all[j].prefix.Addr()) || all[j].prefix.Contains(all[i].prefix.Addr()) {
				plan.Warnings = append(plan.Warnings, fmt.Sprintf("AllowedIPs %s (%s) and %s (%s) overlap; longest-prefix selection must remain authoritative", all[i].prefix, all[i].peer, all[j].prefix, all[j].peer))
			}
		}
	}
	plan.Invariants = []string{
		"each exact AllowedIP prefix has one peer owner",
		"different-length overlaps are resolved by longest-prefix match, never insertion order",
		"replayed or out-of-window transport counters are rejected by the live WireGuard owner",
		"handshake admission is rate-limited and uses cookie/MAC2 gating under load",
		"session readiness distinguishes rekey, handshake retry exhaustion, transport rejection, and later zeroization of stale key material",
		"keypair promotion and expiry remain owned by the live WireGuard implementation; this planner only exposes the expected lifecycle contract",
		"translated receiver-index mappings are source-identity-bound, unique, and explicitly expiring",
		"packet obfuscation is traffic-shape modification only; it is not authentication, confidentiality, replay protection, or a substitute for WireGuard cookie/MAC2 admission",
		"ephemeral peer negotiation uses exponential timeout growth from 8 seconds capped at 48 seconds; retry count remains externally bounded",
		"this policy plan never creates keys, opens a device, or installs routes",
	}
	return plan, nil
}
