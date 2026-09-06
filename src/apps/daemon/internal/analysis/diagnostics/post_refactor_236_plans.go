package diagnostics

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strings"
)

// Post-refactor-236 planners absorb bounded semantics from the 20 admitted
// donor revisions. They only transform caller-supplied evidence: no planner
// captures packets, starts services, dials proxies, controls Tor, reads secret
// values, changes DNS, mutates host configuration, or performs cryptography.

// ClientHello / QUIC evidence -------------------------------------------------
type QUICFragmentObservation struct {
	Offset int `json:"offset"`
	Length int `json:"length"`
}

type ClientHelloEvidenceRequest struct {
	Transport       string                    `json:"transport"`
	ServerName      string                    `json:"server_name"`
	QUICVersion     uint32                    `json:"quic_version"`
	ExtensionIDs    []uint16                  `json:"extension_ids"`
	SupportedGroups []uint16                  `json:"supported_groups"`
	Fragments       []QUICFragmentObservation `json:"fragments"`
	CapturedBytes   int                       `json:"captured_bytes"`
	NowUnix         int64                     `json:"now_unix"`
	ExpiresUnix     int64                     `json:"expires_unix"`
}

type ClientHelloEvidencePlan struct {
	Transport                                      string                    `json:"transport"`
	ServerName                                     string                    `json:"server_name,omitempty"`
	QUICVersion                                    uint32                    `json:"quic_version,omitempty"`
	NormalizedExtensionIDs                         []uint16                  `json:"normalized_extension_ids"`
	NormalizedSupportedGroups                      []uint16                  `json:"normalized_supported_groups"`
	Fragments                                      []QUICFragmentObservation `json:"fragments,omitempty"`
	FragmentGaps                                   []string                  `json:"fragment_gaps,omitempty"`
	FragmentOverlaps                               []string                  `json:"fragment_overlaps,omitempty"`
	Status                                         string                    `json:"status"`
	Expired                                        bool                      `json:"expired"`
	FingerprintSHA256                              string                    `json:"fingerprint_sha256"`
	CapturesPackets, ReassemblesTraffic, DialsQUIC bool
	ReadOnly                                       bool     `json:"read_only"`
	Invariants                                     []string `json:"invariants"`
}

func grease16(v uint16) bool { return v&0x0f0f == 0x0a0a && byte(v>>8) == byte(v) }

func normalizeTLSIDs(in []uint16, limit int) ([]uint16, error) {
	if len(in) > limit {
		return nil, fmt.Errorf("identifier count exceeds %d", limit)
	}
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		if grease16(v) {
			v = 0x0a0a
		}
		out = append(out, v)
	}
	return out, nil
}

func BuildClientHelloEvidencePlan(r ClientHelloEvidenceRequest) (ClientHelloEvidencePlan, error) {
	transport := strings.ToLower(strings.TrimSpace(r.Transport))
	if transport != "tls" && transport != "quic" {
		return ClientHelloEvidencePlan{}, fmt.Errorf("transport must be tls or quic")
	}
	if len(r.ServerName) > 253 || r.CapturedBytes < 0 || r.CapturedBytes > 1<<20 {
		return ClientHelloEvidencePlan{}, fmt.Errorf("invalid capture metadata")
	}
	exts, err := normalizeTLSIDs(r.ExtensionIDs, 512)
	if err != nil {
		return ClientHelloEvidencePlan{}, err
	}
	groups, err := normalizeTLSIDs(r.SupportedGroups, 512)
	if err != nil {
		return ClientHelloEvidencePlan{}, err
	}
	if len(r.Fragments) > 4096 {
		return ClientHelloEvidencePlan{}, fmt.Errorf("fragment count exceeds 4096")
	}
	frags := append([]QUICFragmentObservation(nil), r.Fragments...)
	for _, f := range frags {
		if f.Offset < 0 || f.Length <= 0 || f.Offset > 1<<24 || f.Length > 1<<20 {
			return ClientHelloEvidencePlan{}, fmt.Errorf("invalid QUIC fragment")
		}
	}
	sort.Slice(frags, func(i, j int) bool {
		if frags[i].Offset == frags[j].Offset {
			return frags[i].Length < frags[j].Length
		}
		return frags[i].Offset < frags[j].Offset
	})
	p := ClientHelloEvidencePlan{Transport: transport, ServerName: strings.TrimSpace(r.ServerName), QUICVersion: r.QUICVersion, NormalizedExtensionIDs: exts, NormalizedSupportedGroups: groups, Fragments: frags, Status: "complete", ReadOnly: true, Invariants: []string{
		"GREASE identifiers normalize to one placeholder before fingerprint comparison",
		"QUIC fragment overlap and gap evidence is explicit rather than silently reassembled",
		"expiry is caller-supplied observation metadata and never inferred from wall-clock access",
		"this planner never captures packets, parses live sockets, or dials a peer",
	}}
	if r.ExpiresUnix > 0 && r.NowUnix > 0 && r.NowUnix >= r.ExpiresUnix {
		p.Expired = true
		p.Status = "expired"
	}
	if transport == "quic" {
		end := 0
		for _, f := range frags {
			if f.Offset > end {
				p.FragmentGaps = append(p.FragmentGaps, fmt.Sprintf("%d-%d", end, f.Offset))
			}
			if f.Offset < end {
				p.FragmentOverlaps = append(p.FragmentOverlaps, fmt.Sprintf("%d-%d", f.Offset, minInt236(end, f.Offset+f.Length)))
			}
			if f.Offset+f.Length > end {
				end = f.Offset + f.Length
			}
		}
		if len(frags) == 0 || len(p.FragmentGaps) > 0 || len(p.FragmentOverlaps) > 0 {
			if !p.Expired {
				p.Status = "incomplete"
			}
		}
	}
	parts := []string{transport, strings.ToLower(p.ServerName), fmt.Sprintf("qv:%d", p.QUICVersion), fmt.Sprintf("bytes:%d", r.CapturedBytes)}
	for _, v := range exts {
		parts = append(parts, fmt.Sprintf("e:%04x", v))
	}
	for _, v := range groups {
		parts = append(parts, fmt.Sprintf("g:%04x", v))
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	p.FingerprintSHA256 = hex.EncodeToString(sum[:])
	return p, nil
}

// Encrypted DNS ingress/cache policy ----------------------------------------
type EncryptedDNSPolicyRequest struct {
	Transport         string `json:"transport"`
	PacketBytes       int    `json:"packet_bytes"`
	ObservedTTL       int    `json:"observed_ttl"`
	MinTTL            int    `json:"min_ttl"`
	MaxTTL            int    `json:"max_ttl"`
	ErrorTTL          int    `json:"error_ttl"`
	ResponseIsError   bool   `json:"response_is_error"`
	PaddingBlockBytes int    `json:"padding_block_bytes"`
	ExistingECS       string `json:"existing_ecs"`
	RequestedECS      string `json:"requested_ecs"`
	CacheEnabled      bool   `json:"cache_enabled"`
}

type EncryptedDNSPolicyPlan struct {
	Transport                                   string `json:"transport"`
	EffectiveTTLSeconds                         int    `json:"effective_ttl_seconds"`
	PaddedPacketBytes                           int    `json:"padded_packet_bytes"`
	ECSAction                                   string `json:"ecs_action"`
	EffectiveECS                                string `json:"effective_ecs,omitempty"`
	CacheState                                  string `json:"cache_state"`
	StartsServer, SendsDNS, RewritesExistingECS bool
	ReadOnly                                    bool     `json:"read_only"`
	Invariants                                  []string `json:"invariants"`
}

func BuildEncryptedDNSPolicyPlan(r EncryptedDNSPolicyRequest) (EncryptedDNSPolicyPlan, error) {
	tr := strings.ToLower(strings.TrimSpace(r.Transport))
	allowed := map[string]bool{"doh": true, "odoh": true, "dnscrypt": true, "anonymized-dnscrypt": true, "doq": true}
	if !allowed[tr] {
		return EncryptedDNSPolicyPlan{}, fmt.Errorf("unsupported encrypted DNS transport")
	}
	if r.PacketBytes < 0 || r.PacketBytes > 4096 || r.MinTTL < 0 || r.MaxTTL < r.MinTTL || r.MaxTTL > 604800 || r.ErrorTTL < 0 || r.ErrorTTL > 604800 || r.ObservedTTL < 0 {
		return EncryptedDNSPolicyPlan{}, fmt.Errorf("invalid DNS cache bounds")
	}
	if r.PaddingBlockBytes < 0 || r.PaddingBlockBytes > 4096 {
		return EncryptedDNSPolicyPlan{}, fmt.Errorf("invalid padding block")
	}
	ttl := r.ObservedTTL
	if r.ResponseIsError {
		ttl = r.ErrorTTL
	}
	if ttl < r.MinTTL {
		ttl = r.MinTTL
	}
	if ttl > r.MaxTTL {
		ttl = r.MaxTTL
	}
	padded := r.PacketBytes
	if r.PaddingBlockBytes > 0 {
		padded = ((r.PacketBytes + r.PaddingBlockBytes - 1) / r.PaddingBlockBytes) * r.PaddingBlockBytes
		if padded > 4096 {
			return EncryptedDNSPolicyPlan{}, fmt.Errorf("padding would exceed 4096-byte packet bound")
		}
	}
	p := EncryptedDNSPolicyPlan{Transport: tr, EffectiveTTLSeconds: ttl, PaddedPacketBytes: padded, CacheState: "disabled", ReadOnly: true, Invariants: []string{
		"TTL is clamped between explicit minimum and maximum bounds; error responses use the explicit error TTL",
		"a caller-observed ECS option has precedence and is never silently overwritten",
		"packet plus padding remains within the explicit 4096-byte policy bound",
		"cache planning never starts a DNS server or sends a query",
	}}
	if r.CacheEnabled {
		p.CacheState = "eligible"
	}
	existing := strings.TrimSpace(r.ExistingECS)
	requested := strings.TrimSpace(r.RequestedECS)
	switch {
	case existing != "":
		p.ECSAction = "preserve-existing"
		p.EffectiveECS = existing
	case requested != "":
		p.ECSAction = "attach-requested"
		p.EffectiveECS = requested
	default:
		p.ECSAction = "none"
	}
	return p, nil
}

// Tor lab / relay topology ----------------------------------------------------
type TorLabNodeObservation struct {
	ID               string `json:"id"`
	Role             string `json:"role"`
	Family           string `json:"family,omitempty"`
	Running          bool   `json:"running"`
	BootstrapPercent int    `json:"bootstrap_percent"`
	BandwidthKBPS    int    `json:"bandwidth_kbps"`
	ExitAllowedPorts []int  `json:"exit_allowed_ports,omitempty"`
	MetricsEnabled   bool   `json:"metrics_enabled"`
}
type TorLabRelayRequest struct {
	Nodes                  []TorLabNodeObservation `json:"nodes"`
	MinimumConsensusRelays int                     `json:"minimum_consensus_relays"`
	AllowedFailures        int                     `json:"allowed_failures"`
	VerificationRounds     int                     `json:"verification_rounds"`
}
type TorLabRelayPlan struct {
	Status                                                   string              `json:"status"`
	ConsensusRelays                                          int                 `json:"consensus_relays"`
	ReadyNodes                                               int                 `json:"ready_nodes"`
	FailedNodes                                              []string            `json:"failed_nodes"`
	Families                                                 map[string][]string `json:"families"`
	ExitNodes                                                map[string][]int    `json:"exit_nodes"`
	MetricsNodes                                             []string            `json:"metrics_nodes"`
	VerificationRounds                                       int                 `json:"verification_rounds"`
	StartsTor, WritesTorrc, ControlsProcesses, DeploysRelays bool
	ReadOnly                                                 bool     `json:"read_only"`
	Invariants                                               []string `json:"invariants"`
}

func BuildTorLabRelayPlan(r TorLabRelayRequest) (TorLabRelayPlan, error) {
	if len(r.Nodes) == 0 || len(r.Nodes) > 4096 || r.MinimumConsensusRelays < 0 || r.MinimumConsensusRelays > 4096 || r.AllowedFailures < 0 || r.AllowedFailures > len(r.Nodes) || r.VerificationRounds < 1 || r.VerificationRounds > 100 {
		return TorLabRelayPlan{}, fmt.Errorf("invalid Tor topology bounds")
	}
	p := TorLabRelayPlan{Status: "ready", Families: map[string][]string{}, ExitNodes: map[string][]int{}, VerificationRounds: r.VerificationRounds, ReadOnly: true, Invariants: []string{
		"bootstrap percentage and running state are observations, not process-control authority",
		"consensus readiness requires the requested minimum number of running fully bootstrapped relay-class nodes",
		"allowed failures are explicit and bounded; failure tolerance never hides individual failed nodes",
		"rapid-bootstrap lab settings are evidence only and are never emitted as production Tor configuration",
	}}
	seen := map[string]bool{}
	consensusRoles := map[string]bool{"authority": true, "relay": true, "exit": true}
	for i, n := range r.Nodes {
		id := strings.TrimSpace(n.ID)
		role := strings.ToLower(strings.TrimSpace(n.Role))
		if id == "" || len(id) > 128 || seen[id] || !map[string]bool{"authority": true, "relay": true, "exit": true, "bridge": true, "client": true}[role] || n.BootstrapPercent < 0 || n.BootstrapPercent > 100 || n.BandwidthKBPS < 0 {
			return TorLabRelayPlan{}, fmt.Errorf("invalid Tor node %d", i)
		}
		seen[id] = true
		if n.Running && n.BootstrapPercent == 100 {
			p.ReadyNodes++
			if consensusRoles[role] {
				p.ConsensusRelays++
			}
		} else {
			p.FailedNodes = append(p.FailedNodes, id)
		}
		if fam := strings.TrimSpace(n.Family); fam != "" {
			p.Families[fam] = append(p.Families[fam], id)
		}
		if role == "exit" {
			ports := append([]int(nil), n.ExitAllowedPorts...)
			for _, v := range ports {
				if v < 1 || v > 65535 {
					return TorLabRelayPlan{}, fmt.Errorf("invalid exit port")
				}
			}
			sort.Ints(ports)
			p.ExitNodes[id] = dedupeInts236(ports)
		}
		if n.MetricsEnabled {
			p.MetricsNodes = append(p.MetricsNodes, id)
		}
	}
	for k := range p.Families {
		sort.Strings(p.Families[k])
	}
	sort.Strings(p.FailedNodes)
	sort.Strings(p.MetricsNodes)
	if p.ConsensusRelays < r.MinimumConsensusRelays || len(p.FailedNodes) > r.AllowedFailures {
		p.Status = "not-ready"
	} else if len(p.FailedNodes) > 0 {
		p.Status = "degraded"
	}
	return p, nil
}

// Proxy chain safety ----------------------------------------------------------
type ProxyChainHopObservation struct {
	ID           string `json:"id"`
	Protocol     string `json:"protocol"`
	Reachable    bool   `json:"reachable"`
	SupportsIPv6 bool   `json:"supports_ipv6"`
}
type ProxyChainSafetyRequest struct {
	Mode              string                     `json:"mode"`
	Hops              []ProxyChainHopObservation `json:"hops"`
	ChainLength       int                        `json:"chain_length"`
	DestinationKind   string                     `json:"destination_kind"`
	RemoteDNS         bool                       `json:"remote_dns"`
	RoundRobinOffset  int                        `json:"round_robin_offset"`
	DeterministicSeed string                     `json:"deterministic_seed"`
}
type ProxyChainSafetyPlan struct {
	Mode                                      string   `json:"mode"`
	Status                                    string   `json:"status"`
	Selected                                  []string `json:"selected"`
	Skipped                                   []string `json:"skipped"`
	RequiredReachable                         int      `json:"required_reachable"`
	RemoteDNS                                 bool     `json:"remote_dns"`
	Warnings                                  []string `json:"warnings"`
	HooksProcesses, DialsProxies, ResolvesDNS bool
	ReadOnly                                  bool     `json:"read_only"`
	Invariants                                []string `json:"invariants"`
}

func BuildProxyChainSafetyPlan(r ProxyChainSafetyRequest) (ProxyChainSafetyPlan, error) {
	mode := strings.ToLower(strings.TrimSpace(r.Mode))
	if !map[string]bool{"strict": true, "dynamic": true, "random": true, "round-robin": true}[mode] {
		return ProxyChainSafetyPlan{}, fmt.Errorf("unsupported chain mode")
	}
	if len(r.Hops) == 0 || len(r.Hops) > 256 || r.ChainLength < 1 || r.ChainLength > len(r.Hops) {
		return ProxyChainSafetyPlan{}, fmt.Errorf("invalid chain length")
	}
	dk := strings.ToLower(strings.TrimSpace(r.DestinationKind))
	if !map[string]bool{"ipv4": true, "ipv6": true, "hostname": true}[dk] {
		return ProxyChainSafetyPlan{}, fmt.Errorf("invalid destination kind")
	}
	p := ProxyChainSafetyPlan{Mode: mode, Status: "ready", RequiredReachable: r.ChainLength, RemoteDNS: r.RemoteDNS, ReadOnly: true, Invariants: []string{"strict mode never skips an unavailable selected hop", "dynamic mode may skip unavailable hops but still requires the requested chain length", "random mode is deterministic only when an explicit seed is supplied", "this planner never installs LD_PRELOAD hooks, resolves DNS, or opens proxy sockets"}}
	hops := append([]ProxyChainHopObservation(nil), r.Hops...)
	seen := map[string]bool{}
	for i := range hops {
		hops[i].ID = strings.TrimSpace(hops[i].ID)
		hops[i].Protocol = strings.ToLower(strings.TrimSpace(hops[i].Protocol))
		if hops[i].ID == "" || seen[hops[i].ID] || !map[string]bool{"socks4": true, "socks5": true, "http": true}[hops[i].Protocol] {
			return ProxyChainSafetyPlan{}, fmt.Errorf("invalid hop")
		}
		seen[hops[i].ID] = true
	}
	if dk == "hostname" && !r.RemoteDNS {
		p.Warnings = append(p.Warnings, "hostname destination would require local DNS before the proxy chain")
	}
	if dk == "ipv6" {
		for _, h := range hops {
			if !h.SupportsIPv6 {
				p.Warnings = append(p.Warnings, "hop "+h.ID+" lacks IPv6 support")
			}
		}
	}
	switch mode {
	case "strict":
		for i := 0; i < r.ChainLength; i++ {
			h := hops[i]
			p.Selected = append(p.Selected, h.ID)
			if !h.Reachable {
				p.Status = "blocked"
				p.Warnings = append(p.Warnings, "strict hop unavailable: "+h.ID)
			}
		}
	case "dynamic":
		for _, h := range hops {
			if h.Reachable && len(p.Selected) < r.ChainLength {
				p.Selected = append(p.Selected, h.ID)
			} else if !h.Reachable {
				p.Skipped = append(p.Skipped, h.ID)
			}
		}
		if len(p.Selected) < r.ChainLength {
			p.Status = "blocked"
		}
	case "round-robin":
		off := r.RoundRobinOffset
		if off < 0 {
			return ProxyChainSafetyPlan{}, fmt.Errorf("negative round-robin offset")
		}
		off %= len(hops)
		for n := 0; n < len(hops) && len(p.Selected) < r.ChainLength; n++ {
			h := hops[(off+n)%len(hops)]
			if h.Reachable {
				p.Selected = append(p.Selected, h.ID)
			} else {
				p.Skipped = append(p.Skipped, h.ID)
			}
		}
		if len(p.Selected) < r.ChainLength {
			p.Status = "blocked"
		}
	case "random":
		if strings.TrimSpace(r.DeterministicSeed) == "" {
			return ProxyChainSafetyPlan{}, fmt.Errorf("random mode requires deterministic_seed")
		}
		sort.Slice(hops, func(i, j int) bool {
			a := sha256.Sum256([]byte(r.DeterministicSeed + "|" + hops[i].ID))
			b := sha256.Sum256([]byte(r.DeterministicSeed + "|" + hops[j].ID))
			return strings.Compare(hex.EncodeToString(a[:]), hex.EncodeToString(b[:])) < 0
		})
		for _, h := range hops {
			if h.Reachable && len(p.Selected) < r.ChainLength {
				p.Selected = append(p.Selected, h.ID)
			} else if !h.Reachable {
				p.Skipped = append(p.Skipped, h.ID)
			}
		}
		if len(p.Selected) < r.ChainLength {
			p.Status = "blocked"
		}
	}
	sort.Strings(p.Skipped)
	sort.Strings(p.Warnings)
	return p, nil
}

// Transport replay / salt admission -----------------------------------------
type TransportReplayObservation struct {
	KeyID      string `json:"key_id"`
	SaltHex    string `json:"salt_hex"`
	AgeSeconds int    `json:"age_seconds"`
}
type TransportReplayRequest struct {
	Observations   []TransportReplayObservation `json:"observations"`
	WindowCapacity int                          `json:"window_capacity"`
	MaxAgeSeconds  int                          `json:"max_age_seconds"`
	NATIdleSeconds int                          `json:"nat_idle_seconds"`
	QueueCapacity  int                          `json:"queue_capacity"`
}
type TransportReplayPlan struct {
	Accepted                                          []string `json:"accepted"`
	Replayed                                          []string `json:"replayed"`
	Stale                                             []string `json:"stale"`
	CapacityExceeded                                  []string `json:"capacity_exceeded"`
	Status                                            string   `json:"status"`
	EncryptsTraffic, OpensSockets, MutatesReplayCache bool
	ReadOnly                                          bool     `json:"read_only"`
	Invariants                                        []string `json:"invariants"`
}

func BuildTransportReplayPlan(r TransportReplayRequest) (TransportReplayPlan, error) {
	if len(r.Observations) > 100000 || r.WindowCapacity < 0 || r.WindowCapacity > 1000000 || r.MaxAgeSeconds < 0 || r.MaxAgeSeconds > 86400*30 || r.NATIdleSeconds < 0 || r.NATIdleSeconds > 86400 || r.QueueCapacity < 0 || r.QueueCapacity > 1000000 {
		return TransportReplayPlan{}, fmt.Errorf("invalid replay bounds")
	}
	p := TransportReplayPlan{Status: "ready", ReadOnly: true, Invariants: []string{"replay identity is scoped by key identity plus the full 32-byte handshake salt", "stale observations never become fresh merely because replay capacity remains", "capacity exhaustion is explicit and cannot silently evict evidence in this planner", "NAT and queue lifetimes are bounded caller-supplied evidence only"}}
	seen := map[string]bool{}
	accepted := 0
	for i, o := range r.Observations {
		key := strings.TrimSpace(o.KeyID)
		salt := strings.ToLower(strings.TrimSpace(o.SaltHex))
		if key == "" || len(key) > 128 || len(salt) != 64 || o.AgeSeconds < 0 {
			return TransportReplayPlan{}, fmt.Errorf("invalid replay observation %d", i)
		}
		if _, err := hex.DecodeString(salt); err != nil {
			return TransportReplayPlan{}, fmt.Errorf("invalid salt at %d", i)
		}
		id := key + ":" + salt
		if r.MaxAgeSeconds > 0 && o.AgeSeconds > r.MaxAgeSeconds {
			p.Stale = append(p.Stale, id)
			continue
		}
		if seen[id] {
			p.Replayed = append(p.Replayed, id)
			continue
		}
		seen[id] = true
		if r.WindowCapacity > 0 && accepted >= r.WindowCapacity {
			p.CapacityExceeded = append(p.CapacityExceeded, id)
			continue
		}
		accepted++
		p.Accepted = append(p.Accepted, id)
	}
	for _, v := range [][]string{p.Accepted, p.Replayed, p.Stale, p.CapacityExceeded} {
		sort.Strings(v)
	}
	if len(p.Replayed) > 0 || len(p.CapacityExceeded) > 0 {
		p.Status = "degraded"
	}
	return p, nil
}

// Secret refresh/watch policy ------------------------------------------------
type SecretRefreshPolicyRequest struct {
	Name                string  `json:"name"`
	Declared            bool    `json:"declared"`
	AllowLookup         bool    `json:"allow_lookup"`
	PersistCache        bool    `json:"persist_cache"`
	CachedVersion       int64   `json:"cached_version"`
	RemoteVersion       int64   `json:"remote_version"`
	CacheAgeSeconds     int     `json:"cache_age_seconds"`
	MaxCacheAgeSeconds  int     `json:"max_cache_age_seconds"`
	PollIntervalSeconds int     `json:"poll_interval_seconds"`
	PollJitterPct       float64 `json:"poll_jitter_pct"`
	Watchers            int     `json:"watchers"`
}
type SecretRefreshPolicyPlan struct {
	Name                                           string   `json:"name"`
	State                                          string   `json:"state"`
	LookupAllowed                                  bool     `json:"lookup_allowed"`
	RefreshNeeded                                  bool     `json:"refresh_needed"`
	NextPollMinSeconds                             int      `json:"next_poll_min_seconds"`
	NextPollMaxSeconds                             int      `json:"next_poll_max_seconds"`
	Warnings                                       []string `json:"warnings"`
	ReadsSecretValues, WritesCache, StartsWatchers bool
	ReadOnly                                       bool     `json:"read_only"`
	Invariants                                     []string `json:"invariants"`
}

func BuildSecretRefreshPolicyPlan(r SecretRefreshPolicyRequest) (SecretRefreshPolicyPlan, error) {
	name := strings.TrimSpace(r.Name)
	if name == "" || len(name) > 256 || r.CachedVersion < 0 || r.RemoteVersion < 0 || r.CacheAgeSeconds < 0 || r.MaxCacheAgeSeconds < 0 || r.PollIntervalSeconds < 1 || r.PollIntervalSeconds > 86400 || r.PollJitterPct < 0 || r.PollJitterPct > 20 || r.Watchers < 0 || r.Watchers > 100000 {
		return SecretRefreshPolicyPlan{}, fmt.Errorf("invalid secret refresh request")
	}
	p := SecretRefreshPolicyPlan{Name: name, State: "fresh", LookupAllowed: r.Declared || r.AllowLookup, ReadOnly: true, Invariants: []string{"undeclared secret lookup is denied unless allow_lookup is explicit", "cache persistence is a security tradeoff and never silently enabled by this planner", "poll jitter is bounded and represented as a range to avoid synchronized refresh herds", "version comparison and watch planning never read or expose secret values"}}
	j := r.PollJitterPct / 100.0
	p.NextPollMinSeconds = int(math.Floor(float64(r.PollIntervalSeconds) * (1 - j)))
	p.NextPollMaxSeconds = int(math.Ceil(float64(r.PollIntervalSeconds) * (1 + j)))
	if p.NextPollMinSeconds < 1 {
		p.NextPollMinSeconds = 1
	}
	if !p.LookupAllowed {
		p.State = "blocked-undeclared"
		p.Warnings = append(p.Warnings, "undeclared lookup is not permitted")
	}
	if r.RemoteVersion > r.CachedVersion {
		p.RefreshNeeded = true
		if p.State == "fresh" {
			p.State = "update-available"
		}
	}
	if r.MaxCacheAgeSeconds > 0 && r.CacheAgeSeconds > r.MaxCacheAgeSeconds {
		p.RefreshNeeded = true
		p.State = "stale"
		p.Warnings = append(p.Warnings, "cached value exceeds maximum age")
	}
	if r.PersistCache {
		p.Warnings = append(p.Warnings, "persisted cache may expose secret material at rest and requires an explicit storage policy")
	}
	sort.Strings(p.Warnings)
	return p, nil
}

// REALITY admission -----------------------------------------------------------
type RealityAdmissionRequest struct {
	ServerNames               []string `json:"server_names"`
	ShortIDs                  []string `json:"short_ids"`
	MaxTimeDiffSeconds        int      `json:"max_time_diff_seconds"`
	LimitFallbackUploadMbps   int      `json:"limit_fallback_upload_mbps"`
	LimitFallbackDownloadMbps int      `json:"limit_fallback_download_mbps"`
	ECHEnabled                bool     `json:"ech_enabled"`
}
type RealityAdmissionPlan struct {
	Status                                         string            `json:"status"`
	ServerNames                                    []string          `json:"server_names"`
	ShortIDs                                       []string          `json:"short_ids"`
	RejectedShortIDs                               map[string]string `json:"rejected_short_ids"`
	MaxTimeDiffSeconds                             int               `json:"max_time_diff_seconds"`
	LimitFallbackUploadMbps                        int               `json:"limit_fallback_upload_mbps"`
	LimitFallbackDownloadMbps                      int               `json:"limit_fallback_download_mbps"`
	ECHEnabled                                     bool              `json:"ech_enabled"`
	PerformsHandshake, GeneratesKeys, OpensSockets bool
	ReadOnly                                       bool     `json:"read_only"`
	Invariants                                     []string `json:"invariants"`
}

func BuildRealityAdmissionPlan(r RealityAdmissionRequest) (RealityAdmissionPlan, error) {
	if len(r.ServerNames) == 0 || len(r.ServerNames) > 256 || len(r.ShortIDs) > 256 || r.MaxTimeDiffSeconds < 0 || r.MaxTimeDiffSeconds > 86400 || r.LimitFallbackUploadMbps < 0 || r.LimitFallbackUploadMbps > 1000000 || r.LimitFallbackDownloadMbps < 0 || r.LimitFallbackDownloadMbps > 1000000 {
		return RealityAdmissionPlan{}, fmt.Errorf("invalid REALITY bounds")
	}
	names, err := cleanDistinctStrings(r.ServerNames, 256)
	if err != nil {
		return RealityAdmissionPlan{}, err
	}
	if len(names) == 0 {
		return RealityAdmissionPlan{}, fmt.Errorf("at least one server name required")
	}
	for _, n := range names {
		if strings.ContainsAny(n, " /:@") || len(n) > 253 {
			return RealityAdmissionPlan{}, fmt.Errorf("invalid server name")
		}
	}
	p := RealityAdmissionPlan{Status: "admitted", ServerNames: names, RejectedShortIDs: map[string]string{}, MaxTimeDiffSeconds: r.MaxTimeDiffSeconds, LimitFallbackUploadMbps: r.LimitFallbackUploadMbps, LimitFallbackDownloadMbps: r.LimitFallbackDownloadMbps, ECHEnabled: r.ECHEnabled, ReadOnly: true, Invariants: []string{"short IDs are lowercase hexadecimal prefixes of at most eight bytes and must have an even number of hex digits", "server-name admission is explicit and bounded; no TLS handshake is attempted", "time-difference and fallback-rate bounds are policy evidence rather than traffic-shaping authority", "ECH capability evidence does not imply negotiated or verified ECH"}}
	seen := map[string]bool{}
	for _, raw := range r.ShortIDs {
		id := strings.ToLower(strings.TrimSpace(raw))
		if seen[id] {
			continue
		}
		seen[id] = true
		if len(id) > 16 || len(id)%2 != 0 {
			p.RejectedShortIDs[raw] = "short ID must encode at most 8 bytes with an even hex length"
			continue
		}
		if id != "" {
			if _, e := hex.DecodeString(id); e != nil {
				p.RejectedShortIDs[raw] = "short ID is not hexadecimal"
				continue
			}
		}
		p.ShortIDs = append(p.ShortIDs, id)
	}
	sort.Strings(p.ShortIDs)
	if len(p.RejectedShortIDs) > 0 {
		p.Status = "partial"
	}
	return p, nil
}

// Service recovery / configuration mutation ordering ------------------------
type ServiceRecoveryPolicyRequest struct {
	Service           string `json:"service"`
	Operation         string `json:"operation"`
	BackupExists      bool   `json:"backup_exists"`
	ConfigValidated   bool   `json:"config_validated"`
	HealthBefore      string `json:"health_before"`
	HealthAfter       string `json:"health_after"`
	RollbackAvailable bool   `json:"rollback_available"`
	LogTailLines      int    `json:"log_tail_lines"`
}
type ServiceRecoveryPolicyPlan struct {
	Status                                                    string   `json:"status"`
	Steps                                                     []string `json:"steps"`
	RollbackSteps                                             []string `json:"rollback_steps"`
	Warnings                                                  []string `json:"warnings"`
	RunsShell, ControlsService, WritesConfig, ChangesFirewall bool
	ReadOnly                                                  bool     `json:"read_only"`
	Invariants                                                []string `json:"invariants"`
}

func BuildServiceRecoveryPolicyPlan(r ServiceRecoveryPolicyRequest) (ServiceRecoveryPolicyPlan, error) {
	service := strings.TrimSpace(r.Service)
	op := strings.ToLower(strings.TrimSpace(r.Operation))
	if service == "" || len(service) > 128 || !map[string]bool{"update": true, "restart": true, "restore": true, "reconfigure": true}[op] || r.LogTailLines < 0 || r.LogTailLines > 10000 {
		return ServiceRecoveryPolicyPlan{}, fmt.Errorf("invalid service recovery request")
	}
	p := ServiceRecoveryPolicyPlan{Status: "ready", ReadOnly: true, Invariants: []string{"configuration-changing operations require a recoverable backup or an explicit rollback mechanism", "configuration is validated before a restart/reload step", "health is checked after the proposed change before success is claimed", "log inspection is bounded and never grants shell, service-manager, or firewall authority"}}
	if op == "update" || op == "reconfigure" {
		p.Steps = append(p.Steps, "capture-current-config", "create-backup", "stage-new-config", "validate-staged-config")
	}
	if op == "restore" {
		p.Steps = append(p.Steps, "verify-backup", "stage-backup", "validate-staged-config")
	}
	p.Steps = append(p.Steps, "apply-or-restart", "check-health")
	if r.LogTailLines > 0 {
		p.Steps = append(p.Steps, fmt.Sprintf("inspect-last-%d-log-lines", r.LogTailLines))
	}
	if (op == "update" || op == "reconfigure" || op == "restore") && !r.BackupExists && !r.RollbackAvailable {
		p.Status = "blocked"
		p.Warnings = append(p.Warnings, "no backup or rollback path is available")
	}
	if (op == "update" || op == "reconfigure" || op == "restore") && !r.ConfigValidated {
		p.Status = "blocked"
		p.Warnings = append(p.Warnings, "configuration has not been validated")
	}
	if strings.ToLower(strings.TrimSpace(r.HealthAfter)) == "unhealthy" {
		p.Status = "rollback-required"
		if r.RollbackAvailable || r.BackupExists {
			p.RollbackSteps = []string{"restore-previous-config", "restart-or-reload", "recheck-health"}
		} else {
			p.Warnings = append(p.Warnings, "post-change health is unhealthy but no rollback path is available")
		}
	}
	sort.Strings(p.Warnings)
	return p, nil
}

// Higher-order network trust bundle ------------------------------------------
type NetworkTrustBundleRequest struct {
	Existing        *NetworkEvidenceBundleRequest `json:"existing,omitempty"`
	ClientHello     *ClientHelloEvidenceRequest   `json:"client_hello,omitempty"`
	EncryptedDNS    *EncryptedDNSPolicyRequest    `json:"encrypted_dns,omitempty"`
	TorLab          *TorLabRelayRequest           `json:"tor_lab,omitempty"`
	ProxyChain      *ProxyChainSafetyRequest      `json:"proxy_chain,omitempty"`
	Replay          *TransportReplayRequest       `json:"replay,omitempty"`
	SecretRefresh   *SecretRefreshPolicyRequest   `json:"secret_refresh,omitempty"`
	Reality         *RealityAdmissionRequest      `json:"reality,omitempty"`
	ServiceRecovery *ServiceRecoveryPolicyRequest `json:"service_recovery,omitempty"`
}
type NetworkTrustBundlePlan struct {
	Status          string                     `json:"status"`
	Selected        []string                   `json:"selected"`
	Warnings        []string                   `json:"warnings"`
	Existing        *NetworkEvidenceBundlePlan `json:"existing,omitempty"`
	ClientHello     *ClientHelloEvidencePlan   `json:"client_hello,omitempty"`
	EncryptedDNS    *EncryptedDNSPolicyPlan    `json:"encrypted_dns,omitempty"`
	TorLab          *TorLabRelayPlan           `json:"tor_lab,omitempty"`
	ProxyChain      *ProxyChainSafetyPlan      `json:"proxy_chain,omitempty"`
	Replay          *TransportReplayPlan       `json:"replay,omitempty"`
	SecretRefresh   *SecretRefreshPolicyPlan   `json:"secret_refresh,omitempty"`
	Reality         *RealityAdmissionPlan      `json:"reality,omitempty"`
	ServiceRecovery *ServiceRecoveryPolicyPlan `json:"service_recovery,omitempty"`
	ReadOnly        bool                       `json:"read_only"`
	Invariants      []string                   `json:"invariants"`
}

func BuildNetworkTrustBundlePlan(r NetworkTrustBundleRequest) (NetworkTrustBundlePlan, error) {
	p := NetworkTrustBundlePlan{Status: "ready", ReadOnly: true, Invariants: []string{"aggregate status is the conservative composition of selected read-only child plans", "unknown, blocked, partial, stale, expired, replayed, incomplete, or not-ready evidence can only degrade the aggregate", "the bundle introduces no runtime, secret, process, DNS, Tor, proxy, TLS, firewall, or configuration authority"}}
	degrade := func(label, state string) {
		bad := map[string]bool{"degraded": true, "blocked": true, "not-ready": true, "partial": true, "stale": true, "expired": true, "incomplete": true, "rollback-required": true, "connected-not-ready": true}
		if bad[state] {
			p.Status = "degraded"
			p.Warnings = append(p.Warnings, label+" is "+state)
		}
	}
	if r.Existing != nil {
		v, e := BuildNetworkEvidenceBundlePlan(*r.Existing)
		if e != nil {
			return p, fmt.Errorf("existing: %w", e)
		}
		p.Existing = &v
		p.Selected = append(p.Selected, "network-evidence")
		degrade("network evidence", v.Status)
	}
	if r.ClientHello != nil {
		v, e := BuildClientHelloEvidencePlan(*r.ClientHello)
		if e != nil {
			return p, fmt.Errorf("client_hello: %w", e)
		}
		p.ClientHello = &v
		p.Selected = append(p.Selected, "client-hello")
		degrade("client hello", v.Status)
	}
	if r.EncryptedDNS != nil {
		v, e := BuildEncryptedDNSPolicyPlan(*r.EncryptedDNS)
		if e != nil {
			return p, fmt.Errorf("encrypted_dns: %w", e)
		}
		p.EncryptedDNS = &v
		p.Selected = append(p.Selected, "encrypted-dns")
	}
	if r.TorLab != nil {
		v, e := BuildTorLabRelayPlan(*r.TorLab)
		if e != nil {
			return p, fmt.Errorf("tor_lab: %w", e)
		}
		p.TorLab = &v
		p.Selected = append(p.Selected, "tor-lab")
		degrade("Tor lab", v.Status)
	}
	if r.ProxyChain != nil {
		v, e := BuildProxyChainSafetyPlan(*r.ProxyChain)
		if e != nil {
			return p, fmt.Errorf("proxy_chain: %w", e)
		}
		p.ProxyChain = &v
		p.Selected = append(p.Selected, "proxy-chain")
		degrade("proxy chain", v.Status)
	}
	if r.Replay != nil {
		v, e := BuildTransportReplayPlan(*r.Replay)
		if e != nil {
			return p, fmt.Errorf("replay: %w", e)
		}
		p.Replay = &v
		p.Selected = append(p.Selected, "transport-replay")
		degrade("transport replay", v.Status)
	}
	if r.SecretRefresh != nil {
		v, e := BuildSecretRefreshPolicyPlan(*r.SecretRefresh)
		if e != nil {
			return p, fmt.Errorf("secret_refresh: %w", e)
		}
		p.SecretRefresh = &v
		p.Selected = append(p.Selected, "secret-refresh")
		degrade("secret refresh", v.State)
	}
	if r.Reality != nil {
		v, e := BuildRealityAdmissionPlan(*r.Reality)
		if e != nil {
			return p, fmt.Errorf("reality: %w", e)
		}
		p.Reality = &v
		p.Selected = append(p.Selected, "reality")
		degrade("REALITY admission", v.Status)
	}
	if r.ServiceRecovery != nil {
		v, e := BuildServiceRecoveryPolicyPlan(*r.ServiceRecovery)
		if e != nil {
			return p, fmt.Errorf("service_recovery: %w", e)
		}
		p.ServiceRecovery = &v
		p.Selected = append(p.Selected, "service-recovery")
		degrade("service recovery", v.Status)
	}
	if len(p.Selected) == 0 {
		return p, fmt.Errorf("at least one trust-bundle component is required")
	}
	sort.Strings(p.Selected)
	sort.Strings(p.Warnings)
	return p, nil
}

func minInt236(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func dedupeInts236(in []int) []int {
	if len(in) == 0 {
		return nil
	}
	out := []int{in[0]}
	for _, v := range in[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}
