# Peer convergence validation

This file is an evidence index. Runtime authority remains in the target modules named by the adoption ledger.

- ZIP members: 3320
- Directories: 341
- File/symlink surfaces: 2979
- Symbols: 7351
- Module families: 109
- Semantic decisions: 110
- Target-local repairs: 4
- Accounted target delta paths: 100 (+ the target-delta manifest itself)

## Aether

### sem048
**SEM048 — SOCKS5 UDP association source binding**

- Source: `aether/src/socks.rs` / `dns_response_matches`
- Disposition: `adapted`
- Transformation: `adaptation`; topology `one-to-one`
- Rationale: Donor documents first-packet capture failure and binds UDP authority to TCP/declared endpoint; target hardens existing relay.
- Target capability: SOCKS UDP association
- Target node(s): `src/apps/daemon/internal/runtime/proxy/socks5_stun.go#socksUDPClientAllowed`
- Acceptance/decision evidence: `src/apps/daemon/internal/runtime/proxy/socks5_stun_test.go#TestSocksUDPClientAuthorityRejectsForeignFirstPacket`
- Invariant: UDP client authority comes from control peer or declared endpoint before accepting payload
- Negative invariant: foreign first packet/wrong declared port cannot seize association
- Validation status: `verified`

### sem049
**SEM049 — accept failure backoff**

- Source: `aether/src/socks.rs` / `accept_backoff`
- Disposition: `adapted`
- Transformation: `adaptation`; topology `one-to-many`
- Rationale: Donor yields on listener exhaustion; two LumiNet listeners retried immediately and could hot-spin.
- Target capability: listener retry
- Target node(s): `src/apps/daemon/internal/runtime/proxy/accept_backoff.go#waitAfterAcceptError`
- Acceptance/decision evidence: `src/apps/daemon/internal/runtime/proxy/accept_backoff_test.go#TestWaitAfterAcceptErrorYieldsAndHonorsShutdown`
- Invariant: non-shutdown accept errors yield before retry
- Negative invariant: listener errors cannot hot-spin CPU
- Validation status: `verified`

### sem050
**SEM050 — full DNS query/response correlation**

- Source: `aether/src/dns.rs` / `accepts_a_reply_that_matches_the_query`
- Disposition: `hardened`
- Transformation: `hardening`; topology `one-to-one`
- Rationale: Target UDP resolver checked only txid; donor requires echoed question semantics.
- Target capability: DNS resolver
- Target node(s): `src/packages/lumicore/src/dns/packet.rs#response_matches_query;src/packages/lumicore/src/dns/udp.rs#resolve`
- Acceptance/decision evidence: `src/packages/lumicore/src/dns/packet.rs#response_match_requires_full_echoed_question`
- Invariant: response matches txid, QR, question count, qname, qtype and class
- Negative invariant: txid-only or altered-question response is rejected
- Validation status: `statically-validated`

### sem051
**SEM051 — HTTP health status-line parsing**

- Source: `aether/src/tunnelping.rs` / `http_status_code`
- Disposition: `hardened`
- Transformation: `hardening`; topology `one-to-one`
- Rationale: Donor regression oracle rejects body/header substrings masquerading as a 204 status. The target DiagnosticRunbook is a public LumiCore capability with no current in-repo runtime caller, so this is library-surface hardening rather than a shipped workflow claim.
- Target capability: public LumiCore diagnostic capability
- Target node(s): `src/packages/lumicore/src/diagnostics/runbook.rs#http_status_code`
- Acceptance/decision evidence: `src/packages/lumicore/src/diagnostics/runbook.rs#portal_status_uses_status_line_only`
- Invariant: health verdict is derived from the HTTP status line only
- Negative invariant: body/header text cannot forge status
- Validation status: `statically-validated`

### sem052
**SEM052 — private durable atomic config write**

- Source: `aether/src/config.rs` / `write_private`
- Disposition: `adapted`
- Transformation: `adaptation`; topology `one-to-one`
- Rationale: Donor uses owner-only temp file and sync before atomic rename; target keeps its schema/secret semantics and adopts durability/privacy.
- Target capability: config persistence
- Target node(s): `src/apps/daemon/internal/foundation/config/atomic_file.go#writeAtomicPrivateFile`
- Acceptance/decision evidence: `src/apps/daemon/internal/foundation/config/atomic_file_test.go#TestWriteAtomicPrivateFileIsDurableAndPrivate`
- Invariant: config temp is 0600, synced, closed and atomically renamed
- Negative invariant: partial/crash write never replaces config with unsynced/truncated bytes
- Validation status: `verified`

### sem053
**SEM053 — CGNAT/link-local private-network predicate**

- Source: `aether/src/routing.rs` / `is_private`
- Disposition: `guardrail-derived`
- Transformation: `guardrail derivation`; topology `one-to-many`
- Rationale: Donor predicate exposed multiple weaker target duplicates; target consolidates onto existing canonical local/LAN owner.
- Target capability: local/private classification
- Target node(s): `src/apps/daemon/internal/networking/geoip/geoip.go#IsPrivateIP`
- Acceptance/decision evidence: `src/apps/daemon/internal/networking/geoip/geoip_test.go#TestIsPrivateIP`
- Invariant: all safety callers classify CGNAT/link-local consistently
- Negative invariant: no caller falls back to narrower net.IP.IsPrivate for egress/scan safety
- Validation status: `verified`

### sem054
**SEM054 — bounded provider API response body**

- Source: `aether/src/apifront.rs` / `MAX_BODY`
- Disposition: `hardened`
- Transformation: `hardening`; topology `one-to-many`
- Rationale: Target had unbounded provider/DNS/covert response reads; donor 512KiB ceiling exposed the broader missing invariant that every remote protocol/control reader needs an owner-specific payload ceiling.
- Target capability: bounded remote I/O
- Target node(s): `src/apps/daemon/cmd/doctor.go#runDoctor;src/apps/daemon/internal/analysis/diagnostics/diagnostics.go#readBoundedDiagnosticBody;src/apps/daemon/internal/analysis/scanner/cloudflare_deployer.go#DeployWorkerScript;src/apps/daemon/internal/integrations/captchaclient/http_bounds.go#readBoundedCaptchaResponse;src/apps/daemon/internal/integrations/provision/cloudflare.go#doReq;src/apps/daemon/internal/integrations/relayclient/http_bounds.go#readBoundedRelayControlResponse;src/apps/daemon/internal/integrations/sub/egress.go#readBoundedSubscriptionBody;src/apps/daemon/internal/networking/dns/http_bounds.go#readBoundedDNSBody;src/apps/daemon/internal/networking/dns/ddns_bounds.go#decodeBoundedDDNSJSON;src/apps/daemon/internal/networking/geoip/http_bounds.go#decodeBoundedGeoIPJSON;src/apps/daemon/internal/runtime/proxy/http_bounds.go#readBoundedProxyHTTPBody`
- Acceptance/decision evidence: `src/apps/daemon/internal/integrations/provision/cloudflare_bounds_test.go#TestCFClientRejectsOversizedProviderResponse`
- Invariant: remote bodies are bounded by protocol/payload contract before allocation/parsing
- Negative invariant: provider-controlled body cannot allocate unbounded memory
- Validation status: `verified`

### sem055
**SEM055 — automatic registration POST retries**

- Source: `aether/src/account.rs` / `send_with_retry`
- Disposition: `rejected-with-reason`
- Transformation: `rejection`; topology `negative-to-guardrail`
- Rationale: Registration creates remote account/device state and target has no proven idempotency key/reconciliation; timeout retry can duplicate side effects.
- Target capability: WARP registration
- Target node(s): `n/a`
- Acceptance/decision evidence: `governance/convergence/peer-validation.md#aether-registration-idempotency`
- Invariant: ambiguous remote mutation is retried only with idempotency/reconciliation
- Negative invariant: do not blindly retry account/device creation POST
- Validation status: `reviewed`

### sem056
**SEM056 — MASQUE certificate lifetime/renewal window**

- Source: `aether/src/account.rs` / `masque_cert_expiring`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: Strong lifecycle predicate, but LumiNet currently has no persisted MASQUE certificate owner to harden without introducing a new transport/auth plane.
- Target capability: future MASQUE cert lifecycle
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: future cert cache must reject future-issued/expired certs and renew before expiry
- Negative invariant: do not create unused certificate plane
- Validation status: `reviewed`

### sem057
**SEM057 — block-before-proxy precedence**

- Source: `aether/src/routing.rs` / `decide`
- Disposition: `rejected-with-reason`
- Transformation: `rejection`; topology `one-to-one`
- Rationale: Target intentionally protects service/anticensorship categories from broad block/direct categories and current corpora show no conflict requiring donor precedence.
- Target capability: domain routing
- Target node(s): `n/a`
- Acceptance/decision evidence: `governance/convergence/peer-validation.md#aether-route-precedence`
- Invariant: route precedence is target policy driven by explicit category intent
- Negative invariant: do not change precedence solely to mirror donor
- Validation status: `reviewed`

### sem058
**SEM058 — bounded per-tick network queues/drop-on-full**

- Source: `aether/src/netstack.rs` / `MAX_INGEST_PER_TICK`
- Disposition: `superseded`
- Transformation: `comparison`; topology `one-to-one`
- Rationale: LumiNet already has bounded queues/context cancellation in its runtime owners; importing smoltcp netstack would duplicate transport authority.
- Target capability: runtime backpressure
- Target node(s): `src/apps/daemon/internal/runtime/proxy/evasion_tunnel.go#EvasionTunnelManager`
- Acceptance/decision evidence: `n/a`
- Invariant: queues remain bounded and cancellation-owned
- Negative invariant: no second userspace netstack solely for donor behavior
- Validation status: `reviewed`

### sem059
**SEM059 — bounded transient UDP receive error tolerance**

- Source: `aether/src/wireguard.rs` / `MAX_TRANSIENT_RECV_ERRORS`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: Useful tunnel-loop oracle; LumiNet WARP plane does not expose the same long-lived userspace receive loop to patch directly.
- Target capability: WARP transport reference
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: future receive loops distinguish transient from fatal socket errors with bounded retry
- Negative invariant: no unbounded retry or fatal-on-every-transient policy
- Validation status: `reviewed`

### sem060
**SEM060 — CIDR ordering/sampling and MASQUE reachability probes**

- Source: `aether/src/prober.rs` / `MasqueProbe`
- Disposition: `superseded`
- Transformation: `comparison`; topology `one-to-one`
- Rationale: Target scanners/WARP scanner already own configurable concurrency/timeouts/real handshake verification.
- Target capability: probe strategy
- Target node(s): `src/apps/daemon/internal/runtime/warp/warp_scanner.go#WARPScanner`
- Acceptance/decision evidence: `n/a`
- Invariant: probe ordering remains explicit/configurable
- Negative invariant: no donor-specific range priority becomes hidden policy
- Validation status: `reviewed`

### sem061
**SEM061 — WireGuard range sampling/verification**

- Source: `aether/src/wg_prober.rs` / `WgProbe`
- Disposition: `superseded`
- Transformation: `comparison`; topology `one-to-one`
- Rationale: Target WARP scanner already does real WireGuard handshake and endpoint qualification.
- Target capability: WARP scanning
- Target node(s): `src/apps/daemon/internal/runtime/warp/warp_scanner.go#WARPScanner`
- Acceptance/decision evidence: `n/a`
- Invariant: WARP qualification stays target-native
- Negative invariant: no duplicate WireGuard scanner
- Validation status: `reviewed`

### sem062
**SEM062 — hardware-adaptive socket/buffer profile**

- Source: `aether/src/sysprofile.rs` / `udp_socket_buf_bytes`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: Adaptive tiering is useful performance reference, but hidden hardware-derived behavior would reduce operator predictability without target benchmarks.
- Target capability: performance tuning reference
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: performance defaults change only with target measurement/configuration
- Negative invariant: no opaque donor hardware policy
- Validation status: `reviewed`

### sem063
**SEM063 — last connection cache**

- Source: `aether/src/lastconn.rs` / `LastConn`
- Disposition: `superseded`
- Transformation: `comparison`; topology `one-to-one`
- Rationale: Target profile/pingcache/state owners are deeper and already provide TTL/dedup lifecycle.
- Target capability: connection history
- Target node(s): `src/apps/daemon/internal/foundation/pingcache/pingcache.go#PingCache`
- Acceptance/decision evidence: `n/a`
- Invariant: connection metadata remains in target profile/evidence stores
- Negative invariant: no duplicate ad-hoc lastconn file
- Validation status: `reviewed`

### sem064
**SEM064 — Cloudflare Access/Zero Trust token login/cache**

- Source: `aether/src/zerotrust.rs` / `resolve_token`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: Potential future authenticated-edge integration; no current target authority/consumer justifies importing interactive token acquisition.
- Target capability: future Zero Trust access
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: future token cache must validate expiry and keep secrets protected
- Negative invariant: no unused authentication plane
- Validation status: `reviewed`

### sem065
**SEM065 — MASQUE CONNECT-IP capsule parsing/tunnel**

- Source: `aether/src/masque.rs` / `CapsuleParser`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: Target has no MASQUE transport authority; direct import would create a second transport stack.
- Target capability: MASQUE reference
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: new transport requires explicit target owner and interop tests
- Negative invariant: no parallel donor transport subsystem
- Validation status: `reviewed`

### sem066
**SEM066 — HTTP/2 MASQUE fallback**

- Source: `aether/src/masque_h2.rs` / `verify_h2`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: Transport-specific fallback retained as reference; no target H2-MASQUE plane.
- Target capability: MASQUE H2 reference
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: transport fallback requires target protocol owner
- Negative invariant: no unused H2 tunnel stack
- Validation status: `reviewed`

### sem067
**SEM067 — quiche MASQUE/QUIC client**

- Source: `aether/src/quic.rs` / `verify_masque`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: Quiche-based transport would duplicate target networking authority and native stack.
- Target capability: QUIC/MASQUE reference
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: transport additions must integrate target ownership/ABI/telemetry
- Negative invariant: no second QUIC stack from donor packaging
- Validation status: `reviewed`

### sem068
**SEM068 — fragmented stream adapter**

- Source: `aether/src/fragment.rs` / `FragmentedStream`
- Disposition: `superseded`
- Transformation: `comparison`; topology `one-to-one`
- Rationale: LumiNet already has multiple fragmentation/evasion implementations and controls.
- Target capability: fragmentation
- Target node(s): `src/apps/daemon/internal/protocols/tlsfragment/utls_fragment.go#WrapUTLSFragmentConn`
- Acceptance/decision evidence: `n/a`
- Invariant: fragmentation remains target policy/implementation
- Negative invariant: no duplicate adapter without measured benefit
- Validation status: `reviewed`

### sem069
**SEM069 — noise traffic generator**

- Source: `aether/src/noize.rs` / `Noize`
- Disposition: `superseded`
- Transformation: `comparison`; topology `one-to-one`
- Rationale: LumiNet already has decoy/noise/evasion ownership with cancellation and bounds.
- Target capability: noise/decoy
- Target node(s): `src/apps/daemon/internal/runtime/decoy/manager.go#Manager`
- Acceptance/decision evidence: `n/a`
- Invariant: noise tasks stay cancellation-owned and bounded
- Negative invariant: no donor-specific noise loop
- Validation status: `reviewed`

### sem070
**SEM070 — noise rate/range parser and generator**

- Source: `aether/src/aethernoize.rs` / `parse_range`
- Disposition: `superseded`
- Transformation: `comparison`; topology `one-to-one`
- Rationale: Same responsibility already lives in target decoy/evasion owners.
- Target capability: noise/decoy
- Target node(s): `src/apps/daemon/internal/runtime/decoy/manager.go#Manager`
- Acceptance/decision evidence: `n/a`
- Invariant: noise parameters remain validated by target owner
- Negative invariant: no duplicate CLI noise plane
- Validation status: `reviewed`

### sem071
**SEM071 — ECH retry configuration extraction**

- Source: `aether/src/tls.rs` / `extract_ech_retry_configs`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: Useful ECH interoperability reference; target ECH implementation already owns TLS behavior and cannot be replaced without native tests.
- Target capability: ECH reference
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: ECH retry data remains verified by target TLS owner
- Negative invariant: no donor BoringSSL coupling
- Validation status: `reviewed`

### sem072
**SEM072 — bounded reusable buffer retention**

- Source: `quiche/buffer-pool/src/lib.rs` / `BufferPool`
- Disposition: `hardened`
- Transformation: `hardening`; topology `one-to-one`
- Rationale: Donor pool treats configured size as a retention ceiling; target constructor previously only preallocated then grew forever. BufferPool is a public LumiCore library capability with no current in-repo runtime constructor call, so this is capability-level hardening rather than a shipped runtime claim.
- Target capability: public LumiCore buffer-pool capability
- Target node(s): `src/packages/lumicore/src/data/ring_buffer.rs#BufferPool`
- Acceptance/decision evidence: `src/packages/lumicore/src/data/ring_buffer.rs#test_buffer_pool_never_retains_more_than_capacity`
- Invariant: released fallback buffers cannot grow retained pool above capacity
- Negative invariant: pool retention is never unbounded
- Validation status: `statically-validated`

### sem073
**SEM073 — task kill-switch tree**

- Source: `quiche/task-killswitch/src/lib.rs` / `KillSwitch`
- Disposition: `superseded`
- Transformation: `comparison`; topology `one-to-one`
- Rationale: LumiNet Go contexts/process supervisor and Rust task ownership already provide cancellation without another hierarchy.
- Target capability: task cancellation
- Target node(s): `src/apps/daemon/internal/workflows/jobs/manager.go#CancelJob;src/apps/daemon/internal/runtime/runtimecore/manager.go#Close`
- Acceptance/decision evidence: `n/a`
- Invariant: cancellation remains owner-scoped and propagating
- Negative invariant: no duplicate kill-switch authority
- Validation status: `reviewed`

### sem074
**SEM074 — bounds-checked octet reader/writer**

- Source: `quiche/octets/src/lib.rs` / `Octets`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: Excellent parser oracle, but direct crate import would expand Rust dependency surface; target parsers keep local bounds checks.
- Target capability: parser testing reference
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: binary parsers validate length before access
- Negative invariant: no unchecked indexing from untrusted bytes
- Validation status: `reviewed`

### sem075
**SEM075 — batched datagram/GSO socket abstraction**

- Source: `quiche/datagram-socket/src/lib.rs` / `DatagramSocket`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: High-performance QUIC datagram implementation is transport-specific; no measured target need justifies adoption.
- Target capability: datagram performance reference
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: performance optimizations require target benchmarks and semantics
- Negative invariant: no unmeasured transport dependency
- Validation status: `reviewed`

### sem076
**SEM076 — HTTP/3/QPACK implementation**

- Source: `quiche/quiche/src/h3/mod.rs` / `Connection`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: Full H3/QPACK authority retained for interoperability research; target does not own quiche H3 runtime.
- Target capability: HTTP/3 reference
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: new H3 support must be target-native and protocol-tested
- Negative invariant: no embedded second H3 stack
- Validation status: `reviewed`

### sem077
**SEM077 — QUIC congestion/loss recovery suite**

- Source: `quiche/quiche/src/recovery/mod.rs` / `Recovery`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: Cubic/Reno/PRR/BBR/BBRv2/pacing are valid transport references but inseparable from quiche packet/recovery model.
- Target capability: congestion reference
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: transport algorithms are adopted only with matching state model/benchmarks
- Negative invariant: no isolated algorithm transplant without transport invariants
- Validation status: `reviewed`

### sem078
**SEM078 — QUIC PMTUD state machine**

- Source: `quiche/quiche/src/pmtud.rs` / `Pmtud`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: PMTUD implementation is specific to quiche path state; retained as reference.
- Target capability: PMTUD reference
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: path MTU state requires matching transport path owner
- Negative invariant: no detached PMTUD state machine
- Validation status: `reviewed`

### sem079
**SEM079 — path validation/migration**

- Source: `quiche/quiche/src/path.rs` / `PathMap`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: QUIC path/CID migration is transport-specific and not a standalone target capability.
- Target capability: QUIC migration reference
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: migration authority stays with transport owner
- Negative invariant: no partial quiche path state
- Validation status: `reviewed`

### sem080
**SEM080 — QLOG schema/serialization**

- Source: `quiche/qlog/src/lib.rs` / `QlogStreamer`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: Useful standard telemetry reference; LumiNet keeps one existing evidence/telemetry schema instead of a second logging authority.
- Target capability: telemetry reference
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: telemetry schemas remain target-owned/versioned
- Negative invariant: no parallel qlog authority without QUIC runtime
- Validation status: `reviewed`

### sem081
**SEM081 — Chrome NetLog conversion**

- Source: `quiche/netlog/src/lib.rs` / `NetlogEvent`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: Interoperability/export reference only; no target consumer currently needs NetLog.
- Target capability: telemetry export reference
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: exports are derived from target telemetry
- Negative invariant: no second telemetry source of truth
- Validation status: `reviewed`

### sem082
**SEM082 — QLOG visualization UI**

- Source: `quiche/qlog-dancer/index.html` / `qlog-dancer`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: Visualization reference only; target UI already has diagnostics/evidence surfaces.
- Target capability: diagnostics visualization reference
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: UI remains projection of target evidence
- Negative invariant: no donor visualization as authority
- Validation status: `reviewed`

### sem083
**SEM083 — QUIC fuzz corpus/harness family**

- Source: `quiche/fuzz/src/packet_recv_server.rs` / `fuzz_target`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-many`
- Rationale: Large fuzz corpus is valuable transport/parser evidence but does not map to target protocol owners without quiche equivalence.
- Target capability: fuzzing reference
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: future parser ports should reuse equivalent malformed-input oracles
- Negative invariant: do not claim target coverage from unrelated quiche fuzzing
- Validation status: `reviewed`

### sem084
**SEM084 — Tokio QUIC router/socket framework**

- Source: `quiche/tokio-quiche/src/lib.rs` / `QuicListener`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: Would duplicate target daemon/runtime networking plane and operational cost.
- Target capability: async QUIC reference
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: new async transport boundary needs concrete target requirement
- Negative invariant: no donor-shaped runtime plane
- Validation status: `reviewed`

### sem085
**SEM085 — interactive HTTP/3 client/scenario runner**

- Source: `quiche/h3i/src/main.rs` / `h3i`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: Useful protocol test/oracle surface, not a target runtime module.
- Target capability: HTTP3 test reference
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: protocol tools remain non-authoritative
- Negative invariant: no unused CLI tool in target
- Validation status: `reviewed`

### sem086
**SEM086 — quiche C ABI**

- Source: `quiche/quiche/src/ffi.rs` / `ffi`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: Target already has its own LumiCore ABI; importing quiche C ABI would broaden native compatibility surface.
- Target capability: native ABI reference
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: one target-owned ABI remains authoritative
- Negative invariant: no second native ABI without product consumer
- Validation status: `reviewed`

### sem087
**SEM087 — peer-convergence evidence plane**

- Source: `README.md` / `repository corpus`
- Disposition: `synthesized`
- Transformation: `synthesis`; topology `many-to-many`
- Rationale: Eight heterogeneous donors contribute cross-cutting code/data/tests/negative lessons; durable traceability is a justified new governance plane.
- Target capability: peer convergence governance
- Target node(s): `governance/convergence/peer-adoption-ledger.csv#record_id;scripts/checks/check_peer_convergence.py#main`
- Acceptance/decision evidence: `scripts/checks/check_peer_convergence.py#peer-accountability`
- Invariant: every donor surface/module/symbol and semantic decision is traceable to target ownership/evidence
- Negative invariant: no donor evidence or target adoption becomes orphaned
- Validation status: `statically-validated`

### sem089
**SEM089 — environment/CLI configuration mutation**

- Source: `aether/src/cli.rs` / `parse_and_apply`
- Disposition: `superseded`
- Transformation: `comparison`; topology `one-to-one`
- Rationale: Aether maps CLI flags into process environment; LumiNet already has Cobra/config owners and should not add environment-as-authority side effects.
- Target capability: operator configuration
- Target node(s): `src/apps/daemon/cmd/root.go#rootCmd`
- Acceptance/decision evidence: `governance/convergence/peer-validation.md#aether-cli-environment-authority`
- Invariant: CLI arguments are validated by target command/config owners
- Negative invariant: do not mutate hidden process-global configuration as a second authority
- Validation status: `reviewed`

### sem090
**SEM090 — Cloudflare MASQUE endpoints, ALPN, pins and anycast seeds**

- Source: `aether/src/consts.rs` / `MASQUE_PINS`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-many`
- Rationale: Protocol constants and pins are valuable interoperability evidence but are vendor/time-sensitive and tied to Aether MASQUE transport.
- Target capability: Cloudflare protocol reference
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: provider constants remain versioned with their target transport owner
- Negative invariant: do not copy volatile donor endpoints/pins into unrelated target planes
- Validation status: `reviewed`

### sem091
**SEM091 — structured Aether runtime error taxonomy**

- Source: `aether/src/error.rs` / `AetherError`
- Disposition: `superseded`
- Transformation: `comparison`; topology `one-to-one`
- Rationale: LumiNet already has target-owned structured errors and subsystem-specific error mapping; importing a donor-wide enum would flatten target ownership.
- Target capability: error taxonomy
- Target node(s): `src/apps/daemon/internal/runtime/runtimecore/manager.go#ErrInvalidRequest;src/apps/daemon/internal/integrations/sub/egress.go#ErrUnsafeRemoteTarget`
- Acceptance/decision evidence: `n/a`
- Invariant: errors remain owned and contextual at target seams
- Negative invariant: no donor-global error enum across unrelated target modules
- Validation status: `reviewed`

### sem092
**SEM092 — protocol selection, reconnect and peer hunting orchestration**

- Source: `aether/src/main.rs` / `run_gool`
- Disposition: `superseded`
- Transformation: `comparison`; topology `many-to-many`
- Rationale: Aether monolith coordinates MASQUE/WireGuard/scanning/UI prompts; LumiNet already decomposes these responsibilities across workflows, profile service, scanners and runtime owners.
- Target capability: runtime orchestration
- Target node(s): `src/apps/daemon/internal/workflows/jobs/manager.go#JobManager;src/apps/daemon/internal/runtime/runtimecore/manager.go#Manager`
- Acceptance/decision evidence: `n/a`
- Invariant: workflow/runtime owners remain independently testable and authoritative
- Negative invariant: do not recreate a donor-shaped all-in-one connection orchestrator
- Validation status: `reviewed`

### sem093
**SEM093 — abort-handle forwarder guard**

- Source: `aether/src/main.rs` / `ForwarderGuard`
- Disposition: `superseded`
- Transformation: `comparison`; topology `one-to-one`
- Rationale: Abort-on-drop is a sound lifecycle primitive, but LumiNet already uses context cancellation and owner-scoped process/task lifetimes.
- Target capability: task lifecycle
- Target node(s): `src/apps/daemon/internal/workflows/jobs/manager.go#CancelJob;src/apps/daemon/internal/runtime/runtimecore/manager.go#Close`
- Acceptance/decision evidence: `n/a`
- Invariant: spawned forwarders terminate with their owning workflow
- Negative invariant: do not add a second cancellation hierarchy
- Validation status: `reviewed`

### sem094
**SEM094 — protocol reconnect/cooldown controls**

- Source: `aether/src/main.rs` / `masque_reconnect_delay`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-many`
- Rationale: Reconnect/cooldown values are useful operational reference but depend on Aether transport/prober timing and are not portable target constants.
- Target capability: reconnect tuning reference
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: retry policy belongs to the target owner and must match measured failure semantics
- Negative invariant: do not transplant donor timing constants without target evidence
- Validation status: `reviewed`

### sem095
**SEM095 — structured Cloudflare rejection extraction and rate-limit explanation**

- Source: `aether/src/account.rs` / `extract_api_error`
- Disposition: `adapted`
- Transformation: `adaptation`; topology `one-to-one`
- Rationale: Aether separates structured Cloudflare rejection details and Retry-After hints from retry policy. LumiNet adopts only the bounded error-extraction/message primitive in its existing Cloudflare provisioning owner; automatic registration mutation retry remains rejected without an idempotency contract.
- Target capability: bounded actionable provider errors
- Target node(s): `src/apps/daemon/internal/integrations/provision/cloudflare_errors.go#formatCloudflareAPIError;src/apps/daemon/internal/integrations/provision/cloudflare.go#doReq`
- Acceptance/decision evidence: `src/apps/daemon/internal/integrations/provision/cloudflare_errors_test.go#TestFormatCloudflareAPIErrorExtractsStructuredErrorsAndRetryHint`
- Invariant: bounded provider failures retain structured status/code/message and Retry-After context without changing mutation retry authority
- Negative invariant: never couple error-detail extraction to automatic non-idempotent registration retries
- Validation status: `verified`

### sem096
**SEM096 — bounded HTTP proxy head parsing and authority normalization**

- Source: `aether/src/socks.rs` / `parse_request_line`
- Disposition: `superseded`
- Transformation: `comparison`; topology `one-to-many`
- Rationale: Aether has a compact explicit-proxy parser with 16KiB head ceiling; LumiNet already owns HTTP/proxy routing and bounded remote-read policy.
- Target capability: HTTP proxy parsing
- Target node(s): `src/apps/daemon/internal/runtime/proxy/https_connect_fragmentor.go#HTTPSConnectFragmentor;src/apps/daemon/internal/runtime/proxy/http_bounds.go#readBoundedProxyHTTPBody`
- Acceptance/decision evidence: `n/a`
- Invariant: HTTP request metadata is bounded and parsed by target proxy owners
- Negative invariant: do not add a parallel HTTP proxy parser solely from donor implementation
- Validation status: `reviewed`

### sem097
**SEM097 — JWT expiry parsing and live-token reuse**

- Source: `aether/src/zerotrust.rs` / `token_expired`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: The expiry/cache predicate is sound and independently useful, but LumiNet has no current Cloudflare Access token authority or consumer.
- Target capability: future Zero Trust access
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: future cached access tokens must be reused only while live and validated
- Negative invariant: do not create token persistence without an authenticated target consumer
- Validation status: `reviewed`

### sem098
**SEM098 — service-token completeness and interactive Access login extraction**

- Source: `aether/src/zerotrust.rs` / `has_service_token`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-many`
- Rationale: Cloudflare Access login/service-token mechanics are a coherent future capability but would add identity/token authority not currently needed by LumiNet.
- Target capability: future Zero Trust access
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: identity tokens require explicit owner, expiry and protected persistence
- Negative invariant: do not smuggle browser/login state into general proxy configuration
- Validation status: `reviewed`

### sem099
**SEM099 — macOS platform transport/test harness**

- Source: `aether/src/mac_test.rs` / `mac_test`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: Platform-specific experimental harness is useful historical portability evidence but not a shipped target host contract.
- Target capability: macOS transport test reference
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: platform behavior must be exercised through supported host/native tests
- Negative invariant: do not promote experimental donor harness into product runtime
- Validation status: `reviewed`

### sem109
**SEM109 — verification-off fallback as negative TLS evidence**

- Source: `aether/src/tls.rs` / `install_verification`
- Disposition: `guardrail-derived`
- Transformation: `guardrail derivation`; topology `negative-to-guardrail`
- Rationale: Aether can disable certificate verification when no pin set is configured. LumiNet does not import that BoringSSL/pin authority; the behavior instead exposed an overly permissive target default, so ECH/TLS verification is secure by default and insecure verification remains explicit opt-in only.
- Target capability: secure-by-default ECH verification
- Target node(s): `src/apps/daemon/internal/runtime/proxy/ech.go#ECHInsecureSkipVerify;src/apps/daemon/internal/runtime/proxy/ech_test.go#TestEchClientCertValidation;scripts/checks/repo_audit.py#ECHInsecureSkipVerify`
- Acceptance/decision evidence: `scripts/checks/repo_audit.py#ECHInsecureSkipVerify`
- Invariant: ECH certificate verification is enabled by default; insecure verification requires deliberate opt-in
- Negative invariant: fallback or diagnostic paths must not silently make verification-off the repository default
- Validation status: `verified`

## Aether-GUI

### sem013
**SEM013 — bounded increasing restart delay**

- Source: `src-tauri/src/aether/status.rs` / `RETRY_BACKOFF`
- Disposition: `adapted`
- Transformation: `adaptation`; topology `one-to-one`
- Rationale: Donor state machine has explicit bounded retries; target comment claimed exponential backoff but implementation was constant. The target ProcessSupervisor currently has no production constructor call, so this is capability-level hardening, not a shipped runtime-impact claim.
- Target capability: dormant process-supervision capability
- Target node(s): `src/apps/daemon/internal/platform/system/process_supervisor.go#restartBackoff`
- Acceptance/decision evidence: `src/apps/daemon/internal/platform/system/process_supervisor_test.go#TestProcessSupervisorBackoffIncreasesAndCaps`
- Invariant: retry delay grows with consecutive failures and caps
- Negative invariant: healthy readiness must not erase one-hour circuit-breaker history
- Validation status: `verified`

### sem014
**SEM014 — healthy-state retry reset**

- Source: `src-tauri/src/aether/status.rs` / `MAX_AUTO_RETRIES`
- Disposition: `hardened`
- Transformation: `recomposition`; topology `many-to-one`
- Rationale: Readiness alone must not forgive restart debt. Eighth-order supervision resets consecutive backoff debt only after a stable ready interval while retaining a separate rolling failure window. The target ProcessSupervisor currently has no production constructor call, so this is capability-level hardening, not a shipped runtime-impact claim.
- Target capability: dormant process-supervision capability
- Target node(s): `src/apps/daemon/internal/platform/system/process_supervisor.go#recordFailureAfterRun`
- Acceptance/decision evidence: `src/apps/daemon/internal/platform/system/process_supervisor_test.go#TestProcessSupervisorStableReadinessResetsOnlyBackoffDebt`
- Invariant: a stable ready interval clears consecutive backoff debt without erasing rolling safety history
- Negative invariant: ready-then-crash loops and stale historical failures cannot incorrectly bypass or trip the rolling circuit breaker
- Validation status: `verified`

### sem015
**SEM015 — sidecar readiness from concurrent output streams**

- Source: `src-tauri/src/aether/mod.rs` / `status`
- Disposition: `hardened`
- Transformation: `hardening`; topology `one-to-one`
- Rationale: Donor readiness lineage motivated target synchronization; LumiNet now uses a single readiness latch across stdout/stderr. The target ProcessSupervisor currently has no production constructor call, so this is capability-level hardening, not a shipped runtime-impact claim.
- Target capability: dormant process-supervision capability
- Target node(s): `src/apps/daemon/internal/platform/system/process_supervisor.go#runOnce`
- Acceptance/decision evidence: `src/apps/daemon/internal/platform/system/process_supervisor_test.go#TestProcessSupervisor_Run`
- Invariant: first readiness signal is emitted once without data race
- Negative invariant: stdout/stderr cannot race shared readiness state
- Validation status: `verified`

### sem016
**SEM016 — pre-connect port collision check**

- Source: `src-tauri/src/aether/status.rs` / `port_is_live_probes_loopback_when_bound_any`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: Useful operator preflight; LumiNet already has host/network readiness probes and binding errors, so no duplicate sidecar preflight owner.
- Target capability: port readiness
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: port conflict is surfaced before/at bind
- Negative invariant: do not create UI-only port authority
- Validation status: `reviewed`

### sem017
**SEM017 — PID-file orphan termination**

- Source: `src-tauri/src/aether/orphan.rs` / `kill_pid`
- Disposition: `rejected-with-reason`
- Transformation: `rejection`; topology `negative-to-guardrail`
- Rationale: PID-only killing risks terminating an unrelated process after PID reuse.
- Target capability: process recovery
- Target node(s): `n/a`
- Acceptance/decision evidence: `governance/convergence/peer-validation.md#aether-gui-pid-reuse`
- Invariant: orphan recovery must verify executable/process identity
- Negative invariant: never kill solely by stale PID file
- Validation status: `reviewed`

### sem018
**SEM018 — bounded PTY partial-line buffer**

- Source: `src-tauri/src/aether/pty.rs` / `MAX_PARTIAL`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: 16 KiB partial buffer is a useful sidecar-stream bound; LumiNet has no PTY sidecar plane today.
- Target capability: future sidecar PTY
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: interactive process buffers must be bounded
- Negative invariant: no unbounded partial-line accumulation
- Validation status: `reviewed`

### sem019
**SEM019 — bounded client log history**

- Source: `src/state/connectionStore.ts` / `MAX_LOG_LINES`
- Disposition: `superseded`
- Transformation: `comparison`; topology `one-to-one`
- Rationale: LumiNet already uses a 500-line bounded product log surface.
- Target capability: log UX
- Target node(s): `src/packages/control-ui/src/api/contracts.ts#LogsResponse`
- Acceptance/decision evidence: `n/a`
- Invariant: client log buffers remain bounded
- Negative invariant: no unbounded UI log growth
- Validation status: `reviewed`

### sem020
**SEM020 — profile migration/validation**

- Source: `src-tauri/src/aether/profiles.rs` / `invalid_bind_is_not_forwarded`
- Disposition: `superseded`
- Transformation: `comparison`; topology `one-to-one`
- Rationale: LumiNet profile service already validates, snapshots metadata, cancels stale refreshes and owns profile lifecycle.
- Target capability: profiles
- Target node(s): `src/apps/daemon/internal/integrations/sub/profile_service.go#ProfileService`
- Acceptance/decision evidence: `n/a`
- Invariant: profile mutations remain validated and revision-safe
- Negative invariant: do not duplicate profile state in desktop host
- Validation status: `reviewed`

### sem100
**SEM100 — tray/event/focus host integration**

- Source: `src-tauri/src/tray.rs` / `atomic_flag_round_trips`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-many`
- Rationale: Useful desktop affordance and atomic state reference, but LumiNet desktop host already uses Wails and should not gain a second Tauri host plane.
- Target capability: desktop host UX reference
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: desktop host remains a thin projection of daemon/session truth
- Negative invariant: do not duplicate desktop authority via donor tray runtime
- Validation status: `reviewed`

### sem101
**SEM101 — typed status/log event envelopes**

- Source: `src-tauri/src/events.rs` / `STATUS_EVENT`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: Typed host events are useful product reference; LumiNet currently uses authenticated daemon/control-UI transport and should keep one event/state path.
- Target capability: desktop event reference
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: event payloads remain typed and non-authoritative
- Negative invariant: no second desktop event bus
- Validation status: `reviewed`

## Goida-AI-Unlocker

### sem021
**SEM021 — exact-preimage hosts transaction**

- Source: `source/app/core/hosts_manager.py` / `_verify_applied_content`
- Disposition: `adapted`
- Transformation: `adaptation`; topology `one-to-one`
- Rationale: Donor preserves original hosts bytes and verifies application; target keeps its owner but adds exact-preimage verify/rollback.
- Target capability: hosts mutation
- Target node(s): `src/packages/lumicore/src/dns/hosts_optimizer.rs#write_hosts_transaction`
- Acceptance/decision evidence: `src/packages/lumicore/src/dns/hosts_optimizer.rs#test_hosts_transaction_rolls_back_exact_preimage_on_verification_failure`
- Invariant: system hosts write is verified and rollback restores exact preimage
- Negative invariant: never synthesize a backup when an existing hosts file cannot be read
- Validation status: `statically-validated`

### sem022
**SEM022 — aggressive DNS service/process/ACL takeover**

- Source: `source/app/core/hosts_manager.py` / `_flush_dns_windows`
- Disposition: `rejected-with-reason`
- Transformation: `rejection`; topology `negative-to-guardrail`
- Rationale: Stopping services, killing processes and taking ownership broadens authority beyond the requested hosts mutation.
- Target capability: hosts mutation
- Target node(s): `n/a`
- Acceptance/decision evidence: `governance/convergence/peer-validation.md#goida-host-authority`
- Invariant: host mutation preserves unrelated service/process ownership
- Negative invariant: no service/process/ACL takeover as fallback for a file write
- Validation status: `reviewed`

### sem023
**SEM023 — small remote-main-line TTL cache**

- Source: `source/app/core/http_client.py` / `get_remote_main_line_cached`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: Useful desktop cache pattern but target provider/profile caches already own TTL semantics.
- Target capability: cache policy
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: cache TTL belongs to data owner
- Negative invariant: no generic global HTTP cache
- Validation status: `reviewed`

### sem024
**SEM024 — language normalization and fallback**

- Source: `source/app/gui/localization.py` / `normalize_language`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: Useful localization fallback reference; current control UI is not yet localized enough to justify a new runtime plane.
- Target capability: future localization
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: fallback must be deterministic and non-authoritative
- Negative invariant: no donor-specific locale state
- Validation status: `reviewed`

### sem025
**SEM025 — desktop update workflow**

- Source: `source/app/gui/main_window.py` / `check_for_updates`
- Disposition: `reference-only`
- Transformation: `reference`; topology `many-to-one`
- Rationale: One of several donor updater surfaces; target lacks signed update authority/rollback, so implementation is deferred.
- Target capability: future update plane
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: updates require signed immutable promotion and rollback
- Negative invariant: no self-update download/execute without signed authority
- Validation status: `reviewed`

### sem026
**SEM026 — retrying delete/external-open helpers**

- Source: `source/app/utils/helpers.py` / `extract_update_line`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: Operational helper patterns retained; no natural target owner requires them today.
- Target capability: operator utilities
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: side effects remain explicit and scoped
- Negative invariant: do not add utility grab-bag module
- Validation status: `reviewed`

### sem102
**SEM102 — hosts status/preview/apply/restore operator workflow**

- Source: `source/app/gui/main_window.py` / `MainWindow`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-many`
- Rationale: The preview/status workflow is useful operator evidence, but LumiNet should expose host mutation through its existing authenticated diagnostics/system surfaces rather than a second GUI authority.
- Target capability: host mutation UX reference
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: host changes remain explainable, previewable and recoverable
- Negative invariant: UI must not become hosts-file authority
- Validation status: `reviewed`

## Unlock_AI_and_EN_Services_for_Russia

### sem027
**SEM027 — labeled service-access domains**

- Source: `source/system/etc/hosts` / `hosts sections`
- Disposition: `extracted`
- Transformation: `extraction`; topology `one-to-one`
- Rationale: Stable domain taxonomy is valuable; volatile donor IP bindings are discarded and domains become routing knowledge.
- Target capability: service-access routing
- Target node(s): `src/apps/daemon/internal/networking/routing/domain_data/category-service-access.txt#chatgpt.com`
- Acceptance/decision evidence: `src/apps/daemon/internal/networking/routing/domain_domainrouting_test.go#TestServiceAccessCorpusOverridesGeographicRouting`
- Invariant: labeled service domains have explicit proxy routing intent
- Negative invariant: no donor IP pinning or hosts-file authority is imported
- Validation status: `verified`

### sem028
**SEM028 — hard-coded service destination IPs**

- Source: `source/system/etc/hosts` / `hosts IP bindings`
- Disposition: `rejected-with-reason`
- Transformation: `rejection`; topology `one-to-one`
- Rationale: Destination IPs are volatile outcomes, not stable policy, and would create brittle pinning.
- Target capability: service-access routing
- Target node(s): `n/a`
- Acceptance/decision evidence: `governance/convergence/peer-validation.md#hosts-ip-pinning`
- Invariant: routing policy stores domains/categories, not donor-resolved IP snapshots
- Negative invariant: never treat snapshot IPs as durable service authority
- Validation status: `reviewed`

### sem029
**SEM029 — 28K+ blocking domain corpus**

- Source: `source/system/etc/hosts` / `blocked hosts lines`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: Large block corpus is useful evaluation evidence but too broad/high-false-positive to become default target policy.
- Target capability: blocklist evaluation
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: blocking policy requires target-specific provenance and false-positive review
- Negative invariant: no wholesale blocklist activation from donor snapshot
- Validation status: `reviewed`

### sem030
**SEM030 — 15 unlabeled positive domains**

- Source: `source/system/etc/hosts` / `unlabeled hosts lines`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: Unlabeled positives lack semantic ownership; retained for evaluation rather than live routing.
- Target capability: routing evaluation
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: live categories require named intent
- Negative invariant: no ambiguous domains added to live policy
- Validation status: `reviewed`

### sem031
**SEM031 — Magisk/root module packaging**

- Source: `source/module.prop` / `module metadata`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: Root/Magisk deployment is not a supported LumiNet installation authority.
- Target capability: root deployment reference
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: platform packaging remains target-owned
- Negative invariant: do not introduce root-system mutation plane from packaging evidence
- Validation status: `reviewed`

## ZedPass

### sem009
**SEM009 — SSTP client/profile plane**

- Source: `lib/providers/vpn_provider.dart` / `VpnProvider`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: SSTP is a potentially useful future protocol, but adding it now would create an unverified parallel VPN transport/credential plane.
- Target capability: future SSTP
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: new transport requires target-native ownership, secure secrets, platform tests
- Negative invariant: do not import donor transport with weaker TLS defaults
- Validation status: `reviewed`

### sem010
**SEM010 — verification-off TLS defaults**

- Source: `lib/providers/vpn_provider.dart` / `VpnProvider`
- Disposition: `guardrail-derived`
- Transformation: `guardrail derivation`; topology `negative-to-guardrail`
- Rationale: Donor defaults are weaker; they reinforce LumiNet fail-closed verification and insecure-config filtering.
- Target capability: secure subscription/TLS
- Target node(s): `src/apps/daemon/internal/integrations/sub/safety.go#filterSafeProxyConfig`
- Acceptance/decision evidence: `src/apps/daemon/internal/integrations/sub/safety_test.go#TestFilterSafeProxyConfigRejectsInsecureTLSByDefault`
- Invariant: certificate verification bypass requires explicit opt-in
- Negative invariant: never silently treat insecure profile as secure
- Validation status: `verified`

### sem011
**SEM011 — credentials in ordinary preferences**

- Source: `lib/providers/vpn_provider.dart` / `VpnProvider`
- Disposition: `guardrail-derived`
- Transformation: `guardrail derivation`; topology `negative-to-guardrail`
- Rationale: Plain preference credentials are weaker than LumiNet secret refs/platform stores.
- Target capability: secret ownership
- Target node(s): `src/apps/daemon/internal/foundation/secrets/store.go#Store`
- Acceptance/decision evidence: `governance/convergence/peer-validation.md#zedpass-preference-credentials`
- Invariant: credentials are referenced from protected stores
- Negative invariant: do not persist usernames/passwords as ordinary settings state
- Validation status: `reviewed`

### sem012
**SEM012 — DNS/proxy/TLS profile editing UX**

- Source: `lib/screens/settings_screen.dart` / `_SettingsScreenState`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: Useful operator information architecture; LumiNet already owns equivalent backend settings and does not need donor Flutter state.
- Target capability: settings UX
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: UI remains projection of backend configuration
- Negative invariant: no duplicate settings authority
- Validation status: `reviewed`

## defyxVPN

### sem001
**SEM001 — OS-backed client secret storage**

- Source: `lib/core/data/local/secure_storage/secure_storage.dart` / `SecureStorage`
- Disposition: `superseded`
- Transformation: `comparison`; topology `one-to-one`
- Rationale: LumiNet backend secret references/platform stores are deeper and keep UI non-authoritative.
- Target capability: secret ownership
- Target node(s): `src/apps/daemon/internal/foundation/secrets/store.go#Store`
- Acceptance/decision evidence: `n/a`
- Invariant: secrets remain outside ordinary app state
- Negative invariant: do not persist credentials in ordinary preferences
- Validation status: `reviewed`

### sem002
**SEM002 — deliberate reveal gesture for hidden information**

- Source: `lib/modules/main/presentation/widgets/secret_tap_handler.dart` / `SecretTapHandler`
- Disposition: `inspired-native`
- Transformation: `inspiration`; topology `idea-to-native`
- Rationale: The donor demonstrates intentional disclosure; LumiNet applies the outcome to WARP private-key presentation without copying Flutter UI.
- Target capability: secret-minimized UI
- Target node(s): `src/packages/control-ui/src/pages/Settings.tsx#warpPrivateKeyVisible`
- Acceptance/decision evidence: `scripts/checks/check_host_products.py#control-ui-secret-guard`
- Invariant: private material is absent from normal plaintext presentation until deliberate reveal
- Negative invariant: no unconditional private-key DOM rendering
- Validation status: `verified`

### sem003
**SEM003 — Android VPN service lifecycle and socket bypass**

- Source: `android/app/src/main/kotlin/com/defyx/defyx/VpnService.kt` / `VpnService`
- Disposition: `adapted`
- Transformation: `adaptation`; topology `one-to-many`
- Rationale: LumiNet already owns VpnService/TUN lifecycle; donor evidence exposed the missing per-socket protect bridge.
- Target capability: Android protected dial seam
- Target node(s): `src/apps/android/app/src/main/java/com/luminet/android/VpnEngineService.kt#socketProtector`
- Acceptance/decision evidence: `scripts/checks/check_mobile_product.py#socket-protector-lifecycle`
- Invariant: Go protected dials delegate to VpnService.protect for service lifetime
- Negative invariant: no global app exclusion substitutes for the explicit protector seam
- Validation status: `statically-validated`

### sem004
**SEM004 — native connection status reconciliation**

- Source: `lib/shared/providers/connection_state_provider.dart` / `ConnectionStateNotifier`
- Disposition: `superseded`
- Transformation: `comparison`; topology `one-to-one`
- Rationale: LumiNet service/daemon state is already authoritative and UI state is derived.
- Target capability: connection state
- Target node(s): `src/apps/daemon/internal/runtime/mobilecore/controller.go#Status`
- Acceptance/decision evidence: `n/a`
- Invariant: native/runtime state remains authoritative
- Negative invariant: UI must not become VPN authority
- Validation status: `reviewed`

### sem005
**SEM005 — iOS PacketTunnel host lifecycle**

- Source: `ios/PacketTunnel/PacketTunnelProvider.swift` / `PacketTunnelProvider`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: Useful future iOS host evidence, but iOS is not a current LumiNet product surface.
- Target capability: future iOS host
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: future host must preserve TUN ownership and protected-dial seams
- Negative invariant: do not imply current iOS delivery from dormant source
- Validation status: `reviewed`

### sem006
**SEM006 — client update dialog workflow**

- Source: `lib/modules/main/presentation/widgets/update_dialog.dart` / `CustomUpdateDialog`
- Disposition: `reference-only`
- Transformation: `reference`; topology `many-to-one`
- Rationale: Useful UX reference, but self-update would create unsigned code-download authority without target promotion/rollback contract.
- Target capability: future update plane
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: updates require signed artifact authority and rollback
- Negative invariant: no donor-style self-update before signed promotion contract
- Validation status: `reviewed`

### sem007
**SEM007 — client speed-test presentation**

- Source: `lib/modules/main/presentation/widgets/speed_test.dart` / `SpeedTestWidget`
- Disposition: `superseded`
- Transformation: `comparison`; topology `one-to-one`
- Rationale: LumiNet already has speedtest API and qualification workflow.
- Target capability: speed diagnostics
- Target node(s): `src/apps/daemon/internal/adapters/api/handlers_speedtest.go#RunSpeedtest`
- Acceptance/decision evidence: `n/a`
- Invariant: speed measurement remains backend-owned
- Negative invariant: do not add duplicate client measurement authority
- Validation status: `reviewed`

### sem008
**SEM008 — operator log viewer affordances**

- Source: `lib/modules/main/presentation/widgets/logs_widget.dart` / `LogsNotifier`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: Bounded/log-access UX is useful reference; LumiNet already bounds and serves logs.
- Target capability: log UX
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: logs remain bounded and non-authoritative
- Negative invariant: no unbounded client log accumulation
- Validation status: `reviewed`

### sem103
**SEM103 — connection duration/status presentation**

- Source: `lib/modules/main/presentation/widgets/connection_button.dart` / `ConnectionButton`
- Disposition: `superseded`
- Transformation: `comparison`; topology `one-to-one`
- Rationale: LumiNet already derives live connection/session status from daemon/service truth; donor UI timing stays presentation-only reference.
- Target capability: connection UX
- Target node(s): `src/packages/control-ui/src/store/systemStore.ts#useSystemStore`
- Acceptance/decision evidence: `n/a`
- Invariant: connection duration/status is derived from authoritative runtime state
- Negative invariant: no client-side connection authority
- Validation status: `reviewed`

### sem104
**SEM104 — ad retry/error widget**

- Source: `lib/modules/main/presentation/widgets/google_ads.dart` / `_retryLoadAd`
- Disposition: `rejected-with-reason`
- Transformation: `rejection`; topology `one-to-one`
- Rationale: Advertising/monetization code is outside LumiNet product responsibility and adds unrelated tracking/network authority.
- Target capability: none
- Target node(s): `n/a`
- Acceptance/decision evidence: `governance/convergence/peer-validation.md#defyx-ads-rejected`
- Invariant: product networking remains user-requested/operational
- Negative invariant: do not absorb unrelated ad/tracking runtime
- Validation status: `reviewed`

## goida-vpn-configs

### sem032
**SEM032 — insecure TLS spelling normalization**

- Source: `source/src/parser.py` / `parse_proxy_url`
- Disposition: `adapted`
- Transformation: `adaptation`; topology `many-to-one`
- Rationale: Real feeds contain allowInsecure/insecure/skip-cert-verify spellings target parsers previously ignored.
- Target capability: proxy parsing
- Target node(s): `src/apps/daemon/internal/networking/proxyconfig/types.go#queryBool`
- Acceptance/decision evidence: `src/apps/daemon/internal/networking/proxyconfig/parser_contract_test.go#TestParseProxyURIPreservesObservedInsecureTLSAliases`
- Invariant: source insecure intent is preserved into ProxyConfig.SkipCertVerify
- Negative invariant: no insecure source is misclassified secure by alias loss
- Validation status: `verified`

### sem033
**SEM033 — HTML-escaped proxy query separators**

- Source: `githubmirror/2.txt` / `real-world &amp; links`
- Disposition: `hardened`
- Transformation: `extraction`; topology `many-to-one`
- Rationale: Corpus contains massive HTML-escaped separators; target URI ingress now normalizes only &amp; before parsing.
- Target capability: proxy parsing
- Target node(s): `src/apps/daemon/internal/networking/proxyconfig/types.go#normalizeProxyURI`
- Acceptance/decision evidence: `src/apps/daemon/internal/networking/proxyconfig/parser_contract_test.go#TestParseProxyURIHTMLAmpersandNormalization`
- Invariant: HTML presentation escaping cannot erase transport/TLS query fields
- Negative invariant: normalization must not decode arbitrary payload content
- Validation status: `verified`

### sem034
**SEM034 — insecure configuration filtering**

- Source: `source/src/parser.py` / `filter_insecure_configs`
- Disposition: `adapted`
- Transformation: `adaptation`; topology `many-to-one`
- Rationale: Donor filter outcome is retained but target policy is tied to parsed semantics and explicit opt-in.
- Target capability: secure subscription/TLS
- Target node(s): `src/apps/daemon/internal/integrations/sub/safety.go#filterSafeProxyConfig`
- Acceptance/decision evidence: `src/apps/daemon/internal/integrations/sub/safety_test.go#TestFilterSafeProxyConfigRejectsInsecureTLSByDefault`
- Invariant: verification bypass requires explicit AllowInsecureTLS
- Negative invariant: default ingestion never accepts SkipCertVerify configs
- Validation status: `verified`

### sem035
**SEM035 — two-level proxy deduplication**

- Source: `source/src/parser.py` / `deduplicate_proxies`
- Disposition: `adapted`
- Transformation: `recomposition`; topology `many-to-one`
- Rationale: Target dedupe uses complete proxy semantics instead of collapsing distinct credentials sharing host:port.
- Target capability: subscription ingestion
- Target node(s): `src/apps/daemon/internal/integrations/sub/safety.go#dedupeProxyConfigs`
- Acceptance/decision evidence: `src/apps/daemon/internal/integrations/sub/safety_test.go#TestDedupeProxyConfigsUsesFullSemantics`
- Invariant: equivalent configs collapse after aggregation
- Negative invariant: distinct credentials/config on same endpoint must survive
- Validation status: `verified`

### sem036
**SEM036 — TLS verification disabled and HTTPS downgrade retry**

- Source: `source/src/network.py` / `fetch_content`
- Disposition: `rejected-with-reason`
- Transformation: `guardrail derivation`; topology `negative-to-guardrail`
- Rationale: Donor downloader weakens transport security; target keeps HTTPS-only validated egress with bounded bodies.
- Target capability: subscription egress
- Target node(s): `src/apps/daemon/internal/integrations/sub/egress.go#Egress.Fetch`
- Acceptance/decision evidence: `governance/convergence/peer-validation.md#configs-no-tls-downgrade`
- Invariant: remote subscription fetch remains HTTPS-only and verification-on
- Negative invariant: never disable TLS verification or downgrade HTTPS to HTTP on retry
- Validation status: `reviewed`

### sem037
**SEM037 — bounded concurrent source fetching**

- Source: `source/src/network.py` / `network workers`
- Disposition: `adapted`
- Transformation: `adaptation`; topology `one-to-one`
- Rationale: Donor bounded concurrent source fetch exposed that target aggregation was serial; LumiNet now uses a four-worker owner-local resolver while preserving input order and context cancellation.
- Target capability: subscription concurrency
- Target node(s): `src/apps/daemon/internal/integrations/sub/aggregate.go#resolveInputsBounded`
- Acceptance/decision evidence: `src/apps/daemon/internal/integrations/sub/aggregate_concurrency_test.go#TestResolveInputsBoundedPreservesOrderAndCapsConcurrency`
- Invariant: subscription source fan-out is explicitly bounded and deterministic
- Negative invariant: subscription aggregation never launches unbounded per-source goroutines
- Validation status: `verified`

### sem038
**SEM038 — large multi-protocol live grammar corpus**

- Source: `githubmirror/1.txt` / `feed corpus`
- Disposition: `extracted`
- Transformation: `extraction`; topology `one-to-many`
- Rationale: Volatile endpoints/credentials are not shipped, but syntax/query shapes are retained as parser differential evidence.
- Target capability: proxy parser evaluation
- Target node(s): `governance/convergence/peer-validation.md#proxy-corpus-grammar`
- Acceptance/decision evidence: `src/apps/daemon/internal/networking/proxyconfig/parser_contract_test.go#TestParseProxyURIContract`
- Invariant: parser tests reflect observed protocol spellings/shapes
- Negative invariant: do not promote live donor endpoints or credentials to target defaults
- Validation status: `verified`

### sem039
**SEM039 — SNI/domain catalog**

- Source: `source/config/sni_domains.json` / `sni domains`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: Useful future scanner/routing evaluation corpus; not promoted without freshness and target-specific classification.
- Target capability: SNI evaluation
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: live scanner corpora require target provenance/freshness
- Negative invariant: no blind promotion of donor SNI list
- Validation status: `reviewed`

### sem040
**SEM040 — QR subscription distribution outputs**

- Source: `qr-codes/1.png` / `QR artifacts`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: Product distribution artifact reference; target already exposes config/API surfaces and need not store generated QR images.
- Target capability: QR UX reference
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: generated QR remains derived product output
- Negative invariant: no generated donor media as source of truth
- Validation status: `reviewed`

### sem041
**SEM041 — GitHub release discovery/update tooling**

- Source: `source/src/release_fetcher.py` / `fetch_latest_release_links`
- Disposition: `reference-only`
- Transformation: `reference`; topology `many-to-one`
- Rationale: Useful updater/reference mechanism but deferred until signed target upgrade authority exists.
- Target capability: future update plane
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: release discovery cannot grant execution authority
- Negative invariant: no self-update without signed immutable promotion/rollback
- Validation status: `reviewed`

### sem105
**SEM105 — source fetch error normalization**

- Source: `source/src/network.py` / `_format_fetch_error`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: Concise source-specific diagnostics are useful reference; target subscription errors already preserve source context and safer fetch policy.
- Target capability: subscription diagnostics
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: fetch failures retain source and bounded reason context
- Negative invariant: do not couple error formatting to verification-off downloader behavior
- Validation status: `reviewed`

### sem106
**SEM106 — Shadowsocks plaintext/SS2022 and final-at legacy userinfo forms**

- Source: `githubmirror/3.txt` / `ss corpus forms`
- Disposition: `adapted`
- Transformation: `adaptation`; topology `many-to-one`
- Rationale: Half-million-line differential parsing exposed standards-compatible SS forms the target rejected; target parser now handles plaintext method:password, SS2022 colon-bearing key material, base64 userinfo and legacy payloads whose password contains @.
- Target capability: proxy parsing
- Target node(s): `src/apps/daemon/internal/networking/proxyconfig/parser_ss.go#parseShadowsocks`
- Acceptance/decision evidence: `src/apps/daemon/internal/networking/proxyconfig/parser_contract_test.go#TestParseShadowsocksObservedSIP002Forms`
- Invariant: valid Shadowsocks credentials/endpoints survive real-world URI encodings without reclassifying other protocols
- Negative invariant: mis-schemed UUID/VLESS or VMess JSON must not be manufactured into Shadowsocks configs
- Validation status: `verified`

### sem107
**SEM107 — VMess boolean TLS field**

- Source: `githubmirror/1.txt` / `vmess tls corpus`
- Disposition: `hardened`
- Transformation: `hardening`; topology `one-to-one`
- Rationale: Observed VMess feeds encode tls as both strings and booleans; target now preserves either representation without weakening verification flags.
- Target capability: proxy parsing
- Target node(s): `src/apps/daemon/internal/networking/proxyconfig/parser_vmess.go#vmessTLSValue`
- Acceptance/decision evidence: `src/apps/daemon/internal/networking/proxyconfig/parser_contract_test.go#TestParseVMessAcceptsBooleanTLS`
- Invariant: VMess TLS intent survives string/bool source representations
- Negative invariant: boolean TLS must not cause otherwise valid profiles to be dropped
- Validation status: `verified`

### sem108
**SEM108 — mis-schemed VMess-as-Shadowsocks false-positive corpus**

- Source: `githubmirror/3.txt` / `ss VMess JSON rows`
- Disposition: `guardrail-derived`
- Transformation: `guardrail derivation`; topology `negative-to-guardrail`
- Rationale: Differential analysis proved 97 old SS successes were VMess JSON mislabeled ss:// and accidentally accepted because @ appeared inside decoded JSON.
- Target capability: proxy parsing
- Target node(s): `src/apps/daemon/internal/networking/proxyconfig/parser_ss.go#parseShadowsocks`
- Acceptance/decision evidence: `src/apps/daemon/internal/networking/proxyconfig/parser_contract_test.go#TestParseShadowsocksRejectsMisSchemedVMessJSON`
- Invariant: parser accepts only syntactically coherent Shadowsocks credentials/endpoints
- Negative invariant: decoded JSON or VLESS-shaped payloads cannot become SS configs through incidental delimiters
- Validation status: `verified`

### sem110
**SEM110 — mis-schemed VLESS/Reality-as-Shadowsocks negative corpus**

- Source: `githubmirror/3.txt` / `ss VLESS/Reality-shaped rows`
- Disposition: `guardrail-derived`
- Transformation: `guardrail derivation`; topology `negative-to-guardrail`
- Rationale: Differential corpus failures are mislabeled VLESS/Reality records, not missing Shadowsocks grammar. UUID identity, encryption=none, flow/Reality/WS fields make them a distinct negative parser oracle instead of a permissiveness request.
- Target capability: proxy parsing
- Target node(s): `src/apps/daemon/internal/networking/proxyconfig/parser_ss.go#parseShadowsocks;src/apps/daemon/internal/networking/proxyconfig/parser_contract_test.go#TestParseShadowsocksRejectsMisSchemedVLESS`
- Acceptance/decision evidence: `src/apps/daemon/internal/networking/proxyconfig/parser_contract_test.go#TestParseShadowsocksRejectsMisSchemedVLESS`
- Invariant: Shadowsocks parser accepts only coherent Shadowsocks credentials/endpoints
- Negative invariant: VLESS/Reality-shaped payloads cannot become Shadowsocks configs because they are mislabeled ss://
- Validation status: `verified`

## goida-vpn-site

### sem042
**SEM042 — offline cache/service worker strategy**

- Source: `source/app/static/sw.js` / `service worker cache`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: Useful public-site PWA reference; LumiNet has no public download/PWA product plane.
- Target capability: future PWA
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: offline cache must not become configuration/runtime authority
- Negative invariant: no new public PWA solely to mirror donor
- Validation status: `reviewed`

### sem043
**SEM043 — GitHub release asset discovery with TTL cache**

- Source: `source/app/services/github.py` / `fetch_download_links`
- Disposition: `reference-only`
- Transformation: `reference`; topology `many-to-one`
- Rationale: One of several updater/distribution mechanisms; retained until target has signed update authority.
- Target capability: future update plane
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: release metadata is discovery only, never execution authority
- Negative invariant: no unsigned download/execute path
- Validation status: `reviewed`

### sem044
**SEM044 — external-link confirmation affordance**

- Source: `source/app/static/js/link-confirmation.js` / `link confirmation`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: Useful browser UX pattern; current control UI exposes no equivalent external-link surface needing it.
- Target capability: external link UX
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: external navigation remains explicit
- Negative invariant: no hidden external navigation
- Validation status: `reviewed`

### sem045
**SEM045 — multi-language product translation corpus**

- Source: `source/app/static/i18n/translations.json` / `translations`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: Localization structure is useful reference but donor strings/product taxonomy do not belong in LumiNet.
- Target capability: future localization
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: translations follow target product language and key ownership
- Negative invariant: no donor text corpus as target authority
- Validation status: `reviewed`

### sem046
**SEM046 — client download/project statistics presentation**

- Source: `source/app/static/js/statistics.js` / `statistics`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: Public-site analytics UI has no target operator-plane need.
- Target capability: product analytics reference
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: analytics must be purpose-bound/non-authoritative
- Negative invariant: do not add public telemetry plane without requirement
- Validation status: `reviewed`

### sem047
**SEM047 — SEO/meta routes and templates**

- Source: `source/app/routes/seo.py` / `SEO routes`
- Disposition: `reference-only`
- Transformation: `reference`; topology `one-to-one`
- Rationale: Public marketing site behavior is outside current LumiNet application authority.
- Target capability: marketing reference
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: runtime repo does not gain a marketing-site authority
- Negative invariant: no unrelated web plane
- Validation status: `reviewed`

### sem088
**SEM088 — cross-donor updater/download plane**

- Source: `source/app/services/github.py` / `fetch_download_links`
- Disposition: `rejected-with-reason`
- Transformation: `synthesis`; topology `many-to-one`
- Rationale: defyx, Goida desktop and Goida site all expose updater/distribution UX, but target lacks signed code-download authority and rollback.
- Target capability: future update plane
- Target node(s): `n/a`
- Acceptance/decision evidence: `governance/convergence/peer-validation.md#update-plane-deferred`
- Invariant: software promotion requires signed immutable artifact, explicit approval and rollback
- Negative invariant: no donor updater plane before signed promotion contract
- Validation status: `reviewed`
