# Eighth-order donor-by-donor peer synthesis

This report is a semantic synthesis companion to the exhaustive CSV matrices. A donor with few adopted values was still fully inventoried; low adoption is a decision result, not evidence of shallow inspection.

## AgentDNS-main

- Archive SHA-256: `add33e8ac55099939a21258081c4beb9d6b2859f0cbef000cdabf71dcf15c608`
- Members / surfaces / directories / parsed symbols: 16 / 13 / 3 / 26
- License posture: no explicit LICENSE in archive; README claims MIT, treated as unverified/no-license for source reuse
- **E8-0020 — agent registry/discovery/status API** → `superseded`. AgentDNS provides a small agent registry and status surface, but LumiNet already has capability truth, jobs, diagnostics and runtime ownership; copying its Flask/database authority would fragment state. Target: target capability and runtime truth. Validation: `statically-validated` via `scripts/checks/check_eighth_order_convergence.py#main`.

## DNS-Persist-master

- Archive SHA-256: `0396f84ecbd482d9e84ca7b9862513fdf5475740dfb7854e4cbebf2adedb0778`
- Members / surfaces / directories / parsed symbols: 35 / 30 / 5 / 69
- License posture: MIT
- **E8-0027 — DNS command-and-control/persistence transport** → `rejected-with-reason`. The repository is a persistence/C2 implementation. Porting command execution or stealth persistence would create offensive capability unrelated to LumiNet convergence. Only the bounded DNS-tunnel planning/transport guards already present in LumiNet are retained; no C2/persistence control path is imported. Target: bounded DNS tunnel planning without donor C2 authority. Validation: `verified` via `src/apps/daemon/internal/networking/dnstunnel/plan_test.go#TestBuildPlan`.

## Go-netowrking-tools-main

- Archive SHA-256: `08c1cd69049b710afae52cffd390d7ac4a64046aaf69d08f288f30997926125d`
- Members / surfaces / directories / parsed symbols: 13 / 5 / 8 / 8
- License posture: no explicit license
- **E8-0021 — minimal port scanner/TCP proxy examples** → `superseded`. The examples are much shallower than LumiNet scanner/proxy orchestration and have no explicit license. They add no missing invariant. Target: scanner/proxy runtime. Validation: `statically-validated` via `scripts/checks/check_eighth_order_convergence.py#main`.

## GodMode-main

- Archive SHA-256: `b5dc0d8ab15ee4d702166a2ac80baa8b0cddc25b13bdaac0277f62405a94fea4`
- Members / surfaces / directories / parsed symbols: 157 / 130 / 27 / 117
- License posture: MIT
- **E8-0022 — multi-provider desktop conversation provider abstraction** → `reference-only`. GodMode is an Electron chat product whose provider/UI model is not a natural LumiNet networking responsibility. The review retains it only as product-UX reference; no donor-shaped provider layer is introduced. Target: n/a. Validation: `reviewed` via `n/a`.

## InterceptSuite-main

- Archive SHA-256: `cc1b8f5a1c2c52aa7b26730b9f265a0e3a01546024db1d2e0768f887660a75c4`
- Members / surfaces / directories / parsed symbols: 3 / 2 / 1 / 0
- License posture: no explicit license
- **E8-0029 — interception/MITM workflow concepts** → `rejected-with-reason`. The donor describes interception/MITM workflows without an explicit license. LumiNet does not import credential interception or certificate-subversion behavior. Existing diagnostic interception remains bounded to target diagnostics and TLS application paths retain explicit verification/pinning rules. Target: diagnostic-only interception boundary. Validation: `statically-validated` via `src/apps/daemon/internal/networking/proxyconfig/parser_contract_test.go#TestNormalizeRejectsLegacyInsecureTLSWithoutPin`.

## InviZible-master

- Archive SHA-256: `a4a2dbd2b99f1a618452b4f5bfb441809b39c686e0bbd6d772887f03a65573de`
- Members / surfaces / directories / parsed symbols: 1563 / 1248 / 315 / 930
- License posture: GPL-family copyleft; target uses independent target-native semantics only
- **E8-0009 — periodic actual-vs-declared module-state reconciliation and command-hash no-op avoidance** → `guardrail-derived`. InviZible repeatedly reconciles observed thread/module/firewall state and avoids needless firewall reapplication when the generated command set is unchanged. LumiNet keeps this as a cross-plane invariant: process state is supervisor-owned, host-network state is transaction-owner-observed, and mutation replay requires explicit reconciliation rather than a second generic state loop. Target: single-owner desired-state reconciliation. Validation: `verified` via `src/apps/daemon/internal/foundation/remoteaction/remoteaction_test.go#TestReconcilePreventsDuplicateReplay`.
- **E8-0010 — unique periodic work ownership with exponential backoff and resource constraints** → `superseded`. The donor validates unique periodic ownership and failure backoff. LumiNet already has a service-owned profile refresh scheduler with due-time/backoff/in-flight ownership and now a remote-action cooldown plane; Android battery/storage constraints are not applicable to the desktop/server daemon. Target: periodic refresh ownership and backoff. Validation: `verified` via `src/apps/daemon/internal/integrations/sub/profile_source_health_test.go#TestQueueDueRefreshesRespectsBackoffAndInflightOwnership`.

## Se7en-Pro-1.0.0

- Archive SHA-256: `39cd04fdc9b0c63e1c9315c47d9519e46c842bb5ee46feb4f237b26e237a0772`
- Members / surfaces / directories / parsed symbols: 199 / 143 / 27 / 78
- License posture: MIT
- **E8-0006 — stable-ready interval before restart-debt reset** → `adapted`. Se7en distinguishes merely reaching readiness from staying healthy for a meaningful interval. LumiNet adopts that invariant in the generic process supervisor, while preserving the independent rolling failure window and additionally pruning expired history at record/evaluation time. Target: stable-run process supervision. Validation: `verified` via `src/apps/daemon/internal/platform/system/process_supervisor_test.go#TestProcessSupervisorStableReadinessResetsOnlyBackoffDebt`.
- **E8-0007 — system-proxy backup/restore around tunnel lifecycle** → `superseded`. The donor reinforces snapshot-before-mutation and restoration, but LumiNet already has a stronger single host-network authority with process lock, durable route session, validation, verify, rollback and crash recovery. A donor-shaped proxy service would duplicate authority. Target: durable host-network transaction owner. Validation: `verified` via `src/apps/daemon/internal/platform/system/host_network_test.go#TestHostNetworkPlanUsesDaemonRouteSessionWithoutMutation`.
- **E8-0008 — OS-backed secret storage boundary** → `superseded`. SecretStore is a useful product-level reminder that credentials must be outside ordinary settings/log state. LumiNet already owns a secret-reference boundary and no donor-specific store is introduced. Target: target secret isolation. Validation: `statically-validated` via `src/apps/daemon/internal/foundation/remoteaction/remoteaction_test.go#TestExecutorCooldownStateIsBounded`.

## Subnet-Divider-main

- Archive SHA-256: `4821c3c767b80e3008d3c36894ee8727426ef7ff909a9fa58e8bdc08295dafb0`
- Members / surfaces / directories / parsed symbols: 3 / 2 / 1 / 3
- License posture: no explicit license
- **E8-0023 — shell subnet division and batching** → `superseded`. Subnet splitting is already subsumed by LumiNet scan planning/orchestration with typed bounds and cancellation; the no-license shell adds no stronger primitive. Target: scanner planning. Validation: `statically-validated` via `scripts/checks/check_eighth_order_convergence.py#main`.

## V2RayN-PRO-main(1)

- Archive SHA-256: `5e5e3162c6aa3d2311266d738e396a9a15e7c68a9d06fbd2217e5dfd8c65589d`
- Members / surfaces / directories / parsed symbols: 72 / 61 / 11 / 0
- License posture: GPL-family copyleft plus bundled third-party binaries/notices; target does not copy source/binaries
- **E8-0024 — large V2Ray/sing-box configuration preset corpus** → `reference-only`. The archive is dominated by packaged configuration/binaries and GPL/third-party material. LumiNet already owns normalized proxy/subscription grammar; the corpus is retained as configuration evidence rather than imported wholesale. Target: n/a. Validation: `reviewed` via `n/a`.

## V2ray-for-Doprax-main(1)

- Archive SHA-256: `9395bd68bccfd6f86c80656285061a9da863fb98f20aeca3f8ba9035eedb3f37`
- Members / surfaces / directories / parsed symbols: 11 / 9 / 2 / 0
- License posture: no explicit root license in archive
- **E8-0025 — container/supervisor V2Ray deployment recipe** → `superseded`. The deployment recipe demonstrates multi-process supervision but LumiNet owns explicit deploy templates and child supervision; donor packaging is not adopted. Target: deployment/process supervision. Validation: `verified` via `src/apps/daemon/internal/platform/system/process_supervisor_test.go#TestProcessSupervisorBackoffIncreasesAndCaps`.

## coredns-master

- Archive SHA-256: `99a1da842b6a5144590f526e7fe65835077255bc17c2f413aaefddc9c3d030f9`
- Members / surfaces / directories / parsed symbols: 1103 / 985 / 118 / 4130
- License posture: Apache-2.0
- **E8-0003 — stale-answer window with refresh coordination and transient-error precedence** → `adapted`. CoreDNS shows that stale DNS data is useful only under controlled refresh/failure semantics and that transient SERVFAIL must not shadow a valid positive answer. LumiNet applies the same resilience shape to HTTP DoH caching: successful answers only, stale-if-refresh-error, coalesced miss refresh, bounded lifetime. Target: bounded failure-aware DoH response cache. Validation: `verified` via `src/apps/daemon/internal/networking/dns/dohcache_test.go#TestDoHCacheServesStaleOnlyAfterRefreshFailure`.
- **E8-0004 — bounded cache ownership and independent expiry** → `extracted`. CoreDNS makes cache capacity a first-class policy. LumiNet replaces three unbounded DNS maps with one bounded TTL/LRU primitive that clones values at ownership boundaries and supports separate fresh/stale deadlines. Target: shared bounded DNS cache primitive. Validation: `verified` via `src/apps/daemon/internal/networking/dns/bounded_cache_test.go#TestBoundedTTLCacheEvictsLRUAndClones`.
- **E8-0005 — single-key refresh suppression test principle** → `recomposed`. CoreDNS prefetch testing reinforces that refresh work must be coalesced per cache key. LumiNet validates the same property for concurrent DoH misses without importing the donor prefetch subsystem. Target: DoH miss coalescing. Validation: `verified` via `src/apps/daemon/internal/networking/dns/dohcache_test.go#TestDoHCacheCoalescesConcurrentMisses`.

## dns-over-https-proxy-master

- Archive SHA-256: `2aa075051e81ed0daae1d3bb3db666e16a9b4e4358f5b16043caed40bcfee84f`
- Members / surfaces / directories / parsed symbols: 1294 / 1091 / 203 / 16
- License posture: Apache-2.0
- **E8-0012 — ordered DNS/DoH fallback service** → `superseded`. The donor is useful evidence for explicit fallback ordering, but LumiNet already owns UDP fallback, weighted DoH and failover resolution. Its new cache hardening is composed into those owners instead of adding another proxy daemon. Target: coherent DNS fallback/proxy plane. Validation: `verified` via `src/apps/daemon/internal/networking/dns/dns_fallback_test.go#TestDNSUDPFallbackListener`.

## firewalla-master

- Archive SHA-256: `3b2a30af746488484b4d7a0c6b335a20e268dfe07565ac7c598bbfab57083b04`
- Members / surfaces / directories / parsed symbols: 2599 / 2249 / 350 / 3542
- License posture: AGPL-3.0; target independently rederives selected semantics
- **E8-0001 — per-endpoint provider 429 cooldown remembered across independent calls** → `inspired-native`. Firewalla proves that retry policy needs memory beyond one request: a 429 for one endpoint suppresses subsequent callers without blocking unrelated endpoints. LumiNet rederives the concept around canonical action IDs, bounded secret-free state, context cancellation and existing safety classes rather than copying AGPL code. Target: automatic remote mutation retry coordinator. Validation: `verified` via `src/apps/daemon/internal/foundation/remoteaction/remoteaction_test.go#TestExecutorSharesRateLimitCooldownPerAction`.
- **E8-0002 — endpoint-isolation rate-limit test oracle** → `adapted`. The donor test demonstrates the discriminating property that one endpoint can be rate-limited while another remains available. LumiNet encodes the same target-native invariant at action granularity. Target: remote mutation cooldown isolation. Validation: `verified` via `src/apps/daemon/internal/foundation/remoteaction/remoteaction_test.go#TestExecutorSharesRateLimitCooldownPerAction`.

## ftpscan-master

- Archive SHA-256: `d6f7a61feaceb4205291070d20e4ba540af635c62afdd5e3e1970124e7fa2051`
- Members / surfaces / directories / parsed symbols: 11 / 10 / 1 / 12
- License posture: no explicit license
- **E8-0028 — FTP bounce/scanning utility** → `rejected-with-reason`. The donor is a specialized FTP scanning/bounce utility and provides no target-required capability beyond LumiNet bounded scanners. Bounce/exploitation mechanics are not absorbed. Target: bounded scanner orchestration. Validation: `statically-validated` via `scripts/checks/check_eighth_order_convergence.py#main`.

## godnsagent-master(1)

- Archive SHA-256: `ff39d81b6cb5a1dd4269526efd121691d1b4cc8d9e2635c0f767fcfd70a1ff69`
- Members / surfaces / directories / parsed symbols: 25 / 21 / 4 / 26
- License posture: MIT
- **E8-0011 — cache prefetch based on observed hits** → `superseded`. godnsagent demonstrates useful hit-driven prefetch, but CoreDNS provides stronger bounded/stale/refresh semantics and LumiNet avoids introducing a second prefetch authority until workload evidence justifies proactive refresh. Target: bounded DNS cache with coalesced refresh. Validation: `verified` via `src/apps/daemon/internal/networking/dns/dohcache_test.go#TestDoHCacheCoalescesConcurrentMisses`.

## lossyconn-master

- Archive SHA-256: `b2ed9ec6f403bed4a8bdfb2d4c7149a12b83715c4458837df9320afecec97b02`
- Members / surfaces / directories / parsed symbols: 10 / 9 / 1 / 46
- License posture: MIT
- **E8-0013 — loss/delay/jitter connection wrapper** → `superseded`. This donor was already absorbed before eighth-order convergence. The current live adapter is richer and tested, so no duplicate wrapper is added. Target: lossy network simulation. Validation: `verified` via `src/apps/daemon/internal/runtime/proxy/lossyconn_adapter_test.go#TestLossyJitterConn`.

## openssl-cffi-master

- Archive SHA-256: `99322671d546b84e1076ae304eabc1ddfd9edc600129f62beff52bbf14b4530a`
- Members / surfaces / directories / parsed symbols: 5 / 4 / 1 / 5
- License posture: Apache-2.0
- **E8-0015 — AES-ECB primitive via OpenSSL CFFI** → `superseded`. The Python CFFI wrapper is obsolete for LumiNet. The Rust core already owns a typed AES-128-ECB implementation with key/padding tests and avoids runtime CFFI/ABI coupling. Target: native crypto primitive. Validation: `reviewed` via `src/packages/lumicore/src/crypto/aes_ecb.rs#test_encrypt_decrypt_roundtrip`.

## sing-geoip-main

- Archive SHA-256: `3f7a90618be692321dada33b8ca52aa27571a157a38530d3ea063356bc8d13f7`
- Members / surfaces / directories / parsed symbols: 16 / 13 / 3 / 11
- License posture: GPL-family copyleft; target does not copy generator source
- **E8-0016 — GeoIP rule-set generation pipeline** → `superseded`. The donor generator is GPL and build-oriented. LumiNet already parses bounded GeoIP data into target-owned structures; generator source is not copied. Release provenance/checksum practices are retained as evidence requirements. Target: GeoIP rule ingestion. Validation: `statically-validated` via `scripts/checks/check_eighth_order_convergence.py#main`.

## sing-geosite-main

- Archive SHA-256: `f054fa0081b791fc0787e9dd94404c54334a5b9edc46aebae38ace01c68e6001`
- Members / surfaces / directories / parsed symbols: 16 / 13 / 3 / 14
- License posture: GPL-family copyleft; target does not copy generator source
- **E8-0017 — Geosite rule-set generation pipeline** → `superseded`. The donor generator is GPL and build-oriented. LumiNet retains target-owned geosite rule semantics/presets and records provenance without copying the generator. Target: geosite rule semantics. Validation: `statically-validated` via `scripts/checks/check_eighth_order_convergence.py#main`.

## sysproxy-main

- Archive SHA-256: `61a7ee336866edf6c019c473a74dbccf87a19929b41e3eb7b79748021e6f88db`
- Members / surfaces / directories / parsed symbols: 11 / 7 / 4 / 4
- License posture: MIT
- **E8-0014 — cross-platform system proxy mutation helper** → `superseded`. The donor provides narrow proxy mutation, but LumiNet host_network owns snapshot, lock, verification, rollback and recovery across proxy/DNS/NCSI/routes. Direct sysproxy-style mutation would be a regression in authority integrity. Target: durable host-network transaction owner. Validation: `verified` via `src/apps/daemon/internal/platform/system/host_network_test.go#TestHostNetworkPlanCapturesDNSWithoutMutationOrStateFiles`.

## unique-queue-master

- Archive SHA-256: `d2d7a3181b38df8464d37f0e17552b8347ee82d912232b08bd5f4ca08857b019`
- Members / surfaces / directories / parsed symbols: 9 / 8 / 1 / 28
- License posture: no explicit license
- **E8-0019 — deduplicating MPMC queue with append-only replay log** → `guardrail-derived`. The donor combines lock-free queueing, deduplication and AOF replay, but Enqueue logs and inserts the dedup key before it knows the bounded ring enqueue succeeded; Dequeue can also log removal failure yet delete the key. With no explicit license and partial-write hazards, LumiNet does not copy it. The lesson is to keep queue durability/idempotency atomic under one owner. Target: durable mutation/job ownership guardrail. Validation: `verified` via `src/apps/daemon/internal/foundation/remoteaction/remoteaction_test.go#TestReconcileFailureFailsClosed`.

## v2rayng-panel-main(1)

- Archive SHA-256: `fe7b75817fc8cdc62c16025affd05327c39ec086508f551b394358017a83a454`
- Members / surfaces / directories / parsed symbols: 2 / 1 / 1 / 0
- License posture: no explicit license
- **E8-0026 — V2Ray client panel workflow reference** → `reference-only`. The two-file donor contributes UI/workflow reference only; LumiNet already has its own control UI and configuration authority. Target: n/a. Validation: `reviewed` via `n/a`.

## vps-warp-main(1)

- Archive SHA-256: `4466f36e5c9084a472f55b1b3cbd6ce93dfdac39b38c9213e2e5ef29f08c044c`
- Members / surfaces / directories / parsed symbols: 4 / 3 / 1 / 7
- License posture: MIT
- **E8-0018 — WARP egress bootstrap recipe** → `superseded`. The donor recipe was already represented by LumiNet vps_warp.sh. Eighth-order review finds no stronger separate authority to add. Target: WARP egress bootstrap. Validation: `statically-validated` via `scripts/checks/check_eighth_order_convergence.py#main`.

## Cross-donor composition

- Firewalla rate-limit memory + existing LumiNet mutation safety classes become one bounded action-scoped automatic mutation retry coordinator.
- CoreDNS stale/capacity/refresh semantics + LumiNet DoH/weighted resolver owners become one bounded DNS cache primitive and failure-aware refresh contract.
- Se7en stable-ready restart logic + LumiNet rolling circuit breaker become one supervisor state machine with distinct backoff debt and failure-window debt.
- InviZible unique-work/actual-vs-desired ideas constrain existing profile scheduler, host-network transaction, supervisor and mutation reconciliation owners; they do not justify a second global reconcile loop.
- Shallower cache/proxy/deployment peers remain superseded or reference-only when a stronger target-native owner already exists.
- Offensive persistence, FTP-bounce and MITM mechanisms remain explicit safety rejections; no operational code from those paths is promoted.
