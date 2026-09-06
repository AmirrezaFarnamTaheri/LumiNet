# LumiNet post-refactor 117 historical evidence-anchor overlay

Frozen historical ledgers remain unchanged. This overlay only normalizes evidence-pointer shape so the current strict ledger schema can validate the cumulative graph without rewriting prior source artifacts.

## E8-0001-target
- Original target nodes: `src/apps/daemon/internal/foundation/remoteaction/remoteaction.go#Executor;src/apps/daemon/internal/foundation/remoteaction/remoteaction.go#waitForCooldownAndAcquire;src/apps/daemon/internal/adapters/api/handlers_system_status.go#RemoteMutationRetry`
- Target capability: automatic remote mutation retry coordinator
- Disposition: `inspired-native`

## E8-0001-test
- Original test/evidence node: `src/apps/daemon/internal/foundation/remoteaction/remoteaction_test.go#TestExecutorSharesRateLimitCooldownPerAction`
- Validation status: `verified`
- Rationale: Firewalla proves that retry policy needs memory beyond one request: a 429 for one endpoint suppresses subsequent callers without blocking unrelated endpoints. LumiNet rederives the concept around canonical action IDs, bounded secret-free state, context cancellation and existing safety classes rather than copying AGPL code.

## E8-0002-target
- Original target nodes: `src/apps/daemon/internal/foundation/remoteaction/remoteaction_test.go#TestExecutorSharesRateLimitCooldownPerAction`
- Target capability: remote mutation cooldown isolation
- Disposition: `adapted`

## E8-0002-test
- Original test/evidence node: `src/apps/daemon/internal/foundation/remoteaction/remoteaction_test.go#TestExecutorSharesRateLimitCooldownPerAction`
- Validation status: `verified`
- Rationale: The donor test demonstrates the discriminating property that one endpoint can be rate-limited while another remains available. LumiNet encodes the same target-native invariant at action granularity.

## E8-0005-target
- Original target nodes: `src/apps/daemon/internal/networking/dns/dohcache.go#fetchCoalesced`
- Target capability: DoH miss coalescing
- Disposition: `recomposed`

## E8-0005-test
- Original test/evidence node: `src/apps/daemon/internal/networking/dns/dohcache_test.go#TestDoHCacheCoalescesConcurrentMisses`
- Validation status: `verified`
- Rationale: CoreDNS prefetch testing reinforces that refresh work must be coalesced per cache key. LumiNet validates the same property for concurrent DoH misses without importing the donor prefetch subsystem.

## E8-0011-target
- Original target nodes: `src/apps/daemon/internal/networking/dns/dohcache.go#fetchCoalesced`
- Target capability: bounded DNS cache with coalesced refresh
- Disposition: `superseded`

## E8-0011-test
- Original test/evidence node: `src/apps/daemon/internal/networking/dns/dohcache_test.go#TestDoHCacheCoalescesConcurrentMisses`
- Validation status: `verified`
- Rationale: godnsagent demonstrates useful hit-driven prefetch, but CoreDNS provides stronger bounded/stale/refresh semantics and LumiNet avoids introducing a second prefetch authority until workload evidence justifies proactive refresh.

## E8-0016-target
- Original target nodes: `src/apps/daemon/internal/integrations/sub/geoip_database.go#GeoIPDatabase`
- Target capability: GeoIP rule ingestion
- Disposition: `superseded`

## E8-0016-test
- Original test/evidence node: `scripts/checks/check_eighth_order_convergence.py#main`
- Validation status: `verified`
- Rationale: The donor generator is GPL and build-oriented. LumiNet already parses bounded GeoIP data into target-owned structures; generator source is not copied. Release provenance/checksum practices are retained as evidence requirements.

## E8-0017-target
- Original target nodes: `src/apps/daemon/internal/integrations/sub/singbox_rules_list.go#SingBoxRuleGeoSite`
- Target capability: geosite rule semantics
- Disposition: `superseded`

## E8-0017-test
- Original test/evidence node: `scripts/checks/check_eighth_order_convergence.py#main`
- Validation status: `verified`
- Rationale: The donor generator is GPL and build-oriented. LumiNet retains target-owned geosite rule semantics/presets and records provenance without copying the generator.

## E8-0018-target
- Original target nodes: `src/apps/daemon/internal/platform/system/vps_warp.sh#vps_warp`
- Target capability: WARP egress bootstrap
- Disposition: `superseded`

## E8-0018-test
- Original test/evidence node: `scripts/checks/check_eighth_order_convergence.py#main`
- Validation status: `verified`
- Rationale: The donor recipe was already represented by LumiNet vps_warp.sh. Eighth-order review finds no stronger separate authority to add.

## E8-0020-target
- Original target nodes: `src/apps/daemon/internal/adapters/api/routes_system.go#setupSystemRoutes`
- Target capability: target capability and runtime truth
- Disposition: `superseded`

## E8-0020-test
- Original test/evidence node: `scripts/checks/check_eighth_order_convergence.py#main`
- Validation status: `verified`
- Rationale: AgentDNS provides a small agent registry and status surface, but LumiNet already has capability truth, jobs, diagnostics and runtime ownership; copying its Flask/database authority would fragment state.

## E8-0021-target
- Original target nodes: `src/apps/daemon/internal/analysis/scanner/scan_orchestration.go#ScanBatchOrchestrator`
- Target capability: scanner/proxy runtime
- Disposition: `superseded`

## E8-0021-test
- Original test/evidence node: `scripts/checks/check_eighth_order_convergence.py#main`
- Validation status: `verified`
- Rationale: The examples are much shallower than LumiNet scanner/proxy orchestration and have no explicit license. They add no missing invariant.

## E8-0022-target
- Original target nodes: `n/a`
- Target capability: n/a
- Disposition: `reference-only`

## E8-0022-test
- Original test/evidence node: `n/a`
- Validation status: `verified`
- Rationale: GodMode is an Electron chat product whose provider/UI model is not a natural LumiNet networking responsibility. The review retains it only as product-UX reference; no donor-shaped provider layer is introduced.

## E8-0023-target
- Original target nodes: `src/apps/daemon/internal/analysis/scanner/scan_orchestration.go#ScanBatchOrchestrator`
- Target capability: scanner planning
- Disposition: `superseded`

## E8-0023-test
- Original test/evidence node: `scripts/checks/check_eighth_order_convergence.py#main`
- Validation status: `verified`
- Rationale: Subnet splitting is already subsumed by LumiNet scan planning/orchestration with typed bounds and cancellation; the no-license shell adds no stronger primitive.

## E8-0024-target
- Original target nodes: `n/a`
- Target capability: n/a
- Disposition: `reference-only`

## E8-0024-test
- Original test/evidence node: `n/a`
- Validation status: `verified`
- Rationale: The archive is dominated by packaged configuration/binaries and GPL/third-party material. LumiNet already owns normalized proxy/subscription grammar; the corpus is retained as configuration evidence rather than imported wholesale.

## E8-0026-target
- Original target nodes: `n/a`
- Target capability: n/a
- Disposition: `reference-only`

## E8-0026-test
- Original test/evidence node: `n/a`
- Validation status: `verified`
- Rationale: The two-file donor contributes UI/workflow reference only; LumiNet already has its own control UI and configuration authority.

## E8-0028-target
- Original target nodes: `src/apps/daemon/internal/analysis/scanner/scan_orchestration.go#ScanBatchOrchestrator`
- Target capability: bounded scanner orchestration
- Disposition: `rejected-with-reason`

## E8-0028-test
- Original test/evidence node: `scripts/checks/check_eighth_order_convergence.py#main`
- Validation status: `verified`
- Rationale: The donor is a specialized FTP scanning/bounce utility and provides no target-required capability beyond LumiNet bounded scanners. Bounce/exploitation mechanics are not absorbed.

## E9-0003-target
- Original target nodes: `n/a`
- Target capability: n/a
- Disposition: `reference-only`

## E9-0003-test
- Original test/evidence node: `n/a`
- Validation status: `verified`
- Rationale: The primitive is strong but LumiNet has no concrete changed resource owner requiring cross-module reference counting. Adding a generic pool without an owner would be architecture theater. Retained as future evidence only.

## E9-0010-target
- Original target nodes: `src/apps/daemon/internal/integrations/sub/profile_entitlement.go#EvaluateProfileEntitlement;src/apps/daemon/internal/adapters/api/handlers_subscription_profiles.go#SubscriptionProfileView`
- Target capability: advisory profile entitlement
- Disposition: `synthesized`

## E9-0010-test
- Original test/evidence node: `src/apps/daemon/internal/integrations/sub/profile_entitlement_test.go#TestEvaluateProfileEntitlementWarningsAndPrecedence`
- Validation status: `verified`
- Rationale: The donor supplies useful quota/expiry operator semantics, but its user/billing database is not LumiNet authority. LumiNet synthesizes provider-reported metadata into a derived advisory entitlement view only.

## E9-0011-target
- Original target nodes: `src/apps/daemon/internal/integrations/sub/profile_entitlement.go#EvaluateProfileEntitlement;src/apps/daemon/internal/adapters/api/handlers_subscription_profiles.go#SubscriptionProfileView`
- Target capability: advisory profile entitlement
- Disposition: `synthesized`

## E9-0011-test
- Original test/evidence node: `src/apps/daemon/internal/integrations/sub/profile_entitlement_test.go#TestEvaluateProfileEntitlementWarningsAndPrecedence`
- Validation status: `verified`
- Rationale: The donor supplies useful quota/expiry operator semantics, but its user/billing database is not LumiNet authority. LumiNet synthesizes provider-reported metadata into a derived advisory entitlement view only.

## E9-0012-target
- Original target nodes: `src/apps/daemon/internal/integrations/sub/profile_entitlement.go#EvaluateProfileEntitlement;src/apps/daemon/internal/adapters/api/handlers_subscription_profiles.go#SubscriptionProfileView`
- Target capability: advisory profile entitlement
- Disposition: `synthesized`

## E9-0012-test
- Original test/evidence node: `src/apps/daemon/internal/integrations/sub/profile_entitlement_test.go#TestEvaluateProfileEntitlementWarningsAndPrecedence`
- Validation status: `verified`
- Rationale: The donor supplies useful quota/expiry operator semantics, but its user/billing database is not LumiNet authority. LumiNet synthesizes provider-reported metadata into a derived advisory entitlement view only.

## E9-0013-target
- Original target nodes: `src/apps/daemon/internal/integrations/sub/profile_entitlement.go#EvaluateProfileEntitlement;src/apps/daemon/internal/adapters/api/handlers_subscription_profiles.go#SubscriptionProfileView`
- Target capability: advisory profile entitlement
- Disposition: `synthesized`

## E9-0013-test
- Original test/evidence node: `src/apps/daemon/internal/integrations/sub/profile_entitlement_test.go#TestEvaluateProfileEntitlementWarningsAndPrecedence`
- Validation status: `verified`
- Rationale: The donor supplies useful quota/expiry operator semantics, but its user/billing database is not LumiNet authority. LumiNet synthesizes provider-reported metadata into a derived advisory entitlement view only.

## E9-0014-target
- Original target nodes: `src/apps/daemon/internal/integrations/sub/profile_entitlement.go#ProfileEntitlement`
- Target capability: profile evidence boundary
- Disposition: `rejected-with-reason`

## E9-0014-test
- Original test/evidence node: `scripts/checks/check_ninth_order_convergence.py#main`
- Validation status: `verified`
- Rationale: LumiNet is not adopting a donor commerce ledger or wallet authority. Only non-authoritative entitlement evidence is useful to the target.

## E9-0015-target
- Original target nodes: `src/apps/daemon/internal/integrations/sub/profile_entitlement.go#ProfileEntitlement`
- Target capability: profile evidence boundary
- Disposition: `rejected-with-reason`

## E9-0015-test
- Original test/evidence node: `scripts/checks/check_ninth_order_convergence.py#main`
- Validation status: `verified`
- Rationale: Marzban usage accounting is a server/billing responsibility and AGPL code. LumiNet does not import its metering authority; only already-reported provider metadata is surfaced.

## E9-0016-target
- Original target nodes: `src/apps/daemon/internal/integrations/sub/profile_entitlement.go#ProfileEntitlement`
- Target capability: profile evidence boundary
- Disposition: `rejected-with-reason`

## E9-0016-test
- Original test/evidence node: `scripts/checks/check_ninth_order_convergence.py#main`
- Validation status: `verified`
- Rationale: The no-license worker has valuable product feedback but would duplicate identity/quota authority. LumiNet absorbs only advisory status semantics into profiles.

## E9-0017-target
- Original target nodes: `n/a`
- Target capability: n/a
- Disposition: `reference-only`

## E9-0017-test
- Original test/evidence node: `n/a`
- Validation status: `verified`
- Rationale: Offline bundle preparation is useful operational evidence, but the no-license installer and product stack are not target runtime dependencies. Retained as packaging/runbook reference for a future explicit offline release requirement.

## E9-0018-target
- Original target nodes: `src/apps/daemon/internal/platform/system/tor_controller.go#SignalNewNym`
- Target capability: Tor control ownership
- Disposition: `superseded`

## E9-0018-test
- Original test/evidence node: `src/apps/daemon/internal/platform/system/tor_controller_newnym_test.go#TestSignalNewNymSendsBoundedControlCommand`
- Validation status: `verified`
- Rationale: This archive is byte-identical to the sixth-order donor already reviewed. LumiNet has a stronger long-lived Tor owner with SAFECOOKIE authentication and bounded NEWNYM signaling; no repeated unauthenticated helper is needed.

## E9-0019-target
- Original target nodes: `src/apps/daemon/internal/runtime/runtimecore/tor_engine.go#rotateIdentity`
- Target capability: Tor runtime
- Disposition: `superseded`

## E9-0019-test
- Original test/evidence node: `src/apps/daemon/internal/platform/system/tor_controller_newnym_test.go#TestSignalNewNymSendsBoundedControlCommand`
- Validation status: `verified`
- Rationale: The thin MIT wrapper is shallower than LumiNet's Tor process/controller/engine ownership and adds no missing target primitive.

## E9-0021-target
- Original target nodes: `n/a`
- Target capability: n/a
- Disposition: `reference-only`

## E9-0021-test
- Original test/evidence node: `n/a`
- Validation status: `verified`
- Rationale: No-license presets are retained as revision evidence only; LumiNet already owns normalized config export/import and cannot treat donor templates as authoritative.

## E9-0023-target
- Original target nodes: `n/a`
- Target capability: n/a
- Disposition: `reference-only`

## E9-0023-test
- Original test/evidence node: `n/a`
- Validation status: `verified`
- Rationale: TTL tracking is a potentially useful future mechanism but no ninth-order target requirement needs a new per-flow packet table. Retained as evidence without adding state.

## E9-0026-target
- Original target nodes: `n/a`
- Target capability: n/a
- Disposition: `reference-only`

## E9-0026-test
- Original test/evidence node: `n/a`
- Validation status: `verified`
- Rationale: GPL preset composition was reviewed against LumiNet serverless/DNS/evasion owners. The exact config is not copied; the underlying primitives already exist and no superior target preset is established by source inspection alone.

## E9-0027-target
- Original target nodes: `n/a`
- Target capability: n/a
- Disposition: `reference-only`

## E9-0027-test
- Original test/evidence node: `n/a`
- Validation status: `verified`
- Rationale: The MIT implementation is a useful future identity pattern, but LumiNet currently has no OAuth product requirement. Adding an OAuth authority without a concrete provider/session design would expand attack surface.

## E9-0028-target
- Original target nodes: `n/a`
- Target capability: n/a
- Disposition: `reference-only`

## E9-0028-test
- Original test/evidence node: `n/a`
- Validation status: `verified`
- Rationale: The no-license lab is useful as a model for isolated censorship-transport integration testing, but its privileged container/sudo/VNC assumptions should not be imported. Retained as test-lab reference only.

## E9-0029-target
- Original target nodes: `n/a`
- Target capability: n/a
- Disposition: `reference-only`

## E9-0029-test
- Original test/evidence node: `n/a`
- Validation status: `verified`
- Rationale: The two-file donor is descriptive ecosystem knowledge rather than implementation. It is retained as compatibility/reference evidence; no external-client list becomes runtime truth.

## E9-0030-target
- Original target nodes: `n/a`
- Target capability: n/a
- Disposition: `reference-only`

## E9-0030-test
- Original test/evidence node: `n/a`
- Validation status: `verified`
- Rationale: The descriptive no-license repository contributes UX/compatibility reference. LumiNet already owns routing/profile/import/evasion mechanisms and does not manufacture an implementation from marketing claims.

## E9-0031-target
- Original target nodes: `deploy/server-bootstrap/x-ui-pro.sh#x_ui_pro`
- Target capability: deployment safety guardrail
- Disposition: `guardrail-derived`

## E9-0031-test
- Original test/evidence node: `scripts/checks/check_ninth_order_convergence.py#main`
- Validation status: `verified`
- Rationale: The no-license installer performs broad irreversible/root mutations and remote script execution. LumiNet's existing x-ui-pro file is only a placeholder; ninth-order evidence records that honestly rather than claiming a port. Any future bootstrap must use explicit preflight, pinned inputs, snapshot/rollback and bounded authority.

## FP-S001-target
- Original target nodes: `src/apps/daemon/internal/foundation/remoteaction/remoteaction.go#Policy;src/apps/daemon/internal/foundation/remoteaction/remoteaction.go#waitForCooldownAndAcquire;src/apps/daemon/internal/integrations/provision/cloudflare.go;src/apps/daemon/internal/analysis/scanner/cloudflare_deployer.go;src/apps/daemon/internal/runtime/proxy/google_drive_actions.go;src/apps/daemon/internal/runtime/warp/warp.go;src/apps/daemon/internal/networking/dns/ddns_updater.go`
- Target capability: provider-scoped automatic mutation retry coordinator
- Disposition: `inspired-native`

## FP-S001-test
- Original test/evidence node: `src/apps/daemon/internal/foundation/remoteaction/remoteaction_test.go#TestExecutorSharesCooldownAcrossActionsInSameProviderScope`
- Validation status: `verified`
- Rationale: The earlier LumiNet convergence remembered 429 cooldown by action. Final cross-wave comparison shows provider quotas can span several mutation endpoints, so action-only memory still permits cross-action quota hammering. LumiNet independently generalizes the AGPL evidence into an explicit secret-free RateLimitScope shared only by mutations that declare a common provider quota boundary.

## FP-S004-target
- Original target nodes: `src/apps/daemon/internal/foundation/config/config.go#SaveIfRevision;src/apps/daemon/internal/foundation/config/config.go#GetWithRevision;src/apps/daemon/internal/adapters/api/config_mutation.go#commitConfigSnapshot;src/apps/daemon/internal/adapters/api/config_mutation.go#expectedConfigRevision;src/apps/daemon/internal/adapters/api/handlers_system_startup.go;src/apps/daemon/internal/adapters/api/handlers_system_ddns.go;src/apps/daemon/internal/adapters/api/handlers_proxy_directory.go`
- Target capability: canonical live configuration CAS
- Disposition: `adapted`

## FP-S004-test
- Original test/evidence node: `src/apps/daemon/internal/foundation/config/revision_test.go#TestSaveIfRevisionRejectsStaleWriterWithoutLosingNewerState;src/apps/daemon/internal/adapters/api/config_mutation_test.go#TestParseConfigRevisionETag;src/apps/daemon/internal/adapters/api/config_mutation_test.go#TestConfigRevisionConflictStatus`
- Validation status: `verified`
- Rationale: Ninth-order implemented Caddy-like conditional mutation inside a dormant compatibility ConfigManager. The final pass promotes the invariant into LumiNet foundation/config.Manager, the actual durable settings authority, and a shared API adapter used by settings, DDNS and proxy-directory mutations. Caddy remains evidence; the live owner is no longer donor-shaped.

## FP-S007-target
- Original target nodes: `src/apps/daemon/internal/networking/dns/dnsproxy.go#RateLimiter;src/apps/daemon/internal/networking/dns/dnsproxy.go#PendingRequests;src/apps/daemon/internal/networking/dns/dohcache.go#fetchCoalesced`
- Target capability: bounded DNS admission and duplicate suppression
- Disposition: `superseded`

## FP-S007-test
- Original test/evidence node: `n/a`
- Validation status: `reviewed`
- Rationale: CoreDNS shed is a strong UDP-specific fail-fast primitive, but LumiNet current DNS paths already bound callers with per-client RateLimiter, PendingRequests duplicate suppression and DoH refresh coalescing/cache bounds. Importing a second shed owner would duplicate admission semantics without evidence of an uncovered fdMutex-style bottleneck in the current path.

## U-S009-target
- Original target nodes: `src/apps/daemon/internal/runtime/runtimecore/manager.go#Manager;src/apps/daemon/internal/platform/system/host_network.go`
- Target capability: runtime lifecycle guardrail
- Disposition: `guardrail-derived`

## U-S009-test
- Original test/evidence node: `scripts/checks/check_runtime_core_ownership.py`
- Validation status: `reviewed`
- Rationale: The scripts illustrate kill-on-disconnect intent but use broad process control and shell loops. LumiNet retains the invariant, not the scripts: lifecycle mutation remains with typed runtime/host-network owners.

## U-S014-target
- Original target nodes: `src/apps/daemon/internal/platform/system/host_network.go#ApplyHostNetwork`
- Target capability: host network authority
- Disposition: `rejected-with-reason`

## U-S014-test
- Original test/evidence node: `scripts/checks/check_host_network_ownership.py`
- Validation status: `reviewed`
- Rationale: GPL kernel/iptables randomization would introduce another privileged host-network authority. LumiNet retains one snapshot/verify/recover/rollback host-network owner instead.

## U-S015-target
- Original target nodes: `src/apps/daemon/internal/runtime/runtimecore/manager.go#EngineTor`
- Target capability: Tor client/server role boundary
- Disposition: `rejected-with-reason`

## U-S015-test
- Original test/evidence node: `scripts/checks/check_runtime_core_ownership.py`
- Validation status: `reviewed`
- Rationale: Relay bootstrap, firewall and unattended-upgrade recipes are server operations with broad root authority. LumiNet remains a client runtime and does not absorb relay mutation scripts.

## U-S016-target
- Original target nodes: `src/apps/daemon/internal/runtime/runtimecore/manager.go#EngineTor`
- Target capability: Tor client/server role boundary
- Disposition: `rejected-with-reason`

## U-S016-test
- Original test/evidence node: `scripts/checks/check_runtime_core_ownership.py`
- Validation status: `reviewed`
- Rationale: No-license root install/relay script duplicates the same wrong product role and irreversible host mutation surface; retained as negative evidence only.

## U-S021-target
- Original target nodes: `src/apps/daemon/internal/platform/system/host_network.go#ApplyHostNetwork`
- Target capability: host network authority
- Disposition: `rejected-with-reason`

## U-S021-test
- Original test/evidence node: `scripts/checks/check_host_network_ownership.py`
- Validation status: `reviewed`
- Rationale: No-license Docker/UFW gateway setup broadens host firewall authority without LumiNet snapshot/rollback semantics. Existing LAN gateway/proxy owners remain authoritative.

## PR83-S004-target
- Original target nodes: `src/apps/daemon/internal/runtime/proxy/wstunnel.go`
- Target capability: transport TLS trust
- Disposition: `rejected-with-reason`

## PR83-S004-test
- Original test/evidence node: `src/apps/daemon/internal/runtime/proxy/wstunnel_test.go#TestStunnelRejectsUntrustedCertificateWithoutPin`
- Validation status: `verified`
- Rationale: Installing/generated MITM trust would enlarge LumiNet authority and contradict its strict PKI-or-explicit-pin transport model.

## PR83-S005-target
- Original target nodes: `src/apps/daemon/internal/runtime/proxy/evasion_tunnel.go`
- Target capability: evasion plane
- Disposition: `superseded`

## PR83-S005-test
- Original test/evidence node: `n/a`
- Validation status: `reviewed`
- Rationale: LumiNet already owns fragmentation/evasion in its established proxy/evasion plane; donor packaging would duplicate authority and has no explicit license.

## PR83-S006-target
- Original target nodes: `src/apps/daemon/internal/runtime/runtimecore/manager.go;src/apps/daemon/internal/platform/system/process_supervisor.go`
- Target capability: runtime engine supervision
- Disposition: `superseded`

## PR83-S006-test
- Original test/evidence node: `src/apps/daemon/internal/runtime/runtimecore/manager_test.go#TestManagerRestoresPreviousConfigurationWhenReplacementStartFails`
- Validation status: `verified`
- Rationale: Existing runtimecore and process supervisor provide target-native lifecycle ownership and rollback; another process manager would split authority.

## PR83-S007-target
- Original target nodes: `src/apps/daemon/internal/runtime/warp/warp_scanner.go;src/apps/daemon/internal/runtime/proxy/node_latency_tester.go#EndpointQualityResult`
- Target capability: endpoint quality
- Disposition: `superseded`

## PR83-S007-test
- Original test/evidence node: `src/apps/daemon/internal/runtime/warp/warp_scanner_test.go`
- Validation status: `verified`
- Rationale: Two-stage qualification is sound, but LumiNet already uses bounded repeated handshake/quality sampling with loss, median RTT, jitter and strict concurrency/candidate caps.

## PR83-S008-target
- Original target nodes: `src/apps/daemon/internal/analysis/scanner/probe_pipeline_utils.go`
- Target capability: diagnostic TLS evidence
- Disposition: `guardrail-derived`

## PR83-S008-test
- Original test/evidence node: `scripts/checks/check_post_refactor_83_convergence.py`
- Validation status: `statically-validated`
- Rationale: Scanner reachability evidence must not become transport trust. LumiNet records TLS evidence separately and keeps live transports verified.

## PR83-S009-target
- Original target nodes: `src/apps/daemon/internal/runtime/proxy/node_latency_tester.go#EndpointQualityResult`
- Target capability: endpoint quality
- Disposition: `superseded`

## PR83-S009-test
- Original test/evidence node: `n/a`
- Validation status: `reviewed`
- Rationale: A single ping is weaker than LumiNet loss-aware multi-sample median/jitter scoring and can select flaky endpoints.

## PR83-S010-target
- Original target nodes: `src/apps/daemon/internal/runtime/proxy/kcp_transport.go`
- Target capability: KCP multiplexing
- Disposition: `reference-only`

## PR83-S010-test
- Original test/evidence node: `n/a`
- Validation status: `reviewed`
- Rationale: Fair per-stream scheduling is valuable and may improve KCP multiplexing, but replacing xtaci/smux with a fork requires protocol-compatibility and measured differential evidence. No dependency swap is justified in this pass.

## PR83-S011-target
- Original target nodes: `src/apps/daemon/internal/runtime/proxy/kcp_transport.go`
- Target capability: KCP multiplexing
- Disposition: `reference-only`

## PR83-S011-test
- Original test/evidence node: `n/a`
- Validation status: `reviewed`
- Rationale: The donor makes bounds explicit. LumiNet currently relies on the pinned xtaci/smux implementation/defaults; a future upgrade must verify equivalent bounds rather than copying fork internals.

## PR83-S014-target
- Original target nodes: `src/apps/daemon/internal/adapters/api/handlers_tor_ops.go;src/apps/daemon/internal/platform/system/tor_controller.go`
- Target capability: Tor diagnostics
- Disposition: `reference-only`

## PR83-S014-test
- Original test/evidence node: `n/a`
- Validation status: `reviewed`
- Rationale: OnionPerf provides mature measurement vocabulary (bootstrap, transfer error, circuit path/build timing) that is valuable for future Tor diagnostics, but it is a measurement framework rather than a runtime owner.

## PR83-S015-target
- Original target nodes: `governance/convergence/post-refactor-83-peer-synthesis.md`
- Target capability: privacy evaluation reference
- Disposition: `reference-only`

## PR83-S015-test
- Original test/evidence node: `n/a`
- Validation status: `reviewed`
- Rationale: This is offline privacy-research methodology useful for evaluation design, not production routing. No live trace-retention/fingerprinting plane is justified.

## PR83-S016-target
- Original target nodes: `src/apps/daemon/internal/runtime/runtimecore/tor_engine.go`
- Target capability: Tor runtime
- Disposition: `guardrail-derived`

## PR83-S016-test
- Original test/evidence node: `scripts/checks/check_post_refactor_83_convergence.py`
- Validation status: `statically-validated`
- Rationale: The donor itself documents memory cost and increased compromised-circuit probability. LumiNet retains one supervised Tor engine plus circuit rotation/bridges rather than multiplying processes.

## PR83-S017-target
- Original target nodes: `src/apps/daemon/internal/runtime/proxy/evasion_tunnel_dial.go`
- Target capability: DNS covert-transport guardrail
- Disposition: `guardrail-derived`

## PR83-S017-test
- Original test/evidence node: `n/a`
- Validation status: `reviewed`
- Rationale: LumiNet does not currently ship a production DNS tunnel and truthfully reports that mode unavailable. The donor demonstrates fragmentation/reassembly ideas, but GPL packaging and raw-socket/spoofing authority are incompatible; retain the requirement that any future implementation be bounded and target-native.

## PR83-S018-target
- Original target nodes: `src/apps/daemon/internal/platform/system/host_network.go#HostNetworkChange`
- Target capability: host network authority
- Disposition: `rejected-with-reason`

## PR83-S018-test
- Original test/evidence node: `scripts/checks/check_host_network_ownership.py`
- Validation status: `verified`
- Rationale: Raw spoofing is not needed for LumiNet client functionality and would bypass host-network ownership and safety limits.

## PR83-S019-target
- Original target nodes: `src/apps/daemon/internal/runtime/proxy/wstunnel.go`
- Target capability: transport trust
- Disposition: `rejected-with-reason`

## PR83-S019-test
- Original test/evidence node: `src/apps/daemon/internal/runtime/proxy/wstunnel_test.go#TestStunnelRejectsUntrustedCertificateWithoutPin`
- Validation status: `verified`
- Rationale: Interception and locally trusted forged identities conflict with LumiNet strict transport trust; domain-fronting ideas do not require MITM authority.

## PR83-S020-target
- Original target nodes: `governance/convergence/post-refactor-83-peer-synthesis.md`
- Target capability: security audit reference
- Disposition: `reference-only`

## PR83-S020-test
- Original test/evidence node: `n/a`
- Validation status: `reviewed`
- Rationale: Attack catalog is retained only to inform defensive trust-boundary audits; no offensive workflow is introduced.

## PR83-S021-target
- Original target nodes: `governance/convergence/post-refactor-83-peer-synthesis.md`
- Target capability: security guardrails
- Disposition: `rejected-with-reason`

## PR83-S021-test
- Original test/evidence node: `n/a`
- Validation status: `reviewed`
- Rationale: These behaviors are malicious and have no legitimate target role in LumiNet. The repository contributes only a prohibition/negative-evidence record.

## PR83-S022-target
- Original target nodes: `src/packages/lumicore/src/crypto/mod.rs`
- Target capability: cryptographic policy
- Disposition: `rejected-with-reason`

## PR83-S022-test
- Original test/evidence node: `n/a`
- Validation status: `reviewed`
- Rationale: Custom GPL cryptography and quantum-security claims do not justify replacing standard vetted primitives. The implementation also uses unsafe hot-path pointer operations and must not be imported as a security primitive.

## PR83-S023-target
- Original target nodes: `src/apps/daemon/internal/integrations/sub/aggregate.go#AggregateSubscriptions`
- Target capability: subscription ingestion
- Disposition: `superseded`

## PR83-S023-test
- Original test/evidence node: `n/a`
- Validation status: `reviewed`
- Rationale: LumiNet already has stricter SSRF-aware egress, bounded bodies and mature subscription parsers. Donor has no explicit license and provides no stronger admission invariant.

## PR83-S024-target
- Original target nodes: `governance/convergence/post-refactor-83-peer-synthesis.md`
- Target capability: deployment reference
- Disposition: `reference-only`

## PR83-S024-test
- Original test/evidence node: `n/a`
- Validation status: `reviewed`
- Rationale: Inbound reverse proxy provisioning is a different product role and the installer performs broad host mutation. It is retained as operational evidence, not runtime authority.

## PR83-S025-target
- Original target nodes: `governance/convergence/post-refactor-83-nested-archives.csv`
- Target capability: provenance
- Disposition: `reference-only`

## PR83-S025-test
- Original test/evidence node: `n/a`
- Validation status: `verified`
- Rationale: All three embedded ZIPs hash-identically match prior bldfrm-vpn, mullvad-closest and tor_box uploads; they are revalidated, not double-counted as new semantics.

## PR83-S026-target
- Original target nodes: `governance/convergence/post-refactor-83-peer-synthesis.md`
- Target capability: deployment reference
- Disposition: `reference-only`

## PR83-S026-test
- Original test/evidence node: `n/a`
- Validation status: `reviewed`
- Rationale: Operational recipes are useful reference but broad privileged installation belongs outside LumiNet runtime authority and lacks explicit license.

## PR83-S027-target
- Original target nodes: `src/apps/daemon/internal/platform/system/host_network.go#HostNetworkChange`
- Target capability: host network authority
- Disposition: `rejected-with-reason`

## PR83-S027-test
- Original test/evidence node: `scripts/checks/check_host_network_ownership.py`
- Validation status: `verified`
- Rationale: Rules are useful conflict evidence but would create a second raw firewall authority. LumiNet requires host-network mutations to participate in snapshot/verify/recover/rollback.

## PR83-S028-target
- Original target nodes: `governance/convergence/post-refactor-83-nested-archives.csv`
- Target capability: historical provenance
- Disposition: `reference-only`

## PR83-S028-test
- Original test/evidence node: `n/a`
- Validation status: `verified`
- Rationale: Archive SHA-256 exactly matches previously reviewed nahan-main(1); no semantic delta exists.

## PR83-S029-target
- Original target nodes: `n/a`
- Target capability: n/a
- Disposition: `rejected-with-reason`

## PR83-S029-test
- Original test/evidence node: `n/a`
- Validation status: `reviewed`
- Rationale: Despite the name, this repository is a game-data API client and has no networking/proxy semantic fit for LumiNet.

## PR83-S030-target
- Original target nodes: `src/apps/daemon/internal/foundation/remoteaction/remoteaction.go#Executor;src/apps/daemon/internal/adapters/api/middleware.go`
- Target capability: edge resource guardrails
- Disposition: `reference-only`

## PR83-S030-test
- Original test/evidence node: `n/a`
- Validation status: `reviewed`
- Rationale: The worker demonstrates useful resource bounds and multi-user edge concerns, but LumiNet already owns authentication/capability policy and bounded remote/network actions; importing the worker would duplicate product authority.

## PR97-S006-target
- Original target nodes: `src/apps/daemon/internal/platform/system/tor_controller_protocol_test.go`
- Target capability: Tor control protocol tests
- Disposition: `extracted`

## PR97-S006-test
- Original test/evidence node: `src/apps/daemon/internal/platform/system/tor_controller_protocol_test.go#TestTorControllerBoundsWholeReply`
- Validation status: `verified`
- Rationale: The donor tests continuation and event framing; equivalent target-native negative cases now exercise bounded total replies, timeouts, data blocks and event-before-reply behavior.

## PR97-S008-target
- Original target nodes: `src/apps/daemon/internal/platform/system/tor_controller.go#SignalNewNym`
- Target capability: Tor identity rotation
- Disposition: `superseded`

## PR97-S008-test
- Original test/evidence node: `src/apps/daemon/internal/platform/system/tor_controller_newnym_test.go#TestSignalNewNymSendsBoundedControlCommand`
- Validation status: `verified`
- Rationale: Global Tor restarts expand blast radius and lose process continuity. LumiNet already owns authenticated SIGNAL NEWNYM through the canonical controller, so restart-based identity rotation is rejected.

## PR97-S009-target
- Original target nodes: `governance/convergence/post-refactor-97-omission-audit.md`
- Target capability: installation/archive trust guardrail
- Disposition: `rejected-with-reason`

## PR97-S009-test
- Original test/evidence node: `scripts/checks/check_post_refactor_97_convergence.py#semantic-PR97-S009`
- Validation status: `reviewed`
- Rationale: The donor mixes environment mutation with permissive extraction. LumiNet keeps archive path/type validation and pinned provisioning; this mechanism is not imported.

## PR97-S010-target
- Original target nodes: `src/apps/daemon/internal/platform/system`
- Target capability: host network authority
- Disposition: `guardrail-derived`

## PR97-S010-test
- Original test/evidence node: `scripts/checks/check_post_refactor_97_convergence.py#semantic-PR97-S010`
- Validation status: `reviewed`
- Rationale: Leak-prevention intent is useful, but importing direct iptables commands would create a second privileged network authority outside LumiNet HostNetworkChange ownership. Final disposition is no direct import.

## PR97-S011-target
- Original target nodes: `src/apps/daemon/internal/runtime/runtimecore/tor_engine.go`
- Target capability: Tor transport semantics
- Disposition: `reference-only`

## PR97-S011-test
- Original test/evidence node: `scripts/checks/check_post_refactor_97_convergence.py#semantic-PR97-S011`
- Validation status: `reviewed`
- Rationale: The configuration demonstrates transparent TCP and DNS patterns, but LumiNet currently owns traffic via explicit proxy/TUN seams and does not gain a second transparent-routing authority from this donor.

## PR97-S012-target
- Original target nodes: `src/apps/daemon/internal/platform/system`
- Target capability: Tor traffic admission guardrail
- Disposition: `guardrail-derived`

## PR97-S012-test
- Original test/evidence node: `scripts/checks/check_post_refactor_97_convergence.py#semantic-PR97-S012`
- Validation status: `reviewed`
- Rationale: The donor treats unsupported Internet traffic as a leak risk instead of silently bypassing Tor. This is retained as a TUN/proxy admission invariant, not as an LD_PRELOAD implementation.

## PR97-S013-target
- Original target nodes: `src/apps/daemon/internal/platform/system`
- Target capability: Tor interception boundary
- Disposition: `rejected-with-reason`

## PR97-S013-test
- Original test/evidence node: `scripts/checks/check_post_refactor_97_convergence.py#semantic-PR97-S013`
- Validation status: `reviewed`
- Rationale: Application interposition cannot establish whole-device VPN authority because bypass paths exist below the hook layer. LumiNet therefore retains kernel/TUN-owned routing rather than importing torsocks as the primary tunnel.

## PR97-S014-target
- Original target nodes: `src/apps/daemon/internal/platform/system`
- Target capability: TUN traffic classification
- Disposition: `guardrail-derived`

## PR97-S014-test
- Original test/evidence node: `scripts/checks/check_post_refactor_97_convergence.py#semantic-PR97-S014`
- Validation status: `reviewed`
- Rationale: The donor explicitly separates DNS datagrams from TCP stream forwarding. LumiNet keeps this as a traffic-class invariant under its existing TUN/proxy owners instead of importing a second userspace TCP stack.
