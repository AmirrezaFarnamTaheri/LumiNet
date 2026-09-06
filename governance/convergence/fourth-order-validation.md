# Fourth-order convergence validation

- Frozen third-wave baseline entries: 2393
- Historical directories: 341
- Historical surfaces: 2979
- Historical modules: 109
- Historical symbols: 7351
- High-signal symbols: 2094
- Historical semantic rechecks: 110
- New/successor adoption records: 10

### fo-001
**structural config corruption quarantine preserving forensic bytes**

- Source peer record(s): `SEM052`
- Disposition: `hardened`
- Target node(s): `src/apps/daemon/internal/foundation/config/quarantine.go#quarantineCorruptConfig;src/apps/daemon/internal/foundation/config/config.go#Load`
- Acceptance evidence: `src/apps/daemon/internal/foundation/config/quarantine_test.go#TestLoadQuarantinesStructurallyCorruptConfig`
- Invariant: structurally invalid active config bytes are preserved before any later rewrite and the caller still fails closed
- Negative invariant: never quarantine on secret-store/provider failures and never overwrite older corrupt evidence
- Status: `verified`

### fo-002
**host CPU/memory evidence as a non-amplifying concurrency ceiling**

- Source peer record(s): `SEM062`
- Disposition: `adapted`
- Target node(s): `src/apps/daemon/internal/foundation/resourcebudget/resourcebudget.go#For;src/apps/daemon/internal/foundation/resourcebudget/resourcebudget.go#CapWorkers;src/apps/daemon/internal/analysis/diagnostics/sni_spoof_scan.go#runSniSpoofScanWithProbe;src/apps/daemon/internal/integrations/sub/aggregate.go#resolveInputsBounded`
- Acceptance evidence: `src/apps/daemon/internal/foundation/resourcebudget/resourcebudget_test.go#TestCapWorkersIntersectsAllCeilings`
- Invariant: host-derived policy may only reduce concurrent work relative to subsystem ceilings
- Negative invariant: hardware detection never raises a subsystem ceiling or becomes a scheduler
- Status: `verified`

### fo-003
**bounded subscription source mirrors with static admission and per-source fallback**

- Source peer record(s): `SEM039;SEM037;SEM105`
- Disposition: `recomposed`
- Target node(s): `src/apps/daemon/internal/integrations/sub/profile_service.go#normalizeProfileMirrors;src/apps/daemon/internal/integrations/sub/profile_service.go#orderedProfileSources;src/apps/daemon/internal/integrations/sub/egress.go#ValidateProfileSourceURL;src/apps/daemon/internal/adapters/api/handlers_subscription_profiles.go#validateSubscriptionSources`
- Acceptance evidence: `src/apps/daemon/internal/integrations/sub/profile_source_health_test.go#TestProfileRefreshFallsBackToMirrorAndPrefersLastGoodSource`
- Invariant: primary source remains authoritative while mirrors are bounded alternatives with independent health and no unsafe egress
- Negative invariant: no HTTP/userinfo/non-443 source storage, no TLS downgrade, no mirror promotion into authoritative primary
- Status: `verified`

### fo-004
**last successful source preference inside authoritative ProfileService**

- Source peer record(s): `SEM063`
- Disposition: `recomposed`
- Target node(s): `src/apps/daemon/internal/integrations/sub/profile_service.go#LastSourceURL;src/apps/daemon/internal/integrations/sub/profile_service.go#orderedProfileSources`
- Acceptance evidence: `src/apps/daemon/internal/integrations/sub/profile_source_health_test.go#TestProfileRefreshFallsBackToMirrorAndPrefersLastGoodSource`
- Invariant: last-good preference is advisory ordering only and must refer to a still-configured eligible source
- Negative invariant: no duplicate last-connection file and no implicit rewrite of the primary source
- Status: `verified`

### fo-005
**signed update admission separated from download/install authority**

- Source peer record(s): `SEM006;SEM025;SEM041;SEM043;SEM088`
- Disposition: `synthesized`
- Target node(s): `src/apps/daemon/internal/foundation/updateadmission/updateadmission.go#Verifier;src/apps/daemon/internal/foundation/updateadmission/updateadmission.go#Verify;src/apps/daemon/internal/adapters/api/handlers_update_admission.go#PlanSignedUpdate`
- Acceptance evidence: `src/apps/daemon/internal/foundation/updateadmission/updateadmission_test.go#TestVerifyProducesNonAuthoritativePlan`
- Invariant: only a valid trusted signature bound to the daemon actual current version can produce a bounded non-authoritative plan
- Negative invariant: admission never downloads, installs, executes or grants apply authority; client claims cannot choose current version
- Status: `verified`

### fo-006
**read-only host-network mutation preview attached to authoritative transaction owner**

- Source peer record(s): `SEM102;SEM021`
- Disposition: `inspired-native`
- Target node(s): `src/apps/daemon/internal/platform/system/host_network.go#HostNetworkPlan;src/apps/daemon/internal/platform/system/host_network.go#PlanHostNetwork;src/apps/daemon/internal/adapters/api/handlers_host_network_plan.go#PlanHostNetwork`
- Acceptance evidence: `src/apps/daemon/internal/platform/system/host_network_test.go#TestHostNetworkPlanCapturesDNSWithoutMutationOrStateFiles`
- Invariant: preview reflects owner-observed state and requested change while remaining side-effect free
- Negative invariant: preview never acquires mutation authority, writes recovery state, or changes host DNS/proxy/NCSI/routes
- Status: `verified`

### fo-007
**automatic mutation retry only under target-owned replay-safety proof**

- Source peer record(s): `SEM055`
- Disposition: `guardrail-derived`
- Target node(s): `src/apps/daemon/internal/foundation/remoteaction/remoteaction.go#Do;governance/convergence/remote-http-actions.csv#cloudflare.dns.create`
- Acceptance evidence: `src/apps/daemon/internal/foundation/remoteaction/remoteaction_test.go#TestReconcilePreventsDuplicateReplay`
- Invariant: every automatic replay is justified by idempotency or successful owner reconciliation
- Negative invariant: generic retry never grants authority to replay non-idempotent remote creation
- Status: `verified`

### fo-008
**bounded redacted per-source failure health and backoff**

- Source peer record(s): `SEM105`
- Disposition: `hardened`
- Target node(s): `src/apps/daemon/internal/integrations/sub/profile_service.go#recordSourceFailure;src/apps/daemon/internal/integrations/sub/profile_service.go#boundedSourceError`
- Acceptance evidence: `src/apps/daemon/internal/integrations/sub/profile_source_health_test.go#TestProfileSourceHealthBackoffAndRecovery`
- Invariant: each source failure retains bounded non-secret diagnostic context and independently influences eligibility
- Negative invariant: diagnostic formatting never weakens TLS/SSRF policy or exposes full credential-bearing URLs
- Status: `verified`

### fo-009
**bounded operator log viewer now superseded by target live UI**

- Source peer record(s): `SEM008`
- Disposition: `superseded`
- Target node(s): `src/packages/control-ui/src/pages/Logs.tsx#MAX_LOG_LINES;src/packages/control-ui/src/pages/Logs.tsx#Logs`
- Acceptance evidence: `governance/convergence/peer-validation.md#sem008`
- Invariant: client log history remains bounded and non-authoritative
- Negative invariant: no duplicate donor log store or unbounded accumulation
- Status: `statically-validated`

### fo-010
**allocation-bounded line reader generalized from the donor partial-line bound**

- Source peer record(s): `SEM018`
- Disposition: `hardened`
- Target node(s): `src/apps/daemon/internal/foundation/boundedio/line.go#ReadLine;src/apps/daemon/internal/runtime/proxy/https_connect_fragmentor.go#ResponseLineReader;src/apps/daemon/internal/platform/system/tor_controller.go#readLineLocked;src/apps/daemon/internal/platform/system/control_filter.go#handleConn`
- Acceptance evidence: `src/apps/daemon/internal/foundation/boundedio/line_test.go#TestReadLineRejectsOversizeWithoutUnboundedAccumulation`
- Invariant: line-oriented peer input cannot allocate without a caller-defined byte ceiling while waiting for a terminator
- Negative invariant: oversized lines are never forwarded as partial payloads and callers must fail the protocol/connection path rather than resume on a desynchronized stream
- Status: `verified`

## Historical semantic re-evaluation

### fo-sem001
**OS-backed client secret storage**

- Prior disposition: `superseded`
- Current disposition: `superseded`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `src/apps/daemon/internal/foundation/secrets/store.go#Store`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original superseded disposition remains correct: LumiNet backend secret references/platform stores are deeper and keep UI non-authoritative. Stronger target owner: backend secret references plus platform-backed stores.
- Status: `reviewed`

### fo-sem002
**deliberate reveal gesture for hidden information**

- Prior disposition: `inspired-native`
- Current disposition: `inspired-native`
- Result: `stays-live-after-fourth-order-recheck`
- Target evidence: `src/packages/control-ui/src/pages/Settings.tsx#warpPrivateKeyVisible`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original inspired-native disposition remains correct: The donor demonstrates intentional disclosure; LumiNet applies the outcome to WARP private-key presentation without copying Flutter UI.
- Status: `reviewed`

### fo-sem003
**Android VPN service lifecycle and socket bypass**

- Prior disposition: `adapted`
- Current disposition: `adapted`
- Result: `stays-live-after-fourth-order-recheck`
- Target evidence: `src/apps/android/app/src/main/java/com/luminet/android/VpnEngineService.kt#socketProtector`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original adapted disposition remains correct: LumiNet already owns VpnService/TUN lifecycle; donor evidence exposed the missing per-socket protect bridge.
- Status: `reviewed`

### fo-sem004
**native connection status reconciliation**

- Prior disposition: `superseded`
- Current disposition: `superseded`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `src/apps/daemon/internal/runtime/mobilecore/controller.go#Status`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original superseded disposition remains correct: LumiNet service/daemon state is already authoritative and UI state is derived. Stronger target owner: daemon/mobilecore runtime state remains authoritative.
- Status: `reviewed`

### fo-sem005
**iOS PacketTunnel host lifecycle**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem005`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Useful future iOS host evidence, but iOS is not a current LumiNet product surface.
- Status: `reviewed`

### fo-sem006
**client update dialog workflow**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem006`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Useful UX reference, but self-update would create unsigned code-download authority without target promotion/rollback contract.
- Status: `reviewed`

### fo-sem007
**client speed-test presentation**

- Prior disposition: `superseded`
- Current disposition: `superseded`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `src/apps/daemon/internal/adapters/api/handlers_speedtest.go#RunSpeedtest`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original superseded disposition remains correct: LumiNet already has speedtest API and qualification workflow. Stronger target owner: server-owned speed diagnostics and qualification already exist.
- Status: `reviewed`

### fo-sem008
**operator log viewer affordances**

- Prior disposition: `reference-only`
- Current disposition: `superseded`
- Result: `superseded-by-current-target`
- Target evidence: `src/packages/control-ui/src/pages/Logs.tsx#MAX_LOG_LINES`
- Rationale: The former log-viewer reference is now fully superseded by LumiNet's live bounded operational log page: the UI caps live accumulation at 500 lines and consumes the target telemetry/log API without becoming authoritative.
- Status: `statically-validated`

### fo-sem009
**SSTP client/profile plane**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem009`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: SSTP is a potentially useful future protocol, but adding it now would create an unverified parallel VPN transport/credential plane.
- Status: `reviewed`

### fo-sem010
**verification-off TLS defaults**

- Prior disposition: `guardrail-derived`
- Current disposition: `guardrail-derived`
- Result: `stays-live-after-fourth-order-recheck`
- Target evidence: `src/apps/daemon/internal/integrations/sub/safety.go#filterSafeProxyConfig`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original guardrail-derived disposition remains correct: Donor defaults are weaker; they reinforce LumiNet fail-closed verification and insecure-config filtering.
- Status: `reviewed`

### fo-sem011
**credentials in ordinary preferences**

- Prior disposition: `guardrail-derived`
- Current disposition: `guardrail-derived`
- Result: `stays-live-after-fourth-order-recheck`
- Target evidence: `src/apps/daemon/internal/foundation/secrets/store.go#Store`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original guardrail-derived disposition remains correct: Plain preference credentials are weaker than LumiNet secret refs/platform stores.
- Status: `reviewed`

### fo-sem012
**DNS/proxy/TLS profile editing UX**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem012`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Useful operator information architecture; LumiNet already owns equivalent backend settings and does not need donor Flutter state.
- Status: `reviewed`

### fo-sem013
**bounded increasing restart delay**

- Prior disposition: `adapted`
- Current disposition: `adapted`
- Result: `stays-live-after-fourth-order-recheck`
- Target evidence: `src/apps/daemon/internal/platform/system/process_supervisor.go#restartBackoff`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original adapted disposition remains correct: Donor state machine has explicit bounded retries; target comment claimed exponential backoff but implementation was constant. The target ProcessSupervisor currently has no production constructor call, so this is capability-level hardening, not a shipped runtime-impact claim.
- Status: `reviewed`

### fo-sem014
**healthy-state retry reset**

- Prior disposition: `hardened`
- Current disposition: `hardened`
- Result: `stays-live-after-fourth-order-recheck`
- Target evidence: `src/apps/daemon/internal/platform/system/process_supervisor.go#markReady`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original hardened disposition remains correct: Readiness should reset retry delay but not safety history; target separates consecutive backoff from failure-window debt. The target ProcessSupervisor currently has no production constructor call, so this is capability-level hardening, not a shipped runtime-impact claim.
- Status: `reviewed`

### fo-sem015
**sidecar readiness from concurrent output streams**

- Prior disposition: `hardened`
- Current disposition: `hardened`
- Result: `stays-live-after-fourth-order-recheck`
- Target evidence: `src/apps/daemon/internal/platform/system/process_supervisor.go#runOnce`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original hardened disposition remains correct: Donor readiness lineage motivated target synchronization; LumiNet now uses a single readiness latch across stdout/stderr. The target ProcessSupervisor currently has no production constructor call, so this is capability-level hardening, not a shipped runtime-impact claim.
- Status: `reviewed`

### fo-sem016
**pre-connect port collision check**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem016`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Useful operator preflight; LumiNet already has host/network readiness probes and binding errors, so no duplicate sidecar preflight owner.
- Status: `reviewed`

### fo-sem017
**PID-file orphan termination**

- Prior disposition: `rejected-with-reason`
- Current disposition: `rejected-with-reason`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem017`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original rejected-with-reason disposition remains correct: PID-only killing risks terminating an unrelated process after PID reuse.
- Status: `reviewed`

### fo-sem018
**bounded PTY partial-line buffer**

- Prior disposition: `reference-only`
- Current disposition: `adapted`
- Result: `promoted-as-cross-protocol-bounded-line-reader`
- Target evidence: `src/apps/daemon/internal/foundation/boundedio/line.go#ReadLine;src/apps/daemon/internal/platform/system/tor_controller.go#readLineLocked;src/apps/daemon/internal/runtime/proxy/https_connect_fragmentor.go#ResponseLineReader`
- Rationale: The donor PTY subsystem remains non-live, but its tiny bounded-partial-line invariant generalizes beyond PTY. LumiNet extracts that invariant into one allocation-bounded line reader and applies it to line-oriented proxy/control protocols that previously used unbounded ReadString waiting for a newline. Protocol owners keep their own limits and connection authority.
- Status: `verified`

### fo-sem019
**bounded client log history**

- Prior disposition: `superseded`
- Current disposition: `superseded`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `src/packages/control-ui/src/api/contracts.ts#LogsResponse`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original superseded disposition remains correct: LumiNet already uses a 500-line bounded product log surface. Stronger target owner: target product log surface is already bounded and daemon-derived.
- Status: `reviewed`

### fo-sem020
**profile migration/validation**

- Prior disposition: `superseded`
- Current disposition: `superseded`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `src/apps/daemon/internal/integrations/sub/profile_service.go#ProfileService`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original superseded disposition remains correct: LumiNet profile service already validates, snapshots metadata, cancels stale refreshes and owns profile lifecycle. Stronger target owner: profile validation/refresh/cancellation lifecycle is target-owned.
- Status: `reviewed`

### fo-sem021
**exact-preimage hosts transaction**

- Prior disposition: `adapted`
- Current disposition: `adapted`
- Result: `stays-live-after-fourth-order-recheck`
- Target evidence: `src/packages/lumicore/src/dns/hosts_optimizer.rs#write_hosts_transaction`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original adapted disposition remains correct: Donor preserves original hosts bytes and verifies application; target keeps its owner but adds exact-preimage verify/rollback.
- Status: `reviewed`

### fo-sem022
**aggressive DNS service/process/ACL takeover**

- Prior disposition: `rejected-with-reason`
- Current disposition: `rejected-with-reason`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem022`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original rejected-with-reason disposition remains correct: Stopping services, killing processes and taking ownership broadens authority beyond the requested hosts mutation.
- Status: `reviewed`

### fo-sem023
**small remote-main-line TTL cache**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem023`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Useful desktop cache pattern but target provider/profile caches already own TTL semantics.
- Status: `reviewed`

### fo-sem024
**language normalization and fallback**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem024`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Useful localization fallback reference; current control UI is not yet localized enough to justify a new runtime plane.
- Status: `reviewed`

### fo-sem025
**desktop update workflow**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem025`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: One of several donor updater surfaces; target lacks signed update authority/rollback, so implementation is deferred.
- Status: `reviewed`

### fo-sem026
**retrying delete/external-open helpers**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem026`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Operational helper patterns retained; no natural target owner requires them today.
- Status: `reviewed`

### fo-sem027
**labeled service-access domains**

- Prior disposition: `extracted`
- Current disposition: `extracted`
- Result: `stays-live-after-fourth-order-recheck`
- Target evidence: `src/apps/daemon/internal/networking/routing/domain_data/category-service-access.txt#chatgpt.com`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original extracted disposition remains correct: Stable domain taxonomy is valuable; volatile donor IP bindings are discarded and domains become routing knowledge.
- Status: `reviewed`

### fo-sem028
**hard-coded service destination IPs**

- Prior disposition: `rejected-with-reason`
- Current disposition: `rejected-with-reason`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem028`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original rejected-with-reason disposition remains correct: Destination IPs are volatile outcomes, not stable policy, and would create brittle pinning.
- Status: `reviewed`

### fo-sem029
**28K+ blocking domain corpus**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem029`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Large block corpus is useful evaluation evidence but too broad/high-false-positive to become default target policy.
- Status: `reviewed`

### fo-sem030
**15 unlabeled positive domains**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem030`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Unlabeled positives lack semantic ownership; retained for evaluation rather than live routing.
- Status: `reviewed`

### fo-sem031
**Magisk/root module packaging**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem031`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Root/Magisk deployment is not a supported LumiNet installation authority.
- Status: `reviewed`

### fo-sem032
**insecure TLS spelling normalization**

- Prior disposition: `adapted`
- Current disposition: `adapted`
- Result: `stays-live-after-fourth-order-recheck`
- Target evidence: `src/apps/daemon/internal/networking/proxyconfig/types.go#queryBool`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original adapted disposition remains correct: Real feeds contain allowInsecure/insecure/skip-cert-verify spellings target parsers previously ignored.
- Status: `reviewed`

### fo-sem033
**HTML-escaped proxy query separators**

- Prior disposition: `hardened`
- Current disposition: `hardened`
- Result: `stays-live-after-fourth-order-recheck`
- Target evidence: `src/apps/daemon/internal/networking/proxyconfig/types.go#normalizeProxyURI`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original hardened disposition remains correct: Corpus contains massive HTML-escaped separators; target URI ingress now normalizes only &amp; before parsing.
- Status: `reviewed`

### fo-sem034
**insecure configuration filtering**

- Prior disposition: `adapted`
- Current disposition: `adapted`
- Result: `stays-live-after-fourth-order-recheck`
- Target evidence: `src/apps/daemon/internal/integrations/sub/safety.go#filterSafeProxyConfig`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original adapted disposition remains correct: Donor filter outcome is retained but target policy is tied to parsed semantics and explicit opt-in.
- Status: `reviewed`

### fo-sem035
**two-level proxy deduplication**

- Prior disposition: `adapted`
- Current disposition: `adapted`
- Result: `stays-live-after-fourth-order-recheck`
- Target evidence: `src/apps/daemon/internal/integrations/sub/safety.go#dedupeProxyConfigs`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original adapted disposition remains correct: Target dedupe uses complete proxy semantics instead of collapsing distinct credentials sharing host:port.
- Status: `reviewed`

### fo-sem036
**TLS verification disabled and HTTPS downgrade retry**

- Prior disposition: `rejected-with-reason`
- Current disposition: `rejected-with-reason`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem036`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original rejected-with-reason disposition remains correct: Donor downloader weakens transport security; target keeps HTTPS-only validated egress with bounded bodies.
- Status: `reviewed`

### fo-sem037
**bounded concurrent source fetching**

- Prior disposition: `adapted`
- Current disposition: `adapted`
- Result: `stays-live-after-fourth-order-recheck`
- Target evidence: `src/apps/daemon/internal/integrations/sub/aggregate.go#resolveInputsBounded`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original adapted disposition remains correct: Donor bounded concurrent source fetch exposed that target aggregation was serial; LumiNet now uses a four-worker owner-local resolver while preserving input order and context cancellation.
- Status: `reviewed`

### fo-sem038
**large multi-protocol live grammar corpus**

- Prior disposition: `extracted`
- Current disposition: `extracted`
- Result: `stays-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#proxy-corpus-grammar`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original extracted disposition remains correct: Volatile endpoints/credentials are not shipped, but syntax/query shapes are retained as parser differential evidence.
- Status: `reviewed`

### fo-sem039
**SNI/domain catalog**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem039`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Useful future scanner/routing evaluation corpus; not promoted without freshness and target-specific classification.
- Status: `reviewed`

### fo-sem040
**QR subscription distribution outputs**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem040`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Product distribution artifact reference; target already exposes config/API surfaces and need not store generated QR images.
- Status: `reviewed`

### fo-sem041
**GitHub release discovery/update tooling**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem041`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Useful updater/reference mechanism but deferred until signed target upgrade authority exists.
- Status: `reviewed`

### fo-sem042
**offline cache/service worker strategy**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem042`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Useful public-site PWA reference; LumiNet has no public download/PWA product plane.
- Status: `reviewed`

### fo-sem043
**GitHub release asset discovery with TTL cache**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem043`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: One of several updater/distribution mechanisms; retained until target has signed update authority.
- Status: `reviewed`

### fo-sem044
**external-link confirmation affordance**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem044`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Useful browser UX pattern; current control UI exposes no equivalent external-link surface needing it.
- Status: `reviewed`

### fo-sem045
**multi-language product translation corpus**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem045`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Localization structure is useful reference but donor strings/product taxonomy do not belong in LumiNet.
- Status: `reviewed`

### fo-sem046
**client download/project statistics presentation**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem046`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Public-site analytics UI has no target operator-plane need.
- Status: `reviewed`

### fo-sem047
**SEO/meta routes and templates**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem047`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Public marketing site behavior is outside current LumiNet application authority.
- Status: `reviewed`

### fo-sem048
**SOCKS5 UDP association source binding**

- Prior disposition: `adapted`
- Current disposition: `adapted`
- Result: `stays-live-after-fourth-order-recheck`
- Target evidence: `src/apps/daemon/internal/runtime/proxy/socks5_stun.go#socksUDPClientAllowed`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original adapted disposition remains correct: Donor documents first-packet capture failure and binds UDP authority to TCP/declared endpoint; target hardens existing relay.
- Status: `reviewed`

### fo-sem049
**accept failure backoff**

- Prior disposition: `adapted`
- Current disposition: `adapted`
- Result: `stays-live-after-fourth-order-recheck`
- Target evidence: `src/apps/daemon/internal/runtime/proxy/accept_backoff.go#waitAfterAcceptError`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original adapted disposition remains correct: Donor yields on listener exhaustion; two LumiNet listeners retried immediately and could hot-spin.
- Status: `reviewed`

### fo-sem050
**full DNS query/response correlation**

- Prior disposition: `hardened`
- Current disposition: `hardened`
- Result: `stays-live-after-fourth-order-recheck`
- Target evidence: `src/packages/lumicore/src/dns/packet.rs#response_matches_query;src/packages/lumicore/src/dns/udp.rs#resolve`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original hardened disposition remains correct: Target UDP resolver checked only txid; donor requires echoed question semantics.
- Status: `reviewed`

### fo-sem051
**HTTP health status-line parsing**

- Prior disposition: `hardened`
- Current disposition: `hardened`
- Result: `stays-live-after-fourth-order-recheck`
- Target evidence: `src/packages/lumicore/src/diagnostics/runbook.rs#http_status_code`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original hardened disposition remains correct: Donor regression oracle rejects body/header substrings masquerading as a 204 status. The target DiagnosticRunbook is a public LumiCore capability with no current in-repo runtime caller, so this is library-surface hardening rather than a shipped workflow claim.
- Status: `reviewed`

### fo-sem052
**private durable atomic config write**

- Prior disposition: `adapted`
- Current disposition: `adapted`
- Result: `stays-live-after-fourth-order-recheck`
- Target evidence: `src/apps/daemon/internal/foundation/config/atomic_file.go#writeAtomicPrivateFile`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original adapted disposition remains correct: Donor uses owner-only temp file and sync before atomic rename; target keeps its schema/secret semantics and adopts durability/privacy.
- Status: `reviewed`

### fo-sem053
**CGNAT/link-local private-network predicate**

- Prior disposition: `guardrail-derived`
- Current disposition: `guardrail-derived`
- Result: `stays-live-after-fourth-order-recheck`
- Target evidence: `src/apps/daemon/internal/networking/geoip/geoip.go#IsPrivateIP`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original guardrail-derived disposition remains correct: Donor predicate exposed multiple weaker target duplicates; target consolidates onto existing canonical local/LAN owner.
- Status: `reviewed`

### fo-sem054
**bounded provider API response body**

- Prior disposition: `hardened`
- Current disposition: `hardened`
- Result: `stays-live-after-fourth-order-recheck`
- Target evidence: `src/apps/daemon/cmd/doctor.go#runDoctor;src/apps/daemon/internal/analysis/diagnostics/diagnostics.go#readBoundedDiagnosticBody;src/apps/daemon/internal/analysis/scanner/cloudflare_deployer.go#DeployWorkerScript;src/apps/daemon/internal/integrations/captchaclient/http_bounds.go#readBoundedCaptchaResponse;src/apps/daemon/internal/integrations/provision/cloudflare.go#doReq;src/apps/daemon/internal/integrations/relayclient/http_bounds.go#readBoundedRelayControlResponse;src/apps/daemon/internal/integrations/sub/egress.go#readBoundedSubscriptionBody;src/apps/daemon/internal/networking/dns/http_bounds.go#readBoundedDNSBody;src/apps/daemon/internal/networking/dns/ddns_bounds.go#decodeBoundedDDNSJSON;src/apps/daemon/internal/networking/geoip/http_bounds.go#decodeBoundedGeoIPJSON;src/apps/daemon/internal/runtime/proxy/http_bounds.go#readBoundedProxyHTTPBody`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original hardened disposition remains correct: Target had unbounded provider/DNS/covert response reads; donor 512KiB ceiling exposed the broader missing invariant that every remote protocol/control reader needs an owner-specific payload ceiling.
- Status: `reviewed`

### fo-sem055
**automatic registration POST retries**

- Prior disposition: `rejected-with-reason`
- Current disposition: `superseded`
- Result: `unsafe-mechanism-still-rejected-safe-intent-superseded`
- Target evidence: `src/apps/daemon/internal/foundation/remoteaction/remoteaction.go#Do;src/apps/daemon/internal/foundation/remoteaction/remoteaction_test.go#TestReconcilePreventsDuplicateReplay`
- Rationale: Blind registration POST replay remains forbidden, but the resilience goal is now superseded by LumiNet's target-wide remote-action authority: idempotent actions may retry, ambiguous writes require successful reconciliation, and unreconcilable creates remain single-attempt.
- Status: `verified`

### fo-sem056
**MASQUE certificate lifetime/renewal window**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem056`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Strong lifecycle predicate, but LumiNet currently has no persisted MASQUE certificate owner to harden without introducing a new transport/auth plane.
- Status: `reviewed`

### fo-sem057
**block-before-proxy precedence**

- Prior disposition: `rejected-with-reason`
- Current disposition: `rejected-with-reason`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem057`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original rejected-with-reason disposition remains correct: Target intentionally protects service/anticensorship categories from broad block/direct categories and current corpora show no conflict requiring donor precedence.
- Status: `reviewed`

### fo-sem058
**bounded per-tick network queues/drop-on-full**

- Prior disposition: `superseded`
- Current disposition: `superseded`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `src/apps/daemon/internal/runtime/proxy/evasion_tunnel.go#EvasionTunnelManager`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original superseded disposition remains correct: LumiNet already has bounded queues/context cancellation in its runtime owners; importing smoltcp netstack would duplicate transport authority. Stronger target owner: runtime owners already use bounded queues/context cancellation.
- Status: `reviewed`

### fo-sem059
**bounded transient UDP receive error tolerance**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem059`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Useful tunnel-loop oracle; LumiNet WARP plane does not expose the same long-lived userspace receive loop to patch directly.
- Status: `reviewed`

### fo-sem060
**CIDR ordering/sampling and MASQUE reachability probes**

- Prior disposition: `superseded`
- Current disposition: `superseded`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `src/apps/daemon/internal/runtime/warp/warp_scanner.go#WARPScanner`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original superseded disposition remains correct: Target scanners/WARP scanner already own configurable concurrency/timeouts/real handshake verification. Stronger target owner: target scanner already owns concurrency/timeouts/real endpoint verification.
- Status: `reviewed`

### fo-sem061
**WireGuard range sampling/verification**

- Prior disposition: `superseded`
- Current disposition: `superseded`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `src/apps/daemon/internal/runtime/warp/warp_scanner.go#WARPScanner`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original superseded disposition remains correct: Target WARP scanner already does real WireGuard handshake and endpoint qualification. Stronger target owner: same live WARP scanner supersedes donor range probe.
- Status: `reviewed`

### fo-sem062
**hardware-adaptive socket/buffer profile**

- Prior disposition: `reference-only`
- Current disposition: `adapted`
- Result: `promoted-as-capacity-ceiling`
- Target evidence: `src/apps/daemon/internal/foundation/resourcebudget/resourcebudget.go#For;src/apps/daemon/internal/foundation/resourcebudget/resourcebudget.go#CapWorkers`
- Rationale: Hardware evidence is now useful because it is constrained to a non-authoritative ceiling. CPU/optional-memory tiers can only lower subsystem concurrency; they cannot silently raise an owner's limit. This avoids the earlier predictability objection while preserving the donor's resource-awareness insight.
- Status: `verified`

### fo-sem063
**last connection cache**

- Prior disposition: `superseded`
- Current disposition: `recomposed`
- Result: `promoted-inside-profile-owner`
- Target evidence: `src/apps/daemon/internal/integrations/sub/profile_service.go#orderedProfileSources;src/apps/daemon/internal/integrations/sub/profile_service.go#LastSourceURL`
- Rationale: A separate last-connection file is still rejected, but the last-known-good ordering primitive now composes safely inside ProfileService: the primary URL remains authoritative while the last successful source is preferred on later refreshes if still configured and eligible.
- Status: `verified`

### fo-sem064
**Cloudflare Access/Zero Trust token login/cache**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem064`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Potential future authenticated-edge integration; no current target authority/consumer justifies importing interactive token acquisition.
- Status: `reviewed`

### fo-sem065
**MASQUE CONNECT-IP capsule parsing/tunnel**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem065`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Target has no MASQUE transport authority; direct import would create a second transport stack.
- Status: `reviewed`

### fo-sem066
**HTTP/2 MASQUE fallback**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem066`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Transport-specific fallback retained as reference; no target H2-MASQUE plane.
- Status: `reviewed`

### fo-sem067
**quiche MASQUE/QUIC client**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem067`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Quiche-based transport would duplicate target networking authority and native stack.
- Status: `reviewed`

### fo-sem068
**fragmented stream adapter**

- Prior disposition: `superseded`
- Current disposition: `superseded`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `src/apps/daemon/internal/protocols/tlsfragment/utls_fragment.go#WrapUTLSFragmentConn`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original superseded disposition remains correct: LumiNet already has multiple fragmentation/evasion implementations and controls. Stronger target owner: target already owns fragmentation semantics.
- Status: `reviewed`

### fo-sem069
**noise traffic generator**

- Prior disposition: `superseded`
- Current disposition: `superseded`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `src/apps/daemon/internal/runtime/decoy/manager.go#Manager`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original superseded disposition remains correct: LumiNet already has decoy/noise/evasion ownership with cancellation and bounds. Stronger target owner: target decoy manager owns bounded noise lifecycle.
- Status: `reviewed`

### fo-sem070
**noise rate/range parser and generator**

- Prior disposition: `superseded`
- Current disposition: `superseded`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `src/apps/daemon/internal/runtime/decoy/manager.go#Manager`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original superseded disposition remains correct: Same responsibility already lives in target decoy/evasion owners. Stronger target owner: same target owner supersedes donor noise range parser/runtime.
- Status: `reviewed`

### fo-sem071
**ECH retry configuration extraction**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem071`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Useful ECH interoperability reference; target ECH implementation already owns TLS behavior and cannot be replaced without native tests.
- Status: `reviewed`

### fo-sem072
**bounded reusable buffer retention**

- Prior disposition: `hardened`
- Current disposition: `hardened`
- Result: `stays-live-after-fourth-order-recheck`
- Target evidence: `src/packages/lumicore/src/data/ring_buffer.rs#BufferPool`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original hardened disposition remains correct: Donor pool treats configured size as a retention ceiling; target constructor previously only preallocated then grew forever. BufferPool is a public LumiCore library capability with no current in-repo runtime constructor call, so this is capability-level hardening rather than a shipped runtime claim.
- Status: `reviewed`

### fo-sem073
**task kill-switch tree**

- Prior disposition: `superseded`
- Current disposition: `superseded`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `src/apps/daemon/internal/workflows/jobs/manager.go#CancelJob;src/apps/daemon/internal/runtime/runtimecore/manager.go#Close`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original superseded disposition remains correct: LumiNet Go contexts/process supervisor and Rust task ownership already provide cancellation without another hierarchy. Stronger target owner: live job/runtime owners use context cancellation and explicit stop/close semantics, superseding a second kill-switch hierarchy.
- Status: `reviewed`

### fo-sem074
**bounds-checked octet reader/writer**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem074`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Excellent parser oracle, but direct crate import would expand Rust dependency surface; target parsers keep local bounds checks.
- Status: `reviewed`

### fo-sem075
**batched datagram/GSO socket abstraction**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem075`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: High-performance QUIC datagram implementation is transport-specific; no measured target need justifies adoption.
- Status: `reviewed`

### fo-sem076
**HTTP/3/QPACK implementation**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem076`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Full H3/QPACK authority retained for interoperability research; target does not own quiche H3 runtime.
- Status: `reviewed`

### fo-sem077
**QUIC congestion/loss recovery suite**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem077`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Cubic/Reno/PRR/BBR/BBRv2/pacing are valid transport references but inseparable from quiche packet/recovery model.
- Status: `reviewed`

### fo-sem078
**QUIC PMTUD state machine**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem078`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: PMTUD implementation is specific to quiche path state; retained as reference.
- Status: `reviewed`

### fo-sem079
**path validation/migration**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem079`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: QUIC path/CID migration is transport-specific and not a standalone target capability.
- Status: `reviewed`

### fo-sem080
**QLOG schema/serialization**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem080`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Useful standard telemetry reference; LumiNet keeps one existing evidence/telemetry schema instead of a second logging authority.
- Status: `reviewed`

### fo-sem081
**Chrome NetLog conversion**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem081`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Interoperability/export reference only; no target consumer currently needs NetLog.
- Status: `reviewed`

### fo-sem082
**QLOG visualization UI**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem082`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Visualization reference only; target UI already has diagnostics/evidence surfaces.
- Status: `reviewed`

### fo-sem083
**QUIC fuzz corpus/harness family**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem083`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Large fuzz corpus is valuable transport/parser evidence but does not map to target protocol owners without quiche equivalence.
- Status: `reviewed`

### fo-sem084
**Tokio QUIC router/socket framework**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem084`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Would duplicate target daemon/runtime networking plane and operational cost.
- Status: `reviewed`

### fo-sem085
**interactive HTTP/3 client/scenario runner**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem085`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Useful protocol test/oracle surface, not a target runtime module.
- Status: `reviewed`

### fo-sem086
**quiche C ABI**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem086`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Target already has its own LumiCore ABI; importing quiche C ABI would broaden native compatibility surface.
- Status: `reviewed`

### fo-sem087
**peer-convergence evidence plane**

- Prior disposition: `synthesized`
- Current disposition: `synthesized`
- Result: `stays-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-adoption-ledger.csv#record_id;scripts/checks/check_peer_convergence.py#main`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original synthesized disposition remains correct: Eight heterogeneous donors contribute cross-cutting code/data/tests/negative lessons; durable traceability is a justified new governance plane.
- Status: `reviewed`

### fo-sem088
**cross-donor updater/download plane**

- Prior disposition: `rejected-with-reason`
- Current disposition: `rejected-with-reason`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem088`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original rejected-with-reason disposition remains correct: defyx, Goida desktop and Goida site all expose updater/distribution UX, but target lacks signed code-download authority and rollback.
- Status: `reviewed`

### fo-sem089
**environment/CLI configuration mutation**

- Prior disposition: `superseded`
- Current disposition: `superseded`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `src/apps/daemon/cmd/root.go#rootCmd`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original superseded disposition remains correct: Aether maps CLI flags into process environment; LumiNet already has Cobra/config owners and should not add environment-as-authority side effects. Stronger target owner: Cobra/config owners supersede environment-as-authority mutation.
- Status: `reviewed`

### fo-sem090
**Cloudflare MASQUE endpoints, ALPN, pins and anycast seeds**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem090`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Protocol constants and pins are valuable interoperability evidence but are vendor/time-sensitive and tied to Aether MASQUE transport.
- Status: `reviewed`

### fo-sem091
**structured Aether runtime error taxonomy**

- Prior disposition: `superseded`
- Current disposition: `superseded`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `src/apps/daemon/internal/runtime/runtimecore/manager.go#ErrInvalidRequest;src/apps/daemon/internal/integrations/sub/egress.go#ErrUnsafeRemoteTarget`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original superseded disposition remains correct: LumiNet already has target-owned structured errors and subsystem-specific error mapping; importing a donor-wide enum would flatten target ownership. Stronger target owner: errors remain owned by individual target modules rather than a donor-wide enum.
- Status: `reviewed`

### fo-sem092
**protocol selection, reconnect and peer hunting orchestration**

- Prior disposition: `superseded`
- Current disposition: `superseded`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `src/apps/daemon/internal/workflows/jobs/manager.go#JobManager;src/apps/daemon/internal/runtime/runtimecore/manager.go#Manager`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original superseded disposition remains correct: Aether monolith coordinates MASQUE/WireGuard/scanning/UI prompts; LumiNet already decomposes these responsibilities across workflows, profile service, scanners and runtime owners. Stronger target owner: target decomposes orchestration across live workflow/runtime owners.
- Status: `reviewed`

### fo-sem093
**abort-handle forwarder guard**

- Prior disposition: `superseded`
- Current disposition: `superseded`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `src/apps/daemon/internal/workflows/jobs/manager.go#CancelJob;src/apps/daemon/internal/runtime/runtimecore/manager.go#Close`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original superseded disposition remains correct: Abort-on-drop is a sound lifecycle primitive, but LumiNet already uses context cancellation and owner-scoped process/task lifetimes. Stronger target owner: live owner-scoped context/process lifetimes supersede an abort-forwarder hierarchy.
- Status: `reviewed`

### fo-sem094
**protocol reconnect/cooldown controls**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem094`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Reconnect/cooldown values are useful operational reference but depend on Aether transport/prober timing and are not portable target constants.
- Status: `reviewed`

### fo-sem095
**structured Cloudflare rejection extraction and rate-limit explanation**

- Prior disposition: `adapted`
- Current disposition: `adapted`
- Result: `stays-live-after-fourth-order-recheck`
- Target evidence: `src/apps/daemon/internal/integrations/provision/cloudflare_errors.go#formatCloudflareAPIError;src/apps/daemon/internal/integrations/provision/cloudflare.go#doReq`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original adapted disposition remains correct: Aether separates structured Cloudflare rejection details and Retry-After hints from retry policy. LumiNet adopts only the bounded error-extraction/message primitive in its existing Cloudflare provisioning owner; automatic registration mutation retry remains rejected without an idempotency contract.
- Status: `reviewed`

### fo-sem096
**bounded HTTP proxy head parsing and authority normalization**

- Prior disposition: `superseded`
- Current disposition: `superseded`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `src/apps/daemon/internal/runtime/proxy/https_connect_fragmentor.go#HTTPSConnectFragmentor;src/apps/daemon/internal/runtime/proxy/http_bounds.go#readBoundedProxyHTTPBody`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original superseded disposition remains correct: Aether has a compact explicit-proxy parser with 16KiB head ceiling; LumiNet already owns HTTP/proxy routing and bounded remote-read policy. Stronger target owner: target proxy owners already enforce request parsing and bounded-read policy.
- Status: `reviewed`

### fo-sem097
**JWT expiry parsing and live-token reuse**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem097`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: The expiry/cache predicate is sound and independently useful, but LumiNet has no current Cloudflare Access token authority or consumer.
- Status: `reviewed`

### fo-sem098
**service-token completeness and interactive Access login extraction**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem098`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Cloudflare Access login/service-token mechanics are a coherent future capability but would add identity/token authority not currently needed by LumiNet.
- Status: `reviewed`

### fo-sem099
**macOS platform transport/test harness**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem099`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Platform-specific experimental harness is useful historical portability evidence but not a shipped target host contract.
- Status: `reviewed`

### fo-sem100
**tray/event/focus host integration**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem100`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Useful desktop affordance and atomic state reference, but LumiNet desktop host already uses Wails and should not gain a second Tauri host plane.
- Status: `reviewed`

### fo-sem101
**typed status/log event envelopes**

- Prior disposition: `reference-only`
- Current disposition: `reference-only`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem101`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original reference-only disposition remains correct: Typed host events are useful product reference; LumiNet currently uses authenticated daemon/control-UI transport and should keep one event/state path.
- Status: `reviewed`

### fo-sem102
**hosts status/preview/apply/restore operator workflow**

- Prior disposition: `reference-only`
- Current disposition: `inspired-native`
- Result: `promoted-as-read-only-owner-preview`
- Target evidence: `src/apps/daemon/internal/platform/system/host_network.go#PlanHostNetwork;src/apps/daemon/internal/adapters/api/handlers_host_network_plan.go#PlanHostNetwork`
- Rationale: The donor preview/status workflow is now promotable because LumiNet already owns transactional apply/rollback/recovery. The target adds a read-only plan surface to the same owner; preview creates no recovery files, grants no apply authority, and cannot mutate host state.
- Status: `verified`

### fo-sem103
**connection duration/status presentation**

- Prior disposition: `superseded`
- Current disposition: `superseded`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `src/packages/control-ui/src/store/systemStore.ts#useSystemStore`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original superseded disposition remains correct: LumiNet already derives live connection/session status from daemon/service truth; donor UI timing stays presentation-only reference. Stronger target owner: connection presentation derives from daemon/system state.
- Status: `reviewed`

### fo-sem104
**ad retry/error widget**

- Prior disposition: `rejected-with-reason`
- Current disposition: `rejected-with-reason`
- Result: `stays-non-live-after-fourth-order-recheck`
- Target evidence: `governance/convergence/peer-validation.md#sem104`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original rejected-with-reason disposition remains correct: Advertising/monetization code is outside LumiNet product responsibility and adds unrelated tracking/network authority.
- Status: `reviewed`

### fo-sem105
**source fetch error normalization**

- Prior disposition: `reference-only`
- Current disposition: `adapted`
- Result: `promoted-as-bounded-per-source-diagnostics`
- Target evidence: `src/apps/daemon/internal/integrations/sub/profile_service.go#recordSourceFailure;src/apps/daemon/internal/integrations/sub/profile_service.go#boundedSourceError`
- Rationale: Source-specific failure normalization now composes with the second-order source-health owner. Errors are bounded/redacted per source and drive backoff without inheriting verification-off downloader behavior.
- Status: `verified`

### fo-sem106
**Shadowsocks plaintext/SS2022 and final-at legacy userinfo forms**

- Prior disposition: `adapted`
- Current disposition: `adapted`
- Result: `stays-live-after-fourth-order-recheck`
- Target evidence: `src/apps/daemon/internal/networking/proxyconfig/parser_ss.go#parseShadowsocks`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original adapted disposition remains correct: Half-million-line differential parsing exposed standards-compatible SS forms the target rejected; target parser now handles plaintext method:password, SS2022 colon-bearing key material, base64 userinfo and legacy payloads whose password contains @.
- Status: `reviewed`

### fo-sem107
**VMess boolean TLS field**

- Prior disposition: `hardened`
- Current disposition: `hardened`
- Result: `stays-live-after-fourth-order-recheck`
- Target evidence: `src/apps/daemon/internal/networking/proxyconfig/parser_vmess.go#vmessTLSValue`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original hardened disposition remains correct: Observed VMess feeds encode tls as both strings and booleans; target now preserves either representation without weakening verification flags.
- Status: `reviewed`

### fo-sem108
**mis-schemed VMess-as-Shadowsocks false-positive corpus**

- Prior disposition: `guardrail-derived`
- Current disposition: `guardrail-derived`
- Result: `stays-live-after-fourth-order-recheck`
- Target evidence: `src/apps/daemon/internal/networking/proxyconfig/parser_ss.go#parseShadowsocks`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original guardrail-derived disposition remains correct: Differential analysis proved 97 old SS successes were VMess JSON mislabeled ss:// and accidentally accepted because @ appeared inside decoded JSON.
- Status: `reviewed`

### fo-sem109
**verification-off fallback as negative TLS evidence**

- Prior disposition: `guardrail-derived`
- Current disposition: `guardrail-derived`
- Result: `stays-live-after-fourth-order-recheck`
- Target evidence: `src/apps/daemon/internal/runtime/proxy/ech.go#ECHInsecureSkipVerify;src/apps/daemon/internal/runtime/proxy/ech_test.go#TestEchClientCertValidation;scripts/checks/repo_audit.py#ECHInsecureSkipVerify`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original guardrail-derived disposition remains correct: Aether can disable certificate verification when no pin set is configured. LumiNet does not import that BoringSSL/pin authority; the behavior instead exposed an overly permissive target default, so ECH/TLS verification is secure by default and insecure verification remains explicit opt-in only.
- Status: `reviewed`

### fo-sem110
**mis-schemed VLESS/Reality-as-Shadowsocks negative corpus**

- Prior disposition: `guardrail-derived`
- Current disposition: `guardrail-derived`
- Result: `stays-live-after-fourth-order-recheck`
- Target evidence: `src/apps/daemon/internal/networking/proxyconfig/parser_ss.go#parseShadowsocks;src/apps/daemon/internal/networking/proxyconfig/parser_contract_test.go#TestParseShadowsocksRejectsMisSchemedVLESS`
- Rationale: Re-reviewed against the frozen third-wave target at symbol/module/state-machine depth. The original guardrail-derived disposition remains correct: Differential corpus failures are mislabeled VLESS/Reality records, not missing Shadowsocks grammar. UUID identity, encryption=none, flow/Reality/WS fields make them a distinct negative parser oracle instead of a permissiveness request.
- Status: `reviewed`
