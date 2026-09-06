# Fifth-order promotion validation

This layer re-scores previously non-live peer value with functionality, usability and feature/widget richness as the dominant selection criteria. Historical evidence is not rewritten.

### f5-001
**SSTP system-tunnel engine with rich profile controls**

- Source semantic records: `SEM009`
- Disposition: `adapted`
- Target capability: SSTP system tunnel runtime
- Target nodes: `src/apps/daemon/internal/runtime/runtimecore/sstp_engine.go#newSSTPEngine;src/apps/daemon/internal/runtime/runtimecore/manager.go#EngineSSTP;src/apps/daemon/internal/runtime/runtimecore/capability.go#ProbeEngine;src/packages/control-ui/src/pages/Operations.tsx#sstpPPPOptions`
- Acceptance evidence: `src/apps/daemon/internal/runtime/runtimecore/sstp_engine_test.go#TestSSTPEngineStartsAndStopsExternalClient`
- Validation status: `verified`
- Invariant: SSTP can be started/stopped through the same runtime owner as other engines and preserves server, credentials, proxy, CA, certificate-warning and bounded PPP options
- Negative invariant: SSTP does not create a parallel daemon/runtime authority and process shutdown remains owner-scoped

### f5-002
**read-only local TCP port collision preflight**

- Source semantic records: `SEM016`
- Disposition: `adapted`
- Target capability: runtime startability preflight
- Target nodes: `src/apps/daemon/internal/platform/system/port_preflight.go#CheckLocalTCPPort;src/apps/daemon/internal/adapters/api/handlers_port_preflight.go#PortPreflight;src/packages/control-ui/src/pages/Operations.tsx#runPreflight`
- Acceptance evidence: `src/apps/daemon/internal/platform/system/port_preflight_test.go#TestCheckLocalTCPPortReportsOccupiedAndFree`
- Validation status: `verified`
- Invariant: operators can test a local bind target before starting a listener
- Negative invariant: preflight is advisory/read-only and must not reserve or mutate the port

### f5-003
**signed update manifest discovery by URL**

- Source semantic records: `SEM041;SEM043`
- Disposition: `recomposed`
- Target capability: signed update discovery
- Target nodes: `src/apps/daemon/internal/foundation/updateadmission/discover.go#Discover;src/apps/daemon/internal/adapters/api/handlers_update_discover.go#DiscoverSignedUpdate;src/packages/control-ui/src/pages/Operations.tsx#discoverUpdate`
- Acceptance evidence: `src/apps/daemon/internal/foundation/updateadmission/discover_test.go#TestDiscoverFetchesBoundedEnvelope`
- Validation status: `verified`
- Invariant: one manifest URL produces a bounded signed envelope and an admission plan bound to the daemon build
- Negative invariant: discovery cannot install or execute an artifact and redirect chains remain bounded

### f5-004
**verified update artifact staging and update-center workflow**

- Source semantic records: `SEM006;SEM025;SEM088`
- Disposition: `recomposed`
- Target capability: verified update staging
- Target nodes: `src/apps/daemon/internal/foundation/updateadmission/stage.go#Stage;src/apps/daemon/internal/adapters/api/handlers_update_stage.go#StageSignedUpdate;src/packages/control-ui/src/pages/Operations.tsx#runUpdateAction`
- Acceptance evidence: `src/apps/daemon/internal/foundation/updateadmission/stage_test.go#TestStageDownloadsVerifiesAndReusesArtifact`
- Validation status: `verified`
- Invariant: staged bytes must match the admitted size and SHA-256 and are reusable by exact identity
- Negative invariant: staging never executes, installs, or marks apply authorization true

### f5-005
**unified Operations workspace for readiness, diagnostics, engines and exports**

- Source semantic records: `SEM007;SEM101`
- Disposition: `inspired-native`
- Target capability: operations and diagnostic workspace
- Target nodes: `src/packages/control-ui/src/pages/Operations.tsx#Operations;src/packages/control-ui/src/api/contracts.ts#parseDoctorReport;src/packages/control-ui/src/api/contracts.ts#parseRuntimeEngines`
- Acceptance evidence: `src/packages/control-ui/scripts/test-feature-promotions.mjs#checkOperationsDiagnosticsAndTrace`
- Validation status: `statically-validated`
- Invariant: each operations capability loads independently and successful widgets remain usable when another capability is unavailable
- Negative invariant: UI state does not become daemon authority and unavailable capabilities are not presented as successful

### f5-006
**rich subscription profile management with mirror health and provider metadata**

- Source semantic records: `SEM012`
- Disposition: `adapted`
- Target capability: subscription profile workspace
- Target nodes: `src/packages/control-ui/src/pages/Profiles.tsx#Profiles;src/packages/control-ui/src/api/contracts.ts#parseSubscriptionProfiles;src/apps/daemon/internal/adapters/api/handlers_subscription_profiles.go#UpdateSubscriptionProfile`
- Acceptance evidence: `src/packages/control-ui/scripts/test-feature-promotions.mjs#checkProfilesRichness`
- Validation status: `statically-validated`
- Invariant: profile UI reflects the existing ProfileService state and exposes refresh/source-health/provider metadata without inventing a second state store
- Negative invariant: profile UI mutations go only through existing profile APIs and source health remains daemon-owned

### f5-007
**bounded QLOG/qlog-seq local trace parser and summary**

- Source semantic records: `SEM080`
- Disposition: `adapted`
- Target capability: local transport trace analysis
- Target nodes: `src/packages/control-ui/src/api/qlog.ts#parseTransportTrace`
- Acceptance evidence: `src/packages/control-ui/scripts/test-contracts.mjs#tooManyTraceEvents`
- Validation status: `verified`
- Invariant: local trace parsing accepts supported QLOG forms with explicit byte/event ceilings
- Negative invariant: trace parsing cannot allocate unbounded event collections or upload data implicitly

### f5-008
**Chrome NetLog normalization into the same trace model**

- Source semantic records: `SEM081`
- Disposition: `adapted`
- Target capability: local transport trace analysis
- Target nodes: `src/packages/control-ui/src/api/qlog.ts#eventFromNetlog;src/packages/control-ui/src/api/qlog.ts#reverseNumericConstants`
- Acceptance evidence: `src/packages/control-ui/scripts/test-contracts.mjs#netlog`
- Validation status: `verified`
- Invariant: NetLog events normalize into the same category/name/time/detail model as QLOG
- Negative invariant: NetLog normalization must remain bounded by the shared trace parser limits

### f5-009
**interactive QLOG/NetLog viewer with filters and category counts**

- Source semantic records: `SEM082`
- Disposition: `inspired-native`
- Target capability: transport trace visualization
- Target nodes: `src/packages/control-ui/src/pages/Operations.tsx#traceCategory;src/packages/control-ui/src/pages/Operations.tsx#traceQuery`
- Acceptance evidence: `src/packages/control-ui/scripts/test-feature-promotions.mjs#checkOperationsTraceFiltering`
- Validation status: `statically-validated`
- Invariant: operators can inspect large-but-bounded traces by category and text without leaving the control UI
- Negative invariant: viewer renders only a bounded subset and does not make local trace data authoritative

### f5-010
**installable PWA shell with offline static fallback**

- Source semantic records: `SEM042`
- Disposition: `adapted`
- Target capability: installable offline control shell
- Target nodes: `src/packages/control-ui/public/sw.js#isCacheableRequest;src/packages/control-ui/src/main.tsx#serviceWorker;src/packages/control-ui/public/manifest.webmanifest#standalone`
- Acceptance evidence: `src/packages/control-ui/scripts/test-pwa.mjs#PWA characterization`
- Validation status: `verified`
- Invariant: static shell remains launchable/offline and old shell caches are retired
- Negative invariant: API and websocket-like requests are never satisfied from the static shell cache

### f5-011
**confirmed provider/support external links from rich profile metadata**

- Source semantic records: `SEM044`
- Disposition: `adapted`
- Target capability: provider metadata actions
- Target nodes: `src/packages/control-ui/src/pages/Profiles.tsx#openProviderLink`
- Acceptance evidence: `src/packages/control-ui/scripts/test-feature-promotions.mjs#checkProfilesExternalLinkConfirmation`
- Validation status: `statically-validated`
- Invariant: provider support/home links can be opened directly from the profile workspace after an explicit user action
- Negative invariant: non-web schemes are not opened by this UI helper

## Product build boundary

- Control-UI contract/transport/PWA/promotion scripts execute under the available Node/TypeScript tools.
- The final Vite production bundle remains unbuilt in this environment because the exact lockfile dependency set is not locally cached and outbound registry DNS is unavailable. Source-level product promotion is therefore distinguished from packaged UI runtime verification.
