# Sixth-order convergence validation

- Donors: 18
- ZIP members: 150
- File surfaces: 106
- Directories: 43
- Extracted declaration symbols: 792
- Semantic decisions: 28

### s6-001
**Tor circuit identity rotation without process reload**

- Donor: `Auto_Tor_IP_changer`
- Source: `Auto_Tor_IP_changer-master/autoTOR.py` / `change`
- Disposition: `adapted`
- Transformation: `target-native adaptation`; topology `one-to-many`
- Target: `Tor circuit operations`
- Target nodes: `src/apps/daemon/internal/runtime/runtimecore/tor_engine.go#rotateIdentity;src/apps/daemon/internal/runtime/runtimecore/manager.go#RotateTorIdentity;src/apps/daemon/internal/adapters/api/handlers_system_engines.go#RotateTorIdentity;src/packages/control-ui/src/pages/Operations.tsx#rotateTorIdentity`
- Acceptance evidence: `src/apps/daemon/internal/platform/system/tor_controller_newnym_test.go#TestSignalNewNymSendsBoundedControlCommand`
- Validation status: `verified`
- Rationale: The donor periodically reloads the Tor service to obtain a new public identity. LumiNet already owns a long-lived Tor process and SAFECOOKIE control plane, so the useful outcome is recomposed as SIGNAL NEWNYM through the active runtime owner rather than restarting Tor.
- Invariant: identity rotation targets the already-running Tor engine and leaves process ownership intact
- Negative invariant: rotation never starts or reloads Tor implicitly and existing streams are not falsely claimed to migrate

### s6-002
**v3 onion validation plus deterministic same-service proxy affinity and bounded reachability probe**

- Donor: `ahmia-crawler`
- Source: `ahmia-crawler-master/ahmia/ahmia/middlewares.py` / `ProxyMiddleware`
- Disposition: `recomposed`
- Transformation: `recomposition`; topology `many-to-one`
- Target: `bounded onion reachability diagnostics`
- Target nodes: `src/apps/daemon/internal/analysis/diagnostics/onion_probe.go#ValidOnionV3Host;src/apps/daemon/internal/analysis/diagnostics/onion_probe.go#StableProxyForOnion;src/apps/daemon/internal/analysis/diagnostics/onion_probe.go#ProbeOnion;src/apps/daemon/internal/adapters/api/handlers_tor_ops.go#ProbeOnionService`
- Acceptance evidence: `src/apps/daemon/internal/analysis/diagnostics/onion_probe_test.go#TestValidOnionV3HostAndStableAffinity`
- Validation status: `verified`
- Rationale: Ahmia validates v3 onions and pins the same onion service to the same proxy. LumiNet absorbs those semantics into a one-request diagnostic owner using its Tor SOCKS runtime, strict redirect policy, response ceilings, and deterministic proxy affinity instead of importing Scrapy middleware or a Tor fleet.
- Invariant: only valid v3 onion services are probed and a service deterministically retains one normalized SOCKS proxy for the request
- Negative invariant: probe depth, redirects, body bytes and request timeout remain bounded; it does not become an unbounded crawler

### s6-003
**bounded onion title, description and link metadata extraction**

- Donor: `ahmia-crawler`
- Source: `ahmia-crawler-master/ahmia/ahmia/spiders/onionspider.py` / `parse_item`
- Disposition: `extracted`
- Transformation: `primitive extraction and native reimplementation`; topology `many-to-one`
- Target: `bounded onion metadata diagnostics`
- Target nodes: `src/apps/daemon/internal/analysis/diagnostics/onion_probe.go#extractOnionHTMLMetadata;src/packages/control-ui/src/pages/Operations.tsx#torProbe`
- Acceptance evidence: `src/apps/daemon/internal/analysis/diagnostics/onion_probe_test.go#TestExtractOnionHTMLMetadataCountsOnlyV3OnionLinks`
- Validation status: `verified`
- Rationale: Ahmia extracts document metadata and onion links for indexing. LumiNet retains the operator-useful subset after the 64 KiB probe ceiling: compact title/meta-description plus v3-onion and same-service link counts, using standard-library parsing rather than importing the crawler/indexing stack.
- Invariant: metadata is derived only from the already-bounded text sample and entity-normalized before display
- Negative invariant: metadata extraction cannot trigger additional network requests, scripts, a DOM runtime or indexing side effects

### s6-004
**multi-run SNI stability and latency ranking**

- Donor: `RKh-SNI-Spoofing`
- Source: `RKh-SNI-Spoofing-main/RKh-SNI-Spoofing-v0.1.2.py` / `check`
- Disposition: `adapted`
- Transformation: `adaptation`; topology `one-to-one`
- Target: `SNI stability ranking`
- Target nodes: `src/apps/daemon/internal/analysis/diagnostics/sni_spoof_scan.go#RunSniSpoofStabilityScan;src/apps/daemon/internal/adapters/api/handlers_sni_spoof.go#RunSniSpoofScan;src/packages/control-ui/src/pages/Operations.tsx#runSNIStability`
- Acceptance evidence: `src/apps/daemon/internal/analysis/diagnostics/sni_spoof_scan_test.go#TestRunSniSpoofStabilityScanRanksStableLowLatencyCandidates`
- Validation status: `verified`
- Rationale: The donor repeats probes and ranks candidates by stability and latency. LumiNet ports that outcome into its existing bounded TLS-record SNI diagnostic, retaining cancellation, candidate ceilings and worker bounds while reporting outcome histograms.
- Invariant: rank uses repeated bounded probes, stability first and latency second, with deterministic tie-breaking
- Negative invariant: stability runs are capped and cannot bypass the existing SNI candidate/concurrency budget

### s6-005
**validated 285-candidate SNI corpus**

- Donor: `RKh-SNI-Spoofing`
- Source: `RKh-SNI-Spoofing-main/domains.txt` / `n/a`
- Disposition: `extracted`
- Transformation: `data extraction and normalization`; topology `one-to-one`
- Target: `curated SNI candidate data`
- Target nodes: `src/apps/daemon/internal/analysis/diagnostics/sni_candidates.go#CuratedSniCandidates;src/apps/daemon/internal/adapters/api/handlers_sni_spoof.go#defaultSniSpoofList;src/packages/control-ui/src/pages/Operations.tsx#loadSNICorpus`
- Acceptance evidence: `src/apps/daemon/internal/analysis/diagnostics/sni_candidates_test.go#TestCuratedSniCandidatesAreValidUniqueAndDefensiveCopy`
- Validation status: `verified`
- Rationale: The donor carries 319 candidate rows. After LumiNet grammar validation and case-insensitive deduplication, 285 unique candidates remain and are exposed through the existing SNI defaults endpoint rather than a second catalog.
- Invariant: the built-in corpus has exactly 285 unique candidates and every entry satisfies the same SNI grammar as runtime probes
- Negative invariant: callers receive a defensive copy and the corpus does not bypass runtime candidate ceilings

### s6-006
**VPN Gate discovery, filtering, ranking and SSTP handoff**

- Donor: `PowerShell-VPNGate`
- Source: `PowerShell-VPNGate-main/PowerShell-VPNGate.ps1` / `n/a`
- Disposition: `adapted`
- Transformation: `target-native provider adaptation`; topology `one-to-many`
- Target: `VPN Gate provider directory`
- Target nodes: `src/apps/daemon/internal/integrations/vpngate/client.go#Fetch;src/apps/daemon/internal/integrations/vpngate/client.go#Parse;src/apps/daemon/internal/adapters/api/handlers_vpngate.go#setupVPNGateRoutes;src/packages/control-ui/src/pages/Operations.tsx#loadVPNGate`
- Acceptance evidence: `src/apps/daemon/internal/integrations/vpngate/client_test.go#TestParseFiltersAndRanksServers`
- Validation status: `verified`
- Rationale: The donor downloads VPN Gate CSV data, lets the user choose geography and tries provider endpoints. LumiNet decomposes that into a bounded read-only provider adapter, deterministic ranking, and explicit SSTP handoff to the already-authoritative runtime engine.
- Invariant: catalog retrieval is bounded and ranking/filtering is deterministic before presenting SSTP metadata
- Negative invariant: the provider adapter never starts or mutates a tunnel; runtimecore remains the only SSTP lifecycle owner

### s6-007
**DNS UDP truncation fallback that forces TCP retry**

- Donor: `OrbotIPtProxy`
- Source: `OrbotIPtProxy-master/OrbotTun.go/dns.go` / `ReceiveTo`
- Disposition: `superseded`
- Transformation: `proven supersession with donor oracle`; topology `one-to-one`
- Target: `DNS TCP fallback`
- Target nodes: `src/apps/daemon/internal/networking/dns/dns_fallback.go#DNSUDPFallbackListener`
- Acceptance evidence: `src/apps/daemon/internal/networking/dns/dns_fallback_test.go#TestDNSUDPFallbackListenerReturnsTruncatedNoErrorResponse`
- Validation status: `verified`
- Rationale: Orbot uses a truncated DNS response to force clients onto TCP when UDP cannot be proxied. LumiNet already implements the same responsibility in a dedicated DNS owner; this wave adds a packet-contract test proving transaction/question retention, QR+TC, cleared RCODE, and zero answer/authority/additional counts.
- Invariant: fallback responses preserve the DNS transaction/question while forcing a standards-compatible TCP retry
- Negative invariant: fallback never fabricates answers or hides a DNS error as successful data

### s6-008
**legacy tun2socks packet-flow bridge**

- Donor: `OrbotIPtProxy`
- Source: `OrbotIPtProxy-master/OrbotTun.go/OrbotTun.go` / `StartSocks`
- Disposition: `superseded`
- Transformation: `comparison and supersession`; topology `many-to-one`
- Target: `TUN to SOCKS runtime`
- Target nodes: `src/apps/daemon/internal/platform/mobilehost/tun2socks_adapter.go#StartTun2Socks;src/apps/daemon/internal/platform/system/tun_router.go#TunRouterManager`
- Acceptance evidence: `src/apps/daemon/internal/platform/system/tun_router_test.go#TestTunRouterDNSFailureRollsBackRoutes`
- Validation status: `verified`
- Rationale: The donor exposes a narrow go-tun2socks packet bridge. LumiNet already has platform/mobilehost Tun2SocksAdapter plus system-level TUN routing, route rollback and socket-protection owners, so importing OrbotTun would create a second packet-routing authority with less lifecycle coverage.
- Invariant: TUN packet routing remains under target route/device lifecycle owners with rollback and mobile socket protection
- Negative invariant: no donor-shaped TUN bridge may bypass target route leases, shutdown or socket protection

### s6-009
**reviewable VLESS plus XHTTP devcontainer bundle generation**

- Donor: `g2rayXHTTPS`
- Source: `g2rayXHTTPS-master/.devcontainer/config.json` / `n/a`
- Disposition: `adapted`
- Transformation: `target-native template generation`; topology `one-to-many`
- Target: `VLESS XHTTP deployment template`
- Target nodes: `src/apps/daemon/internal/integrations/provision/devcontainer_vless.go#GenerateVLESSDevcontainer;src/apps/daemon/internal/adapters/api/handlers_provision.go#GenerateVLESSDevcontainer;src/packages/control-ui/src/pages/Operations.tsx#generateDevcontainer`
- Acceptance evidence: `src/apps/daemon/internal/integrations/provision/devcontainer_vless_test.go#TestGenerateVLESSDevcontainerUsesXHTTPAndPinnedVersion`
- Validation status: `verified`
- Rationale: The donor provides a static Codespaces/devcontainer deployment for Xray VLESS+XHTTP. LumiNet converts the useful setup outcome into a read-only generator with validated UUID/version/port/path/mode and amd64/arm64 packaging, fitting the target XHTTP vocabulary without hidden deployment side effects.
- Invariant: generation is deterministic from validated inputs and returns reviewable files without deploying them
- Negative invariant: template generation cannot mutate remote infrastructure or silently choose an unpinned Xray version

### s6-010
**subscription profile backup and restore UX**

- Donor: `nahan`
- Source: `nahan-main/_worker.js` / `exportConfig`
- Disposition: `adapted`
- Transformation: `product adaptation`; topology `one-to-one`
- Target: `profile portability`
- Target nodes: `src/packages/control-ui/src/pages/Profiles.tsx#exportProfiles;src/packages/control-ui/src/pages/Profiles.tsx#importProfiles`
- Acceptance evidence: `src/packages/control-ui/scripts/test-sixth-order-promotions.mjs#checks`
- Validation status: `verified`
- Rationale: Nahan exposes browser-side backup/restore. LumiNet already owns profile persistence and validation, so this value is promoted as bounded JSON export/import that calls the existing profile API and preserves mirrors/refresh controls rather than copying Worker/KV state.
- Invariant: export uses a versioned schema and import is capped by file size and entry count before existing profile API validation
- Negative invariant: browser import does not become a second persistent profile store or bypass daemon validation

### s6-011
**multi-user quota, usage, Telegram, PWA, update and dashboard plane**

- Donor: `nahan`
- Source: `nahan-main/_worker.js` / `getDashboardUI`
- Disposition: `superseded`
- Transformation: `comparison and decomposition`; topology `many-to-many`
- Target: `rich operator console`
- Target nodes: `src/packages/control-ui/src/pages/Profiles.tsx#Profiles;src/packages/control-ui/src/pages/Operations.tsx#Operations;src/packages/control-ui/public/sw.js#CACHE_NAME`
- Acceptance evidence: `src/packages/control-ui/scripts/test-feature-promotions.mjs#checks`
- Validation status: `verified`
- Rationale: Nahan bundles multi-user profiles, quota/expiry, activity, Telegram operations, update checks, PWA-like dashboard behavior and clean-IP/ECH controls into one Worker. Fifth-order LumiNet already exposes richer separated owners for Profiles, Operations, signed update admission/staging, PWA shell, provider health and Telegram deployment adapters; this wave only adds the missing portable profile backup/restore primitive.
- Invariant: operator features remain separated by target authority while preserving visible quota, source health, update and operational workflows
- Negative invariant: do not recreate a monolithic Worker/KV control plane or duplicate existing state owners

### s6-012
**anti-censorship technique taxonomy as live capability discovery**

- Donor: `awesome-anti-censorship`
- Source: `awesome-anti-censorship-master/README.md` / `n/a`
- Disposition: `inspired-native`
- Transformation: `inspired-native synthesis`; topology `many-to-one`
- Target: `circumvention capability catalog`
- Target nodes: `src/apps/daemon/internal/analysis/provider/circumvention_catalog.go#CircumventionCatalog;src/apps/daemon/internal/adapters/api/handlers_circumvention_catalog.go#setupCircumventionCatalogRoutes;src/packages/control-ui/src/pages/Operations.tsx#loadCircumventionCatalog`
- Acceptance evidence: `src/apps/daemon/internal/analysis/provider/circumvention_catalog_test.go#TestCircumventionCatalogHasUniqueIDsAndDefensiveTags`
- Validation status: `verified`
- Rationale: The list is valuable as a taxonomy rather than executable code. LumiNet converts the concepts into an inventory of capabilities operators can actually use today and explicitly labels reference-only families, avoiding stale outbound link lists.
- Invariant: catalog entries describe target-native/external/reference integration levels rather than claiming every listed technique is implemented
- Negative invariant: documentation evidence cannot grant runtime authority or invent an implementation

### s6-013
**privacy-tool taxonomy normalized into target capability discovery**

- Donor: `awesome-privacy`
- Source: `awesome-privacy-master/readme.md` / `n/a`
- Disposition: `inspired-native`
- Transformation: `inspired-native synthesis`; topology `many-to-one`
- Target: `circumvention capability catalog`
- Target nodes: `src/apps/daemon/internal/analysis/provider/circumvention_catalog.go#CircumventionCatalog`
- Acceptance evidence: `src/apps/daemon/internal/analysis/provider/circumvention_catalog_test.go#TestCircumventionCatalogHasUniqueIDsAndDefensiveTags`
- Validation status: `verified`
- Rationale: The privacy list contributes categorization and operator vocabulary. LumiNet maps only relevant network/privacy mechanisms onto the same target-native capability catalog instead of copying third-party product recommendations or stale URLs.
- Invariant: catalog vocabulary helps operators discover the target capabilities that actually exist
- Negative invariant: external project listings remain evidence/reference and are not represented as installed LumiNet features

### s6-014
**Tor ecosystem taxonomy recomposed with live Tor operations**

- Donor: `awesome-tor`
- Source: `awesome-tor-master/README.md` / `n/a`
- Disposition: `inspired-native`
- Transformation: `inspired-native synthesis`; topology `many-to-one`
- Target: `Tor operator capability discovery`
- Target nodes: `src/apps/daemon/internal/analysis/provider/circumvention_catalog.go#CircumventionCatalog;src/packages/control-ui/src/pages/Operations.tsx#rotateTorIdentity;src/packages/control-ui/src/pages/Operations.tsx#probeOnion`
- Acceptance evidence: `src/packages/control-ui/scripts/test-sixth-order-promotions.mjs#checks`
- Validation status: `verified`
- Rationale: The Tor list contributes ecosystem vocabulary and operational categories. LumiNet exposes the pieces it actually owns—Tor runtime, identity rotation and bounded onion diagnostics—while keeping unrelated tools as reference-level catalog items.
- Invariant: Tor capabilities shown to operators correspond to real target owners and diagnostic actions
- Negative invariant: the catalog does not claim third-party Tor ecosystem projects are bundled or installed

### s6-015
**Tor circuit rotation and onion-crawler operator affordances**

- Donor: `onion-route-proxy`
- Source: `onion-route-proxy-main/README.md` / `n/a`
- Disposition: `inspired-native`
- Transformation: `idea-to-native product derivation`; topology `many-to-one`
- Target: `Tor operations workspace`
- Target nodes: `src/packages/control-ui/src/pages/Operations.tsx#rotateTorIdentity;src/packages/control-ui/src/pages/Operations.tsx#probeOnion;src/apps/daemon/internal/analysis/provider/circumvention_catalog.go#CircumventionCatalog`
- Acceptance evidence: `src/packages/control-ui/scripts/test-sixth-order-promotions.mjs#checks`
- Validation status: `verified`
- Rationale: The repository is mostly aspirational product copy, but its circuit rotation/crawler/bridge/operator concepts align with real target seams. LumiNet realizes the defensible subset as explicit NEWNYM, bounded onion probe metadata and capability discovery in Operations rather than pretending to provide the donor browser/fingerprint/AI stack.
- Invariant: operator UI exposes only actions backed by target capabilities and labels reference techniques accurately
- Negative invariant: aspirational browser fingerprint randomization, AI page analysis and bridge claims are not fabricated as shipped behavior

### s6-016
**hourly random-content commit workflow**

- Donor: `onion-route-proxy`
- Source: `onion-route-proxy-main/.github/workflows/rCDIRHslpXrK.yml` / `n/a`
- Disposition: `rejected-with-reason`
- Transformation: `negative-to-guardrail`; topology `one-to-one`
- Target: `repository mutation guardrail`
- Target nodes: `scripts/checks/check_sixth_order_convergence.py#main`
- Acceptance evidence: `scripts/checks/check_sixth_order_convergence.py#main`
- Validation status: `verified`
- Rationale: The workflow mutates repository contents hourly with randomized commit messages and no product-state purpose. It adds repository churn rather than runtime/user value and is explicitly not absorbed.
- Invariant: convergence must not add scheduled random repository mutation or synthetic activity generation
- Negative invariant: no write-enabled cron may be introduced merely to manufacture commits/activity

### s6-017
**multi-server multi-port multi-user management panel concept**

- Donor: `VUMP-limited`
- Source: `VUMP-limited-master/README.md` / `n/a`
- Disposition: `superseded`
- Transformation: `comparison and supersession`; topology `many-to-one`
- Target: `profile and runtime management`
- Target nodes: `src/packages/control-ui/src/pages/Profiles.tsx#Profiles;src/packages/control-ui/src/pages/Operations.tsx#Operations`
- Acceptance evidence: `src/packages/control-ui/scripts/test-feature-promotions.mjs#checks`
- Validation status: `verified`
- Rationale: VUMP contains a management-panel concept but no implementation. LumiNet already has richer profile management, runtime engines, mirrors/health/quota metadata and operator workspaces, so the concept is fully covered without importing a parallel panel.
- Invariant: one target profile/runtime model drives the management UI
- Negative invariant: do not create a second donor-shaped server/user database for the same operator outcome

### s6-018
**Buffer/ArrayBuffer/typed-array compatibility polyfill**

- Donor: `node-typedarray`
- Source: `node-typedarray-master/lib/node-typedarray.js` / `ArrayBufferToBuffer`
- Disposition: `superseded`
- Transformation: `comparison and supersession`; topology `one-to-one`
- Target: `native byte-array runtime`
- Target nodes: `src/packages/control-ui/package.json#typescript;src/apps/daemon/internal/adapters/api/websocket.go#Client`
- Acceptance evidence: `scripts/checks/check_sixth_order_convergence.py#main`
- Validation status: `verified`
- Rationale: The donor patches global Buffer/Array/typed-array behavior for an old Node/browser compatibility era. LumiNet targets modern browser/TypeScript and Go byte slices; importing global prototype mutations would add compatibility debt without user functionality.
- Invariant: byte handling uses the platform/runtime primitives already supported by target toolchains
- Negative invariant: no global Array or Buffer prototype polyfill from the donor may be injected into control-ui runtime

### s6-019
**legacy handwritten WebSocket framing and handshake**

- Donor: `websocket`
- Source: `websocket-master/lib/websocket.js` / `websocket_answer`
- Disposition: `superseded`
- Transformation: `comparison and supersession`; topology `many-to-one`
- Target: `WebSocket transport`
- Target nodes: `src/apps/daemon/internal/adapters/api/websocket.go#Client;src/packages/control-ui/src/api/ControlTransport.ts#ControlTransport`
- Acceptance evidence: `src/apps/daemon/internal/adapters/api/websocket_session_test.go#TestHubRegistersOnlyAuthenticatedWebSocketClients`
- Validation status: `verified`
- Rationale: The donor implements handshake/framing manually on top of old Node Buffers. LumiNet already owns authenticated daemon WebSockets through gorilla/websocket and browser transport contracts with session tests, so the donor stack is strictly shallower.
- Invariant: WebSocket framing/handshake remains delegated to maintained target/runtime libraries and existing session authority
- Negative invariant: no second manual WebSocket protocol implementation is added

### s6-020
**HTML entity/text normalization insight for bounded onion metadata**

- Donor: `node-dom`
- Source: `node-dom-master/lib/browser/htmlencoding.js` / `HTMLDecode`
- Disposition: `inspired-native`
- Transformation: `concept extraction using native primitive`; topology `many-to-one`
- Target: `bounded onion metadata normalization`
- Target nodes: `src/apps/daemon/internal/analysis/diagnostics/onion_probe.go#compactHTMLText`
- Acceptance evidence: `src/apps/daemon/internal/analysis/diagnostics/onion_probe_test.go#TestExtractOnionHTMLMetadataCountsOnlyV3OnionLinks`
- Validation status: `verified`
- Rationale: The legacy DOM package contains a broad entity table/decoder. The useful tiny semantic is entity-normalized metadata text; LumiNet implements it with Go standard-library html.UnescapeString inside the already-bounded onion sample instead of importing the table or DOM runtime.
- Invariant: title/description text is compacted and HTML entities are normalized after the network byte ceiling
- Negative invariant: the legacy DOM/entity tables are not copied and normalization cannot execute document scripts

### s6-021
**full server-side browser DOM/CSS/script emulation**

- Donor: `node-dom`
- Source: `node-dom-master/lib/browser/index.js` / `HTMLDocument`
- Disposition: `superseded`
- Transformation: `comparison and supersession`; topology `many-to-one`
- Target: `browser UI plus bounded text parsing`
- Target nodes: `src/packages/control-ui/src/App.tsx#App;src/apps/daemon/internal/analysis/diagnostics/onion_probe.go#extractOnionHTMLMetadata`
- Acceptance evidence: `scripts/checks/check_sixth_order_convergence.py#main`
- Validation status: `verified`
- Rationale: The donor emulates a large browser DOM, style system, dynamic NodeLists, XHR and script execution. LumiNet does not need a second browser runtime for bounded network diagnostics; real UI runs in the browser and onion metadata intentionally avoids script/DOM execution.
- Invariant: browser execution stays in the real UI runtime while daemon diagnostics parse only bounded inert metadata
- Negative invariant: daemon diagnostics must not execute fetched page scripts or instantiate a donor DOM runtime

### s6-022
**legacy web extraction fixtures and parsing outcome**

- Donor: `node-gadgets`
- Source: `node-gadgets-master/lib/gadgets.js` / `n/a`
- Disposition: `inspired-native`
- Transformation: `inspiration and supersession`; topology `many-to-one`
- Target: `bounded web metadata extraction`
- Target nodes: `src/apps/daemon/internal/analysis/diagnostics/onion_probe.go#extractOnionHTMLMetadata`
- Acceptance evidence: `src/apps/daemon/internal/analysis/diagnostics/onion_probe_test.go#TestExtractOnionHTMLMetadataCountsOnlyV3OnionLinks`
- Validation status: `verified`
- Rationale: The donor demonstrates extracting structured web content through a browser-emulation stack and carries a sizeable test fixture. LumiNet absorbs only the diagnostic outcome—bounded inert metadata/link extraction—and keeps the donor fixture as provenance evidence rather than executing gadget code.
- Invariant: metadata extraction is bounded, deterministic and non-executing
- Negative invariant: no arbitrary gadget/page JavaScript is executed as part of diagnostics

### s6-023
**legacy gadget/browser execution subsystem**

- Donor: `node-gadgets`
- Source: `node-gadgets-master/lib/gadgets.js` / `n/a`
- Disposition: `superseded`
- Transformation: `comparison and supersession`; topology `one-to-one`
- Target: `browser execution boundary`
- Target nodes: `src/packages/control-ui/src/App.tsx#App`
- Acceptance evidence: `scripts/checks/check_sixth_order_convergence.py#main`
- Validation status: `verified`
- Rationale: The full gadget loader depends on the obsolete node-dom execution model. Target diagnostics deliberately avoid arbitrary remote script execution and the real control UI already has a browser runtime, so no second execution environment is justified.
- Invariant: only the actual control UI browser executes UI JavaScript; fetched diagnostic content is inert
- Negative invariant: diagnostic fetches must not execute arbitrary remote gadget scripts

### s6-024
**legacy search/extract bot server and fixture corpus**

- Donor: `node-bot`
- Source: `node-bot-master/lib/bot.js` / `n/a`
- Disposition: `superseded`
- Transformation: `comparison and supersession`; topology `one-to-many`
- Target: `bounded provider and onion diagnostics`
- Target nodes: `src/apps/daemon/internal/analysis/diagnostics/onion_probe.go#ProbeOnion;src/apps/daemon/internal/integrations/vpngate/client.go#Fetch`
- Acceptance evidence: `scripts/checks/check_sixth_order_convergence.py#main`
- Validation status: `verified`
- Rationale: The donor wraps old DOM/gadget extraction into a search/bot pipeline. LumiNet now has focused provider discovery, Tor onion probing and explicit capability catalogs; importing a general unbounded bot/crawler would duplicate responsibilities without improving the target operator workflow.
- Invariant: network discovery remains capability-specific and bounded by the target owner
- Negative invariant: no generic donor crawler is granted open-ended fetch or execution authority

### s6-025
**browser/Node JavaScript TLS implementation and transport abstraction**

- Donor: `abstract-tls`
- Source: `abstract-tls-master/lib/abstract-tls.js` / `abstract_tls`
- Disposition: `superseded`
- Transformation: `comparison and supersession`; topology `many-to-one`
- Target: `native TLS transport stack`
- Target nodes: `src/apps/daemon/internal/platform/system/http_client_config.go#NewHTTPClientManager;src/apps/daemon/internal/analysis/diagnostics/sni_spoof_scan.go#buildFakeClientHello`
- Acceptance evidence: `scripts/checks/check_sixth_order_convergence.py#main`
- Validation status: `verified`
- Rationale: The donor implements TLS records/ciphers/cert handling in old JavaScript and even contains a verification TODO/bypass. LumiNet already uses Go crypto/tls and Xray/sing-box transport owners with current TLS/ECH/pinning semantics, so importing this stack would be a regression in functionality and interoperability.
- Invariant: TLS protocol ownership remains in native libraries/core transports while LumiNet only implements narrowly required diagnostic record construction
- Negative invariant: no duplicate general-purpose JavaScript TLS stack or verification-bypass behavior is introduced

### s6-026
**automatic apt-based Tor installer**

- Donor: `Auto_Tor_IP_changer`
- Source: `Auto_Tor_IP_changer-master/install.py` / `n/a`
- Disposition: `superseded`
- Transformation: `comparison and supersession`; topology `one-to-one`
- Target: `Tor dependency discovery`
- Target nodes: `src/apps/daemon/internal/runtime/runtimecore/capability.go#ProbeEngine;src/packages/control-ui/src/pages/Operations.tsx#engines`
- Acceptance evidence: `src/packages/control-ui/scripts/test-feature-promotions.mjs#checks`
- Validation status: `verified`
- Rationale: The donor installs Tor through apt with sudo. LumiNet already exposes engine capability discovery and explicit binary availability/path to the operator; silently mutating the host package manager would be a separate installation authority and is not necessary to absorb the useful Tor feature.
- Invariant: operators can see whether the Tor binary exists and where it was found before trying to start it
- Negative invariant: runtime start does not silently invoke a package manager or require sudo installation side effects

### s6-027
**distributed Tor fleet crawler, depth scheduling, PageRank and Elasticsearch indexing**

- Donor: `ahmia-crawler`
- Source: `ahmia-crawler-master/ahmia/ahmia/spiders/onionspider.py` / `compute_pagerank`
- Disposition: `reference-only`
- Transformation: `comparison and decomposition`; topology `one-to-many`
- Target: `future bounded onion discovery/indexing`
- Target nodes: `n/a`
- Acceptance evidence: `n/a`
- Validation status: `reviewed`
- Rationale: Ahmia carries a materially larger crawler/indexing plane: multi-page traversal, per-domain limits, Tor proxy fleet, authority/PageRank calculation and Elasticsearch persistence. LumiNet absorbs the independently useful validation/affinity/metadata primitives but does not currently have a search-index product requiring the full persistent crawler.
- Invariant: the crawler remains useful reference for any future search/index product and its independent primitives are already extracted
- Negative invariant: do not claim that a single bounded onion probe is equivalent to Ahmia crawling/PageRank/indexing

### s6-028
**URI/YAML profile generation, clean-IP/ECH and per-user profile presentation**

- Donor: `nahan`
- Source: `nahan-main/_worker.js` / `getAllProfiles`
- Disposition: `superseded`
- Transformation: `comparison and recomposition`; topology `many-to-many`
- Target: `canonical proxy/profile grammar`
- Target nodes: `src/apps/daemon/internal/networking/proxyconfig/types.go#ParseProxyURI;src/apps/daemon/internal/networking/proxyconfig/types.go#ToURI;src/packages/control-ui/src/pages/Profiles.tsx#Profiles`
- Acceptance evidence: `scripts/checks/check_sixth_order_convergence.py#main`
- Validation status: `verified`
- Rationale: Nahan generates user-specific URI/YAML profiles over clean IPs and exposes ECH/transport toggles. LumiNet already has the canonical proxy grammar, provider/clean-IP owners, ECH/TLS fields and rich subscription Profiles surface; importing Worker-specific serializers would create a second configuration grammar.
- Invariant: one canonical target grammar owns parse/serialize semantics across supported protocols
- Negative invariant: provider-specific profile generation does not create a second URI/schema authority
