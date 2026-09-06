# Third-Wave Convergence Validation

This document binds each third-wave decision to its exact donor evidence, target owner, invariants, and validation status. Historical peer and second-order evidence remain immutable and are validated by their own gates.

### tw-sem001
**TW-SEM001 — modern Xray TLS share fields cs/ech/vcn/pcs**

- Donor/source: `PattNG` / `V2rayNG/app/src/main/java/com/v2ray/ang/fmt/FmtBase.kt` / `getItemFormQuery`
- Source SHA-256: `1725f65231734864801c3801f68e4043465d3afb52cc336fd1998eab70578833`
- Disposition: `adapted`; transformation `clean-room adaptation`; topology `one-to-many`
- Rationale: PattNG preserves modern Xray TLS fields that LumiNet previously dropped. Fields are rederived into the canonical target model.
- Target capability: proxy grammar
- Target node(s): `src/apps/daemon/internal/networking/proxyconfig/types.go#ProxyConfig;src/apps/daemon/internal/networking/proxyconfig/parser_vless.go#parseVLESS`
- Acceptance/decision evidence: `src/apps/daemon/internal/networking/proxyconfig/third_wave_contract_test.go#TestThirdWaveVLESSRoundTripPreservesModernXrayTLSAndFinalMask`
- Invariant: modern TLS share fields survive parsing and serialization
- Negative invariant: unsafe TLS intent is never silently converted to an insecure Xray setting
- Risk: `high`; evidence confidence: `high`
- Validation status: `verified`

### tw-sem002
**TW-SEM002 — HTML-escaped query normalization lesson**

- Donor/source: `PattNG-Config-Processor` / `index.html` / `processor`
- Source SHA-256: `3599ce47300469ad0850118869c32cf0bd6f89c9cc4b50750c0335c86bc740b9`
- Disposition: `inspired-native`; transformation `target-native hardening`; topology `negative-to-guardrail`
- Rationale: The unlicensed processor demonstrates real-world share-link normalization pressure. LumiNet adopts only the compatibility outcome, not source or hosted proxy behavior.
- Target capability: proxy grammar
- Target node(s): `src/apps/daemon/internal/networking/proxyconfig/types.go#ParseProxyURI`
- Acceptance/decision evidence: `src/apps/daemon/internal/networking/proxyconfig/third_wave_contract_test.go#TestThirdWaveVLESSRoundTripPreservesModernXrayTLSAndFinalMask`
- Invariant: share parsing tolerates canonical URL decoding without donor service dependency
- Negative invariant: do not copy or call the donor CORS proxy
- Risk: `medium`; evidence confidence: `high`
- Validation status: `verified`

### tw-sem003
**TW-SEM003 — FinalMask share field and JSON validation**

- Donor/source: `PattNG` / `V2rayNG/app/src/main/java/com/v2ray/ang/fmt/FmtBase.kt` / `finalMask`
- Source SHA-256: `1725f65231734864801c3801f68e4043465d3afb52cc336fd1998eab70578833`
- Disposition: `hardened`; transformation `clean-room hardening`; topology `one-to-one`
- Rationale: FinalMask is useful but raw share-controlled JSON requires a strict object and size boundary.
- Target capability: Xray FinalMask
- Target node(s): `src/apps/daemon/internal/networking/proxyconfig/finalmask.go#DecodeFinalMask`
- Acceptance/decision evidence: `src/apps/daemon/internal/networking/proxyconfig/third_wave_contract_test.go#TestThirdWaveFinalMaskValidationIsBoundedAndObjectOnly`
- Invariant: FinalMask JSON is object-only and <=16KiB
- Negative invariant: oversized or non-object JSON never reaches core configuration
- Risk: `high`; evidence confidence: `high`
- Validation status: `verified`

### tw-sem004
**TW-SEM004 — XHTTP host/path/mode/extra share grammar**

- Donor/source: `PattNG` / `V2rayNG/app/src/main/java/com/v2ray/ang/fmt/FmtBase.kt` / `xhttpMode`
- Source SHA-256: `1725f65231734864801c3801f68e4043465d3afb52cc336fd1998eab70578833`
- Disposition: `adapted`; transformation `clean-room adaptation`; topology `one-to-one`
- Rationale: PattNG exposes XHTTP link metadata. LumiNet preserves only bounded current XHTTP fields.
- Target capability: XHTTP share grammar
- Target node(s): `src/apps/daemon/internal/networking/proxyconfig/xhttp.go#CanonicalXHTTPTransport`
- Acceptance/decision evidence: `src/apps/daemon/internal/networking/proxyconfig/third_wave_contract_test.go#TestThirdWaveXHTTPShareRoundTripPreservesModeAndExtra`
- Invariant: xhttp and splithttp canonicalize to one transport contract
- Negative invariant: unknown modes or unbounded extra JSON fail closed
- Risk: `high`; evidence confidence: `high`
- Validation status: `verified`

### tw-sem005
**TW-SEM005 — XHTTP runtime settings**

- Donor/source: `PattNG` / `V2rayNG/app/src/main/java/com/v2ray/ang/core/CoreOutboundBuilder.kt` / `updateStreamSettings`
- Source SHA-256: `63f0a2b4b3cd0e3218cde089ea04c46e59b0a698f10ec867e6b31182e9dee4eb`
- Disposition: `adapted`; transformation `target-native adaptation`; topology `many-to-one`
- Rationale: The target core owner now emits the canonical XHTTP subset rather than merely retaining metadata.
- Target capability: Xray XHTTP runtime
- Target node(s): `src/apps/daemon/internal/runtime/proxy/core_manager.go#buildXrayOutbound;src/apps/daemon/internal/networking/proxyconfig/xhttp.go#BuildXrayXHTTPSettings`
- Acceptance/decision evidence: `src/apps/daemon/internal/networking/proxyconfig/third_wave_contract_test.go#TestThirdWaveBuildXrayXHTTPSettings`
- Invariant: XHTTP metadata reaches the Xray owner
- Negative invariant: non-Xray cores reject XHTTP rather than silently dropping it
- Risk: `high`; evidence confidence: `high`
- Validation status: `statically-validated`

### tw-sem006
**TW-SEM006 — Reality spiderX preservation**

- Donor/source: `PattNG` / `V2rayNG/app/src/main/java/com/v2ray/ang/fmt/FmtBase.kt` / `spiderX`
- Source SHA-256: `1725f65231734864801c3801f68e4043465d3afb52cc336fd1998eab70578833`
- Disposition: `adapted`; transformation `clean-room adaptation`; topology `one-to-one`
- Rationale: Reality spiderX is independently useful and fits the existing Reality owner.
- Target capability: Reality configuration
- Target node(s): `src/apps/daemon/internal/runtime/proxy/core_manager.go#buildXrayOutbound`
- Acceptance/decision evidence: `src/apps/daemon/internal/networking/proxyconfig/third_wave_contract_test.go#TestThirdWaveRealitySpiderXRoundTrip`
- Invariant: spiderX survives share parse and reaches Reality settings
- Negative invariant: sing-box never silently drops Xray-specific spiderX
- Risk: `medium`; evidence confidence: `high`
- Validation status: `statically-validated`

### tw-sem007
**TW-SEM007 — WireGuard pre-shared key preservation and core emission**

- Donor/source: `PattNG` / `V2rayNG/app/src/main/java/com/v2ray/ang/core/CoreOutboundBuilder.kt` / `wireguard`
- Source SHA-256: `63f0a2b4b3cd0e3218cde089ea04c46e59b0a698f10ec867e6b31182e9dee4eb`
- Disposition: `adapted`; transformation `clean-room adaptation`; topology `one-to-many`
- Rationale: PSK is standard WireGuard state and was already modeled but not fully preserved/emitted.
- Target capability: WireGuard peer security
- Target node(s): `src/apps/daemon/internal/runtime/proxy/core_manager.go#buildSingBoxOutbound;src/apps/daemon/internal/runtime/proxy/core_manager.go#buildXrayOutbound`
- Acceptance/decision evidence: `src/apps/daemon/internal/networking/proxyconfig/third_wave_contract_test.go#TestThirdWaveWireGuardPSKRoundTrip`
- Invariant: PSK survives import/export and reaches both compatible core owners
- Negative invariant: PSK is never silently discarded
- Risk: `high`; evidence confidence: `high`
- Validation status: `statically-validated`

### tw-sem008
**TW-SEM008 — purguard scheme collapses to WireGuard owner**

- Donor/source: `purvpn` / `links/purguard.txt` / `purguard://`
- Source SHA-256: `0d9c2362fe8fb1d9476fefc51e39632ed3154ea85a08926d5fb136f873c8f5b0`
- Disposition: `inspired-native`; transformation `grammar-derived native alias`; topology `many-to-one`
- Rationale: The corpus contains a purguard alias with WireGuard semantics. LumiNet maps the scheme into its existing WireGuard parser instead of introducing a new protocol authority.
- Target capability: WireGuard share grammar
- Target node(s): `src/apps/daemon/internal/networking/proxyconfig/parser_wg.go#parseWireGuard`
- Acceptance/decision evidence: `src/apps/daemon/internal/networking/proxyconfig/third_wave_contract_test.go#TestThirdWavePurguardIsWireGuardAliasAndPreservesPSK`
- Invariant: purguard aliases canonicalize to WireGuard and retain PSK
- Negative invariant: do not create a separate purguard runtime protocol
- Risk: `medium`; evidence confidence: `high`
- Validation status: `verified`

### tw-sem009
**TW-SEM009 — Hysteria2 obfs/ALPN/bandwidth/finalmask grammar**

- Donor/source: `PattNG` / `V2rayNG/app/src/main/java/com/v2ray/ang/fmt/FmtBase.kt` / `getItemFormQuery`
- Source SHA-256: `1725f65231734864801c3801f68e4043465d3afb52cc336fd1998eab70578833`
- Disposition: `adapted`; transformation `clean-room adaptation`; topology `many-to-one`
- Rationale: PattNG plus the corpus expose fields the target parser previously dropped.
- Target capability: Hysteria2 grammar
- Target node(s): `src/apps/daemon/internal/networking/proxyconfig/parser_hy2.go#parseHysteria2`
- Acceptance/decision evidence: `src/apps/daemon/internal/networking/proxyconfig/third_wave_contract_test.go#TestThirdWaveHysteria2RoundTripPreservesObservedCorpusFields`
- Invariant: observed Hysteria2 fields round-trip canonically
- Negative invariant: core-specific fields are not reinterpreted across cores
- Risk: `high`; evidence confidence: `high`
- Validation status: `verified`

### tw-sem010
**TW-SEM010 — bounded mport port-hopping grammar**

- Donor/source: `PattNG` / `V2rayNG/app/src/main/java/com/v2ray/ang/core/CoreOutboundBuilder.kt` / `udpHop`
- Source SHA-256: `63f0a2b4b3cd0e3218cde089ea04c46e59b0a698f10ec867e6b31182e9dee4eb`
- Disposition: `adapted`; transformation `clean-room adaptation`; topology `one-to-many`
- Rationale: Port hopping is valuable where the selected core has a native server_ports contract; Xray mapping requires explicit FinalMask policy.
- Target capability: Hysteria2 port hopping
- Target node(s): `src/apps/daemon/internal/networking/proxyconfig/hysteria2_fields.go#ParseHysteria2PortHopping`
- Acceptance/decision evidence: `src/apps/daemon/internal/networking/proxyconfig/third_wave_contract_test.go#TestThirdWaveHysteria2PortHoppingValidation`
- Invariant: at most 32 valid ports/ranges are accepted
- Negative invariant: mport is never expanded into an unbounded port set or guessed into Xray policy
- Risk: `high`; evidence confidence: `high`
- Validation status: `verified`

### tw-sem011
**TW-SEM011 — certificate-pin semantics remain core-specific**

- Donor/source: `purvpn` / `links/hysteria` / `pinSHA256`
- Source SHA-256: `cf1f384b4478bd93cf0a1fde1c73214a200e89e037589c8d3fbc846cc4900415`
- Disposition: `guardrail-derived`; transformation `negative-to-guardrail`; topology `many-to-one`
- Rationale: The corpus uses raw certificate pins. LumiNet retains that meaning for Xray and refuses to reinterpret it as sing-box public-key pinning.
- Target capability: certificate pin compatibility
- Target node(s): `src/apps/daemon/internal/networking/proxyconfig/core_compat.go#ValidateSingBoxCompatibility`
- Acceptance/decision evidence: `src/apps/daemon/internal/networking/proxyconfig/third_wave_contract_test.go#TestThirdWaveSingBoxCompatibilityRejectsXrayOnlyFields`
- Invariant: raw peer-certificate pins retain their certificate semantics
- Negative invariant: do not reinterpret certificate hashes as public-key hashes
- Risk: `high`; evidence confidence: `high`
- Validation status: `verified`

### tw-sem012
**TW-SEM012 — cross-core no-silent-drop guardrail**

- Donor/source: `PattNG` / `V2rayNG/app/src/main/java/com/v2ray/ang/core/CoreOutboundBuilder.kt` / `updateOutbound`
- Source SHA-256: `63f0a2b4b3cd0e3218cde089ea04c46e59b0a698f10ec867e6b31182e9dee4eb`
- Disposition: `synthesized`; transformation `target-native synthesis`; topology `many-to-many`
- Rationale: Donor breadth makes silent cross-core field loss visible. LumiNet adds one compatibility owner that rejects Xray-only fields under sing-box.
- Target capability: core compatibility
- Target node(s): `src/apps/daemon/internal/networking/proxyconfig/core_compat.go#ValidateSingBoxCompatibility;src/apps/daemon/internal/runtime/proxy/core_manager.go#buildSingBoxOutbound`
- Acceptance/decision evidence: `src/apps/daemon/internal/networking/proxyconfig/third_wave_contract_test.go#TestThirdWaveSingBoxCompatibilityRejectsXrayOnlyFields`
- Invariant: unsupported core-specific metadata fails before configuration generation
- Negative invariant: no parser success may imply silent runtime field loss
- Risk: `high`; evidence confidence: `high`
- Validation status: `statically-validated`

### tw-sem013
**TW-SEM013 — SNI length validation and exact TLS-record-header probe**

- Donor/source: `sni-spoofing-rust` / `src/scan.rs` / `scan_one`
- Source SHA-256: `2942c623314d455612c04be33352fdedae98fe608b6216c7dab38cdf8a688a05`
- Disposition: `adapted`; transformation `clean-room adaptation`; topology `one-to-one`
- Rationale: The Rust scanner validates SNI and uses the TLS record header as its probe oracle. LumiNet adopts a bounded equivalent in its existing diagnostics owner.
- Target capability: SNI diagnostic probe
- Target node(s): `src/apps/daemon/internal/analysis/diagnostics/sni_spoof_scan.go#probeFakeSNI`
- Acceptance/decision evidence: `src/apps/daemon/internal/analysis/diagnostics/sni_spoof_scan_test.go#TestProbeFakeSNIReadsExactTLSRecordHeader`
- Invariant: SNI is DNS-safe and <=219 bytes; success requires a complete five-byte TLS header
- Negative invariant: malformed names and short headers never count as success
- Risk: `medium`; evidence confidence: `high`
- Validation status: `verified`

### tw-sem014
**TW-SEM014 — fixed worker pool and 4096-candidate budget**

- Donor/source: `sni-spoofing-rust` / `src/scan.rs` / `scan_all`
- Source SHA-256: `2942c623314d455612c04be33352fdedae98fe608b6216c7dab38cdf8a688a05`
- Disposition: `hardened`; transformation `hardening over donor task model`; topology `one-to-one`
- Rationale: The donor semaphore bounds active work but can still create one task per candidate. LumiNet keeps a fixed worker pool and absolute candidate budget.
- Target capability: bounded SNI scheduling
- Target node(s): `src/apps/daemon/internal/analysis/diagnostics/sni_spoof_scan.go#RunSniSpoofScan`
- Acceptance/decision evidence: `src/apps/daemon/internal/analysis/diagnostics/sni_spoof_scan_test.go#TestRunSniSpoofScanCapsConcurrencyAndCandidateBudget`
- Invariant: diagnostic work is bounded in candidates and concurrent workers
- Negative invariant: never create unbounded goroutines for controlled candidate lists
- Risk: `high`; evidence confidence: `high`
- Validation status: `verified`

### tw-sem015
**TW-SEM015 — file-descriptor exhaustion gets longer bounded accept backoff**

- Donor/source: `sni-spoofing-rust` / `src/listener.rs` / `accept`
- Source SHA-256: `0fe8362e05970dd243fbb594af54d3657f2e4342defa64bbaf7caaffa01c05e4`
- Disposition: `adapted`; transformation `clean-room adaptation into shared target helper`; topology `many-to-one`
- Rationale: The donor distinguishes EMFILE/ENFILE from ordinary accept errors. The target shared helper is the stronger owner.
- Target capability: accept-loop recovery
- Target node(s): `src/apps/daemon/internal/runtime/proxy/accept_backoff.go#acceptBackoffForError`
- Acceptance/decision evidence: `src/apps/daemon/internal/runtime/proxy/accept_backoff_test.go#TestAcceptBackoffForErrorDistinguishesFDExhaustion`
- Invariant: fd exhaustion backs off longer while remaining cancellation-aware
- Negative invariant: accept loops do not busy-spin on resource exhaustion
- Risk: `medium`; evidence confidence: `high`
- Validation status: `verified`

### tw-sem016
**TW-SEM016 — JoinSet task drain on listener shutdown**

- Donor/source: `sni-spoofing-rust` / `src/listener.rs` / `JoinSet`
- Source SHA-256: `0fe8362e05970dd243fbb594af54d3657f2e4342defa64bbaf7caaffa01c05e4`
- Disposition: `reference-only`; transformation `reference comparison`; topology `one-to-one`
- Rationale: Draining active tasks is attractive, but target connection handlers lack one uniform bounded cancellation contract; unconditional drain could hang shutdown.
- Target capability: future connection-task drain
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: future drain requires bounded handler cancellation
- Negative invariant: do not block daemon shutdown indefinitely
- Risk: `high`; evidence confidence: `high`
- Validation status: `reviewed`

### tw-sem017
**TW-SEM017 — full packet/sniffer/SNI rewrite proxy plane**

- Donor/source: `sni-spoofing-rust` / `src/proxy.rs` / `Proxy`
- Source SHA-256: `4bc4d558fb76880da3db7297b98fc3fffac401f51869213532104995a319cc72`
- Disposition: `superseded`; transformation `comparison against target owner`; topology `many-to-one`
- Rationale: LumiNet already owns SNI mutation/fragment/padding in its evasion tunnel; another packet/sniffer plane would duplicate network authority.
- Target capability: SNI evasion runtime
- Target node(s): `src/apps/daemon/internal/runtime/proxy/evasion_tunnel.go#EvasionTunnelManager`
- Acceptance/decision evidence: `n/a`
- Invariant: one target runtime owner controls SNI mutation
- Negative invariant: do not add a second packet/sniffer proxy authority
- Risk: `high`; evidence confidence: `high`
- Validation status: `reviewed`

### tw-sem018
**TW-SEM018 — Android underlying-network monitor/rebind**

- Donor/source: `PattNG` / `V2rayNG/app/src/main/java/com/v2ray/ang/service/NetworkMonitor.kt` / `NetworkMonitor`
- Source SHA-256: `ab86fff0f5609cd12aa93c2198b09805988e4e20c7171ef9b3493fbb8e6c5480`
- Disposition: `reference-only`; transformation `comparison`; topology `one-to-one`
- Rationale: Useful mobile lifecycle reference, but LumiNet VPNEngine lacks a safe underlying-network rebind/reload authority.
- Target capability: mobile network rebind
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: target authority remains singular
- Negative invariant: do not mutate underlying network without a target-owned VPN lifecycle contract
- Risk: `high`; evidence confidence: `high`
- Validation status: `reviewed`

### tw-sem019
**TW-SEM019 — WorkManager subscription updater**

- Donor/source: `PattNG` / `V2rayNG/app/src/main/java/com/v2ray/ang/handler/SubscriptionUpdater.kt` / `SubscriptionUpdater`
- Source SHA-256: `c180cd5679c8e19d3ee2280d1d47e1fc24ad942a1ebefc5adbf95f95620e1ccc`
- Disposition: `superseded`; transformation `comparison`; topology `one-to-one`
- Rationale: Second-order ProfileService already owns durable source health and auto-refresh; donor scheduling would create a second authority.
- Target capability: subscription source health
- Target node(s): `src/apps/daemon/internal/integrations/sub/profile_service.go#ProfileService`
- Acceptance/decision evidence: `n/a`
- Invariant: target authority remains singular
- Negative invariant: do not add a parallel scheduler
- Risk: `high`; evidence confidence: `high`
- Validation status: `reviewed`

### tw-sem020
**TW-SEM020 — automatic certificate fingerprint discovery**

- Donor/source: `PattNG` / `V2rayNG/app/src/main/java/com/v2ray/ang/handler/CertificateFingerprintManager.kt` / `CertificateFingerprintManager`
- Source SHA-256: `ea4ed8e6ce367d3675df085caa66cc8b9dcb62954129bd71e9122acfb7596ec6`
- Disposition: `reference-only`; transformation `comparison`; topology `one-to-one`
- Rationale: Automatic first-seen pin adoption is TOFU and would create certificate trust authority without explicit approval.
- Target capability: certificate pin onboarding
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: target authority remains singular
- Negative invariant: do not auto-trust first-seen certificates
- Risk: `high`; evidence confidence: `high`
- Validation status: `reviewed`

### tw-sem021
**TW-SEM021 — application self-update checker**

- Donor/source: `PattNG` / `V2rayNG/app/src/main/java/com/v2ray/ang/handler/UpdateCheckerManager.kt` / `UpdateCheckerManager`
- Source SHA-256: `1982f65f01656c2fabf9312eeee52e4d401fa138c09dc4c8ca9ae6e30970a43e`
- Disposition: `rejected-with-reason`; transformation `comparison`; topology `one-to-one`
- Rationale: LumiNet still lacks a signed promotion/rollback authority for self-update.
- Target capability: future signed update plane
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: target authority remains singular
- Negative invariant: do not execute unsigned remote update promotion
- Risk: `high`; evidence confidence: `high`
- Validation status: `reviewed`

### tw-sem022
**TW-SEM022 — WebDAV backup plane**

- Donor/source: `PattNG` / `V2rayNG/app/src/main/java/com/v2ray/ang/handler/WebDavManager.kt` / `WebDavManager`
- Source SHA-256: `223b9f47b085f9486edc2801858e2d238a8bf5867bc251882318140faafce5d7`
- Disposition: `rejected-with-reason`; transformation `comparison`; topology `one-to-one`
- Rationale: WebDAV backup adds credential, remote-path and restore-integrity authority not justified by the current target.
- Target capability: future backup/restore
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: target authority remains singular
- Negative invariant: do not add remote backup without secret storage, integrity and rollback contracts
- Risk: `high`; evidence confidence: `high`
- Validation status: `reviewed`

### tw-sem023
**TW-SEM023 — Android ProcessService lifecycle plane**

- Donor/source: `PattNG` / `V2rayNG/app/src/main/java/com/v2ray/ang/service/ProcessService.kt` / `ProcessService`
- Source SHA-256: `07cbad98c188ef8decb57611168b20e9ff7cae751273fb8e9f722910e078a85e`
- Disposition: `superseded`; transformation `comparison`; topology `one-to-one`
- Rationale: The daemon already owns process lifecycle and introducing mobile donor supervision would duplicate process authority.
- Target capability: process lifecycle
- Target node(s): `src/apps/daemon/internal/integrations/sub/profile_service.go#ProfileService`
- Acceptance/decision evidence: `n/a`
- Invariant: target authority remains singular
- Negative invariant: one process owner remains authoritative
- Risk: `high`; evidence confidence: `high`
- Validation status: `reviewed`

### tw-sem024
**TW-SEM024 — donor Android product shell/root/LAN sharing**

- Donor/source: `PattNG` / `README.md` / `product shell`
- Source SHA-256: `3a81d64b6583be71d7005eb8b7b3bf3776683dfbb12e9c678e0dcf54ced6c14b`
- Disposition: `reference-only`; transformation `comparison`; topology `one-to-one`
- Rationale: UI/product breadth is useful context but not stronger than target owners and includes broad device authority.
- Target capability: mobile product reference
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: target authority remains singular
- Negative invariant: do not promote root/LAN authority from UI state
- Risk: `high`; evidence confidence: `high`
- Validation status: `reviewed`

### tw-sem025
**TW-SEM025 — public CORS proxy fetch pattern**

- Donor/source: `PattNG-Config-Processor` / `index.html` / `fetch`
- Source SHA-256: `3599ce47300469ad0850118869c32cf0bd6f89c9cc4b50750c0335c86bc740b9`
- Disposition: `rejected-with-reason`; transformation `negative-to-guardrail`; topology `one-to-one`
- Rationale: The public proxy pattern sends imported subscription URLs to a third party and creates a privacy/credential leak.
- Target capability: remote import privacy
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: subscription imports stay direct through target-owned bounded clients
- Negative invariant: never disclose private subscription URLs to a public CORS relay
- Risk: `high`; evidence confidence: `high`
- Validation status: `reviewed`

### tw-sem026
**TW-SEM026 — fixed FinalMask/cipher presets**

- Donor/source: `PattNG-Config-Processor` / `README.md` / `presets`
- Source SHA-256: `24b51e0987bb78e14dfa21ea872dc1c887f4bd260c7f9c70cb6cc1bb1b7b5221`
- Disposition: `reference-only`; transformation `reference`; topology `one-to-many`
- Rationale: Preset values are setup-specific and unlicensed; only field grammar/validation is useful.
- Target capability: configuration presets
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: operator-supplied settings remain explicit
- Negative invariant: do not transplant opaque fixed cryptographic/obfuscation presets
- Risk: `medium`; evidence confidence: `high`
- Validation status: `reviewed`

### tw-sem027
**TW-SEM027 — sanitized real-world proxy grammar corpus**

- Donor/source: `purvpn` / `README.md` / `corpus`
- Source SHA-256: `482c1d5e8fac3eaeb57cd4a488a0a160d27964c3ad422e7cca357451f68ee17b`
- Disposition: `extracted`; transformation `aggregate extraction`; topology `many-to-many`
- Rationale: Thousands of live share links expose grammar prevalence and malformed-key pressure. Only aggregate syntax counts are retained.
- Target capability: parser validation corpus
- Target node(s): `governance/convergence/third-wave-corpora.json#purvpn`
- Acceptance/decision evidence: `scripts/checks/check_third_wave_convergence.py#check_corpus`
- Invariant: corpus evidence contains counts and key names only
- Negative invariant: never retain raw endpoints, credentials, UUIDs or keys
- Risk: `high`; evidence confidence: `high`
- Validation status: `verified`

### tw-sem028
**TW-SEM028 — raw live endpoints/credentials/config payloads**

- Donor/source: `purvpn` / `links/link.txt` / `live share payloads`
- Source SHA-256: `29fe8be044e02126bcb80f7a5780e0a35b1b0219021707155ca32a805223ca5b`
- Disposition: `rejected-with-reason`; transformation `negative evidence`; topology `many-to-many`
- Rationale: Raw provider nodes and credentials are operationally sensitive and not needed for adopted grammar semantics.
- Target capability: secret minimization
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: only aggregate grammar evidence survives
- Negative invariant: never copy live donor endpoints or credentials into source/governance/release
- Risk: `critical`; evidence confidence: `high`
- Validation status: `reviewed`

### tw-sem029
**TW-SEM029 — insecure TLS compatibility flags in live corpus**

- Donor/source: `purvpn` / `links/link.txt` / `insecure/allowInsecure`
- Source SHA-256: `29fe8be044e02126bcb80f7a5780e0a35b1b0219021707155ca32a805223ca5b`
- Disposition: `rejected-with-reason`; transformation `negative-to-guardrail`; topology `many-to-one`
- Rationale: The corpus demonstrates legacy insecure flags but current target must not normalize those into automatic certificate-verification bypass.
- Target capability: secure TLS migration
- Target node(s): `src/apps/daemon/internal/networking/proxyconfig/xray_tls.go#BuildXrayTLSSettings`
- Acceptance/decision evidence: `src/apps/daemon/internal/networking/proxyconfig/third_wave_contract_test.go#TestThirdWaveBuildXrayTLSSettingsFailsClosed`
- Invariant: legacy insecure intent requires an explicit peer certificate pin for Xray
- Negative invariant: do not emit automatic Xray allowInsecure bypass
- Risk: `critical`; evidence confidence: `high`
- Validation status: `verified`

### tw-sem030
**TW-SEM030 — packetEncoding share field**

- Donor/source: `purvpn` / `links/link.txt` / `packetEncoding`
- Source SHA-256: `29fe8be044e02126bcb80f7a5780e0a35b1b0219021707155ca32a805223ca5b`
- Disposition: `reference-only`; transformation `reference`; topology `one-to-many`
- Rationale: Observed in the corpus but no agreed cross-core canonical mapping was established.
- Target capability: future packet encoding
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: future mapping must be explicit per core
- Negative invariant: do not silently reinterpret packetEncoding
- Risk: `medium`; evidence confidence: `high`
- Validation status: `reviewed`

### tw-sem031
**TW-SEM031 — sparse early-data ed/eh share fields**

- Donor/source: `purvpn` / `links/link.txt` / `ed/eh`
- Source SHA-256: `29fe8be044e02126bcb80f7a5780e0a35b1b0219021707155ca32a805223ca5b`
- Disposition: `reference-only`; transformation `reference`; topology `one-to-many`
- Rationale: Sparse evidence is insufficient to define one cross-core target contract.
- Target capability: future early-data grammar
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: future adoption requires explicit transport semantics
- Negative invariant: do not infer semantics solely from key names
- Risk: `low`; evidence confidence: `high`
- Validation status: `reviewed`

### tw-sem032
**TW-SEM032 — prebuilt platform binaries and bundles**

- Donor/source: `sni-spoofing-rust` / `releases/README.md` / `releases/*`
- Source SHA-256: `b750b7ed921181a97170c1259ff45d86e0297e3f30ca47dbd000079b41770010`
- Disposition: `reference-only`; transformation `artifact-only classification`; topology `one-to-many`
- Rationale: Prebuilt binaries are accounted as release evidence but are neither executed nor imported because source is available.
- Target capability: release evidence hygiene
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: source-level evidence drives adoption
- Negative invariant: do not import opaque peer binaries into target runtime/release
- Risk: `high`; evidence confidence: `high`
- Validation status: `reviewed`

### tw-sem033
**TW-SEM033 — remaining Android/UI/build/docs surfaces**

- Donor/source: `PattNG` / `README.md` / `repository remainder`
- Source SHA-256: `3a81d64b6583be71d7005eb8b7b3bf3776683dfbb12e9c678e0dcf54ced6c14b`
- Disposition: `reference-only`; transformation `exhaustive surface disposition`; topology `many-to-many`
- Rationale: Remaining PattNG surfaces add contextual product/build knowledge but no stronger target mechanism after independent decisions above.
- Target capability: donor context accountability
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: all donor surfaces remain traceable
- Negative invariant: do not equate donor breadth with live adoption
- Risk: `low`; evidence confidence: `high`
- Validation status: `reviewed`

### tw-sem034
**TW-SEM034 — remaining Rust CLI/UI/build/container/docs surfaces**

- Donor/source: `sni-spoofing-rust` / `README.md` / `repository remainder`
- Source SHA-256: `ed306e9e6250bed57bb75f6132e244f5bbb6f8f7e4f9f5ff4c2c2194cce44047`
- Disposition: `reference-only`; transformation `exhaustive surface disposition`; topology `many-to-many`
- Rationale: Remaining Rust surfaces provide context but add no stronger target mechanism after scanner/listener/proxy decisions.
- Target capability: donor context accountability
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: all donor surfaces remain traceable
- Negative invariant: do not equate packaging/UI breadth with runtime value
- Risk: `low`; evidence confidence: `high`
- Validation status: `reviewed`

### tw-sem035
**TW-SEM035 — remaining app/media/config surfaces**

- Donor/source: `purvpn` / `README.md` / `repository remainder`
- Source SHA-256: `482c1d5e8fac3eaeb57cd4a488a0a160d27964c3ad422e7cca357451f68ee17b`
- Disposition: `reference-only`; transformation `exhaustive surface disposition`; topology `many-to-many`
- Rationale: Remaining PurVPN surfaces are data/product context; live secrets/media are not target dependencies.
- Target capability: donor context accountability
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: all donor surfaces remain traceable
- Negative invariant: do not import live provider state or media as runtime authority
- Risk: `low`; evidence confidence: `high`
- Validation status: `reviewed`

### tw-sem036
**TW-SEM036 — remaining processor documentation/surface**

- Donor/source: `PattNG-Config-Processor` / `README.md` / `repository remainder`
- Source SHA-256: `24b51e0987bb78e14dfa21ea872dc1c887f4bd260c7f9c70cb6cc1bb1b7b5221`
- Disposition: `reference-only`; transformation `exhaustive surface disposition`; topology `many-to-many`
- Rationale: The tiny donor is fully accounted by the parser idea, CORS anti-pattern, preset rejection and contextual remainder.
- Target capability: donor context accountability
- Target node(s): `n/a`
- Acceptance/decision evidence: `n/a`
- Invariant: all donor surfaces remain traceable
- Negative invariant: do not add external processor service authority
- Risk: `low`; evidence confidence: `high`
- Validation status: `reviewed`

