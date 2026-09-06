# LumiNet ultimate peer-convergence synthesis

## Scope and decision

This release layers 20 newly supplied peer archives onto the frozen all-43 LumiNet release, while preserving and revalidating the earlier evidence chain. The cumulative convergence now accounts for **63 donors**, **8,223 donor file/symlink surfaces**, **1,594 directories**, **571 bounded module groups**, **18,098 parsed symbols/declarations**, and **662 adoption records**. The current wave contains 239 outer ZIP members plus one independently opened nested Lambda member, 183 logical donor surfaces, 22 fine-grained semantic decisions, 13 target repairs, and 41 exact target-delta paths at report generation time.

The convergence rule remains target-native: peer repositories are evidence. A whole donor is never imported merely because it contains useful behavior. Value is split into independently selectable mechanisms, compared to current LumiNet owners, then adapted, hardened, retained as reference evidence, converted into a guardrail, superseded, or rejected. Copyleft/no-license code is not silently copied into the target.

## Delivered architecture changes

### 1. Tor pluggable-transport plane
LumiNet no longer models bridges as an obfs4-only special case. The canonical torrc builder now accepts bounded typed transport plugins and bridge lines, while the live engine API is deliberately narrower: only registered **obfs4, Snowflake, and WebTunnel client transports** may be requested. Untrusted API data cannot select arbitrary executable paths or arbitrary flags. Executables are canonicalized and resolved before replacement authority is acquired, so a missing transport binary cannot stop a healthy running Tor engine. The production Tor process publishes the validated torrc, uses `AvoidDiskWrites 1`, and no longer emits GeoIP paths into a fresh temporary directory where the files do not exist.

### 2. Encrypted-DNS/Tor diagnostic plane
The no-license DoT-over-Tor donor is used only as conceptual evidence. LumiNet independently implements strict DNS-over-TLS with authenticated server names, TLS 1.2+, port/deadline validation, direct or SOCKS raw dialing, and fail-closed proxy handling. DoH proxy misconfiguration no longer falls back direct. A read-only Tor DNSEL API distinguishes `exit`, `not_exit`, and `unknown`; resolver failure is never converted into false negative evidence, and the live diagnostic uses encrypted DNS, optionally through the active Tor SOCKS engine.

### 3. Atomic filesystem observation
The filesystem-watch value was moved into the actual reusable system primitive rather than left in a donor-shaped helper. The watcher observes parent directories so atomic temp-file rename publication remains visible, filters to exact targets, debounces bursts, bounds backend-error delivery, and survives repeated replacements. The runtime proxy watcher delegates to this owner. Watching does **not** become configuration-reconciliation authority: there is still no promoted automatic runtime reconfiguration owner, avoiding split-brain state.

### 4. Endpoint and TLS evidence
Mullvad endpoint-selection evidence produced a bounded measurement primitive that preserves partial loss, uses median successful RTT, adjacent-sample jitter, and deterministic loss-first comparison. RealiTLScanner evidence enriches verified TLS peer metadata with issuer, chain count/bytes, signature algorithm, and public-key algorithm. These are deliberately **evidence primitives**, not falsely advertised as live route-selection authority.

### 5. Existing mutation resilience retained
The previous provider-scoped automatic mutation retry plane remains authoritative and was revalidated unchanged under the race detector. This wave did not introduce a competing retry loop. Action safety classes, provider cooldown, bounded in-flight coordination, fail-closed capacity, jittered local backoff, exact `Retry-After`, reconciliation-before-replay, cancellation, and secret-free telemetry remain intact.

## New donor-by-donor disposition

| Donor | Members | Surfaces | License posture | Final semantic disposition |
|---|---|---|---|---|
| fswatch-main | 15 | 12 | GPL-3.0-or-later | hardened: atomic-replacement-safe exact-path watching |
| mullvad-browser-main | 14 | 9 | MPL-2.0 (README claim; archive lacks license file) | reference-only: anti-fingerprinting product-role reference |
| onionsphinkter-production | 19 | 13 | no explicit license | guardrail-derived: unbounded/weak-auth side-effect queue counterexample |
| php-proxy-app-master | 18 | 13 | MIT | rejected-with-reason: open-proxy/SSRF role mismatch guardrail |
| dns_over_tls_over_tor-master | 8 | 7 | no explicit license | inspired-native: strict DNS-over-TLS optionally through Tor/SOCKS |
| the-onion-diaries-master | 4 | 3 | no explicit license | reference-only: hidden-service/server deployment reference |
| ptnettools-main | 10 | 9 | CC0-1.0 | adapted: obfs4 client transport is data, not a hard-coded torrc special case; adapted: Snowflake client transport support; adapted: WebTunnel client transport support |
| fptn-manager-master | 5 | 4 | MIT | reference-only: FPTN deployment/transport experimentation reference |
| RealiTLScanner-main | 11 | 10 | MPL-2.0 | extracted: richer verified TLS peer evidence |
| tor.rb-master | 31 | 25 | Unlicense/public domain | adapted: tri-state Tor DNSEL exit evidence |
| MullvadVPN-Tricks-main | 10 | 9 | GPL-3.0 | guardrail-derived: fail-closed lifecycle lesson |
| torget-main | 6 | 5 | GPL-3.0 | superseded: SOCKS-auth circuit-isolation reference |
| iptables-mod-randmap-master | 14 | 10 | GPL-2.0 | rejected-with-reason: kernel NAT randomization authority rejection |
| tor-relay-bootstrap-master | 17 | 9 | GPL-3.0 | rejected-with-reason: root relay bootstrap role mismatch |
| aces-main | 15 | 11 | BSD-like US Government permissive | reference-only: encrypted evidence-stream concept |
| tor_box-master | 4 | 3 | no explicit license | rejected-with-reason: Tor relay/install script role mismatch |
| mullvad-closest-main | 12 | 10 | Unlicense/public domain | extracted: loss-aware robust endpoint quality scoring |
| bldfrm-vpn-main | 2 | 1 | no explicit license | reference-only: promotional/documentation-only peer |
| smart-vpn-ec2-manager-main | 8 | 8 | no explicit license | reference-only: auto-stop cloud lease concept |
| mullvad-proxy-main | 16 | 12 | no explicit license | rejected-with-reason: blanket firewall/gateway mutation counterexample |

## Fine-grained semantic decisions

| ID | Donor | Value unit | Disposition | Target capability | Validation |
|---|---|---|---|---|---|
| U-S001 | fswatch-main | atomic-replacement-safe exact-path watching | hardened | configuration observation | verified |
| U-S002 | ptnettools-main | obfs4 client transport is data, not a hard-coded torrc special case | adapted | Tor client bridge configuration | verified |
| U-S003 | ptnettools-main | Snowflake client transport support | adapted | Tor client bridge configuration | verified |
| U-S004 | ptnettools-main | WebTunnel client transport support | adapted | Tor client bridge configuration | verified |
| U-S005 | dns_over_tls_over_tor-master | strict DNS-over-TLS optionally through Tor/SOCKS | inspired-native | encrypted DNS resolution | statically-validated |
| U-S006 | tor.rb-master | tri-state Tor DNSEL exit evidence | adapted | Tor diagnostic evidence | verified |
| U-S007 | mullvad-closest-main | loss-aware robust endpoint quality scoring | extracted | endpoint quality evidence | verified |
| U-S008 | RealiTLScanner-main | richer verified TLS peer evidence | extracted | scanner TLS evidence | verified |
| U-S009 | MullvadVPN-Tricks-main | fail-closed lifecycle lesson | guardrail-derived | runtime lifecycle guardrail | reviewed |
| U-S010 | mullvad-browser-main | anti-fingerprinting product-role reference | reference-only | n/a | reviewed |
| U-S011 | onionsphinkter-production | unbounded/weak-auth side-effect queue counterexample | guardrail-derived | remote mutation safety | reviewed |
| U-S012 | php-proxy-app-master | open-proxy/SSRF role mismatch guardrail | rejected-with-reason | API/proxy trust boundary | reviewed |
| U-S013 | the-onion-diaries-master | hidden-service/server deployment reference | reference-only | n/a | reviewed |
| U-S014 | iptables-mod-randmap-master | kernel NAT randomization authority rejection | rejected-with-reason | host network authority | reviewed |
| U-S015 | tor-relay-bootstrap-master | root relay bootstrap role mismatch | rejected-with-reason | Tor client/server role boundary | reviewed |
| U-S016 | tor_box-master | Tor relay/install script role mismatch | rejected-with-reason | Tor client/server role boundary | reviewed |
| U-S017 | torget-main | SOCKS-auth circuit-isolation reference | superseded | Tor client isolation | reviewed |
| U-S018 | fptn-manager-master | FPTN deployment/transport experimentation reference | reference-only | n/a | reviewed |
| U-S019 | aces-main | encrypted evidence-stream concept | reference-only | n/a | reviewed |
| U-S020 | smart-vpn-ec2-manager-main | auto-stop cloud lease concept | reference-only | n/a | reviewed |
| U-S021 | mullvad-proxy-main | blanket firewall/gateway mutation counterexample | rejected-with-reason | host network authority | reviewed |
| U-S022 | bldfrm-vpn-main | promotional/documentation-only peer | reference-only | n/a | reviewed |

## Higher-level plane decisions

| Plane | Representative donors | Disposition | Current owner | Residual gap |
|---|---|---|---|---|
| Tor client pluggable-transport plane | ptnettools-main | adopted-and-hardened | src/apps/daemon/internal/runtime/runtimecore/manager.go;src/apps/daemon/internal/runtime/runtimecore/adapters.go;src/apps/daemon/internal/platform/system/tor_config_builder.go | Actual PT binary execution cannot be exercised in this offline container; availability is fail-closed and package-harness verified. |
| encrypted DNS privacy plane | dns_over_tls_over_tor-master;tor.rb-master | inspired-native-and-hardened | src/apps/daemon/internal/networking/dns/resolver.go;src/apps/daemon/internal/analysis/diagnostics/tor_exit_check.go;src/apps/daemon/internal/adapters/api/handlers_tor_ops.go | Real upstream DoH/DoT exchanges are not executed in the offline/local-toolchain environment. |
| filesystem observation plane | fswatch-main | extracted-and-hardened | src/apps/daemon/internal/platform/system/file_watcher.go;src/apps/daemon/internal/runtime/proxy/config_watcher.go | No production config auto-reconciliation owner currently consumes the adapter; promotion remains intentionally dormant to avoid split-brain runtime state. |
| endpoint quality evidence plane | mullvad-closest-main;RealiTLScanner-main | extracted-not-promoted | src/apps/daemon/internal/runtime/proxy/node_latency_tester.go;src/apps/daemon/internal/analysis/scanner/probe_pipeline_utils.go | A live endpoint selector can consume the quality contract only after comparative production measurements and ownership review. |
| Tor server/relay plane | tor-relay-bootstrap-master;tor_box-master;the-onion-diaries-master | role-mismatch-reference | src/apps/daemon/internal/runtime/runtimecore/manager.go | No server/relay product plane is requested or safely owned by LumiNet. |
| browser anti-fingerprinting plane | mullvad-browser-main | reference-only | n/a | Network privacy does not provide browser-fingerprint protection; no false capability is advertised. |
| privileged firewall/NAT plane | iptables-mod-randmap-master;mullvad-proxy-main;MullvadVPN-Tricks-main | guardrail-derived | src/apps/daemon/internal/platform/system/host_network.go | Unix DNS-leak/firewall features remain unsupported until representable inside that transaction model. |
| ephemeral cloud/deployment lease plane | smart-vpn-ec2-manager-main;fptn-manager-master | reference-only | n/a | No new cloud deployment owner is introduced in this wave. |

## Target repairs

| Repair | Problem | Target nodes | Verification |
|---|---|---|---|
| U-R001 |  |  |  |
| U-R002 |  |  |  |
| U-R003 |  |  |  |
| U-R004 |  |  |  |
| U-R005 |  |  |  |
| U-R006 |  |  |  |
| U-R007 |  |  |  |
| U-R008 |  |  |  |
| U-R009 |  |  |  |
| U-R010 |  |  |  |
| U-R011 |  |  |  |
| U-R012 |  |  |  |
| U-R013 |  |  |  |

## Material non-adoptions

- **Tor relay/hidden-service bootstrap:** server/relay lifecycle is a different product role from LumiNet’s client Tor engine. Root-mutating relay installers are retained only as operational evidence.
- **Browser anti-fingerprinting:** the Mullvad Browser archive contains release/metadata surfaces rather than a browser implementation. LumiNet has no browser execution owner, so network privacy is not mislabeled as browser fingerprint protection.
- **Firewall/NAT/kill-switch scripts:** raw iptables/UFW/NAT mutation would bypass the transactional `HostNetworkChange` authority. These peers become guardrails only.
- **Generic PHP web proxy:** user-selected remote URLs create a product-role and SSRF/trust-boundary mismatch; no generic open-proxy plane is introduced.
- **Root/Docker/cloud bootstrap managers:** useful lease/auto-stop intent is retained as reference evidence, but hard-coded cloud identity, broad Docker/root mutation, and non-transactional teardown are not adopted.
- **Downloader/circuit utilities:** Tor downloading and relay utilities are superseded by the existing runtime Tor controller and diagnostic owners; no second Tor process/circuit authority is added.

## Source and provenance boundaries
Every new surface is hash-accounted. The smart-vpn EC2 archive contained a nested Lambda payload ZIP; its member was independently opened and hashed rather than hidden under the outer archive. License posture is recorded per donor. No-license and copyleft material is used as evidence, independently rederived behavior, or negative guardrails unless an existing compatible target boundary already owns the implementation.
