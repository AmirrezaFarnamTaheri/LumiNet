# Post-refactor-220 omission and supersession audit

## Coverage denominator

- Project universe: **40** (LumiNet target + **39** uploaded donor archives).
- Immutable post-refactor-160 donor surfaces: **12,285** across 19 donors.
- Immutable post-refactor-180 donor surfaces: **6,232** across 20 donors.
- Cross-wave donor surface accountability: **18,517** file/symlink surfaces.
- Post-refactor-220 does not duplicate those surfaces; it links current decisions back to their exact historical roots/fine records and hashes.

## Audit ladder

1. **Files/symlinks:** preserved historical surface matrices remain the denominator; both libcrafter symlinks remain explicitly accounted in post-180 evidence.
2. **Roots/packages/deliverables:** every uploaded donor has one cross-wave accountability row and historical root record.
3. **Symbols/contracts:** held higher-level mechanisms were reopened; new target owners have concrete source/test anchors in the post-220 ledger.
4. **State machines/recovery:** flow close, network epoch, detour graph, config mutation retry, interrupted-job lineage and fragment/source-retry state retain closed/bounded transition rules.
5. **Negative paths/trust:** partial flow coverage, oversized bulk close, stale provider corpus, conversion loss/parser drift, orphaned detours, credential persistence, duplicate recovery descendants and explicit-revision mutation conflicts all have fail-closed semantics.
6. **Operator surfaces:** Connections, Path intelligence, Compatibility Lab, Interrupted job recovery, and the Capability & Coverage Center expose the new capabilities without becoming authoritative stores.
7. **Deep leaves:** small superseding fragments were separately promoted, notably Throne AnyTLS idle fields and the VLESS security serializer correction surfaced by the round-trip oracle.
8. **Deployment/admin/tooling:** unrelated high-authority products remain explicit rejections rather than being hidden under a whole-donor label.

## Per-project resolution

| Project | Wave | Surfaces | Post-220 resolution | Target value / boundary |
|---|---:|---:|---|---|
| LumiNet | target | 2811 | authoritative-target | all selected semantics are recomposed into LumiNet-owned planes; one authoritative owner per state/side-effect domain |
| LEGION2-main | post-refactor-160 | 1087 | rejected-with-reason | negative scanner/security evidence; Broad exploit/recon corpus remains outside LumiNet product authority. |
| OnionHop-master | post-refactor-160 | 212 | preserved | front-aware Tor bridge diagnostics + shared public endpoint admission; No donor Tor/Xray runtime transplant. |
| SIMORGH-main | post-refactor-160 | 58 | reference-only | operational/reference evidence; No donor-specific runtime authority. |
| Xray-core-main | post-refactor-160 | 992 | superseded | target-native runtime/health/DNS/routing owners; Only separable stronger primitives retained; no parallel Xray authority. |
| Xray-docs-next-main | post-refactor-160 | 506 | reference-only | protocol/operational knowledge; Documentation informs contracts but is not executable authority. |
| Xray-tun-main | post-refactor-160 | 810 | superseded | existing target TUN/NAT/platform owners; No parallel TUN controller. |
| iperf-master | post-refactor-160 | 113 | preserved | real bounded iperf3 diagnostic protocol; No embedded C runtime or unauthorised load generator. |
| lantern-main | post-refactor-160 | 1029 | preserved | passive Android physical-underlay tracking; No active requestNetwork ownership. |
| metacubexd-main | post-refactor-160 | 180 | expanded | operator UX patterns absorbed into shared control UI; UI state remains non-authoritative. |
| nexvpn-main | post-refactor-160 | 193 | preserved | Android per-app include/exclude routing; Post-160 mobile authority remains canonical. |
| rethink-app-main | post-refactor-160 | 1247 | preserved | Android per-app policy semantics and fail-closed validation; No second VPN controller. |
| sing-box-testing | post-refactor-160 | 1264 | expanded | validate-before-swap ETag refresh + compatibility target/import/export semantics; No second long-lived proxy/subscription owner. |
| v2board-master | post-refactor-160 | 362 | rejected-with-reason | commerce/account model reference only; Commerce/reseller/account control plane is unrelated product authority. |
| v2ray-core-main | post-refactor-160 | 1065 | superseded | existing target runtime/routing/DNS owners; No duplicate V2Ray core. |
| v2ray-core-master | post-refactor-160 | 1450 | preserved | evidence-bounded same-socket STUN mapping; No false cone/filter precision. |
| v2ray-go-main | post-refactor-160 | 817 | superseded | existing Go runtime/adapters; No donor-specific parallel runtime. |
| v2rayA-main | post-refactor-160 | 413 | expanded | operator/profile UX ideas absorbed into target-native control UI/compatibility surfaces; No second web control daemon. |
| v2rayN-master | post-refactor-160 | 407 | expanded | STUN negative oracle + compatibility client-format semantics; No second desktop runtime/control plane. |
| v2ray_client-master | post-refactor-160 | 80 | superseded | profile/runtime/observability capabilities owned natively; No second client stack. |
| IPRadar2ForLinux | post-refactor-180 | 46 | promoted | canonical flow registry + local provider attribution + derived network intelligence; Process termination/firewall automation remains outside the flow observation authority. |
| SNI-Spoofing-Go | post-refactor-180 | 52 | rejected-with-reason | negative evidence only; Raw wrong-sequence packet injection would create a second low-level packet authority. |
| SNI-Spoofing-Pro | post-refactor-180 | 31 | rejected-with-reason | negative evidence only; Raw fake-TCP/SNI injection and service deployment remain outside coherent product authority. |
| Sanaei-3xui-v2ray | post-refactor-180 | 150 | rejected-with-reason | server-admin UX/reference evidence only; Multi-user Xray server administration is a separate control-plane product/authority. |
| Scrapling | post-refactor-180 | 236 | promoted-with-guardrails | credential-redacted persisted intents + explicit lineage-tracked interrupted-job requeue; No automatic boot replay; consequential/secret-bearing jobs remain non-reconstructible. |
| Shin-TG-V2ray-Collector | post-refactor-180 | 10 | rejected-with-reason | negative supply-chain evidence only; Untrusted scraped public configuration corpus is not embedded as trusted product data. |
| Throne | post-refactor-180 | 844 | promoted | connection/process metadata contract + exact AnyTLS idle-session fields; Desktop process enforcement is not inferred from observation metadata. |
| V2RayDAR | post-refactor-180 | 62 | promoted-selectively | strict generated-output re-ingest proof and compatibility evidence; External runtime execution remains an optional release oracle, not a second runtime owner. |
| Vwarp | post-refactor-180 | 195 | superseded | existing WARP scanner/runtime owners; No donor staged pipeline duplication. |
| WarpScanner | post-refactor-180 | 41 | preserved | real-handshake loss/jitter/median WARP ranking; Peer arbitrary score/worker model remains superseded. |
| Yacd-meta | post-refactor-180 | 226 | promoted | Connections operator plane with search/filter/detail/owner-delegated close; UI never claims host-wide completeness; no close-all shortcut. |
| gotk4 | post-refactor-180 | 168 | rejected-with-reason | toolchain/reference evidence only; No second GTK UI/toolchain beside shared React/Wails/Android product surfaces. |
| ipscan | post-refactor-180 | 350 | superseded | existing bounded scanner plus derived flow/path intelligence; No parallel scanner orchestration. |
| libcrafter | post-refactor-180 | 1284 | preserved | declared-length packet guards + bounded conflict-aware IPv4 reassembly; Raw packet construction/injection is not generalized into new authority. |
| mylg | post-refactor-180 | 392 | promoted | truthful traceroute + derived path intelligence; No second scanner/runtime owner. |
| obfuscated-openssh | post-refactor-180 | 450 | rejected-with-reason | negative compatibility evidence only; No legacy SSH protocol fork. |
| okhttp | post-refactor-180 | 616 | preserved | bounded redirects/loops + bounded Retry-After; Existing post-180 implementation remains authoritative. |
| subconverter | post-refactor-180 | 508 | promoted-selectively | local compatibility conversion + RE2 shaping + detour-safe graph transforms; No embedded scripting, remote includes, filesystem traversal, or second parser authority. |
| tailscale-rs | post-refactor-180 | 485 | promoted | passive daemon network epochs + existing immutable LPM provider index; Observation never becomes route mutation or network acquisition. |
| tsidp | post-refactor-180 | 86 | rejected-with-reason | identity-boundary reference evidence only; LumiNet does not become a general-purpose OIDC identity provider. |

## Saturation result

The post-220 pass continued until the held/reference-only values that had become implementable were either promoted into a coherent target owner or re-rejected against an explicit authority prerequisite. A final compositional pass also promoted one cross-plane product surface that no donor contained as a complete mechanism: the read-only Capability & Coverage Center, which keeps registry availability, runtime-owner participation, passive network state, native linkage, and provider-corpus freshness as separate evidence dimensions. The remaining non-promotions are not missing peer review: each would create a new product authority (identity/server commerce/admin), a competing host/network authority (process kill/firewall/raw packet injection), a duplicate UI/runtime stack, or a mutable untrusted data supply. No further reviewed peer leaf presently dominates a shipped target mechanism enough to justify that architectural cost.
