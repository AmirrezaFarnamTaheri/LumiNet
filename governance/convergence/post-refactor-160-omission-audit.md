# Post-refactor-160 omission audit

## Denominator

This wave treats the 19 uploaded peer archives as read-only evidence and the supplied LumiNet tree as the only target authority. Archive members were validated before extraction. The new-peer evidence denominator is:

- 19 donors
- 12,285 file surfaces
- 2,185 directories
- 44 module/build manifests
- 70,594 normalized declarations
- 2 nested archive surfaces
- 584 cross-repository byte-overlap groups
- 24 semantic surface tags
- 410 adoption/decision records: 19 donor-root accountability rows, 382 donor-by-semantic buckets, and 9 fine peer-derived value records

Every file surface has a SHA-256 and links to its donor-root record plus at least one semantic bucket. Directory, manifest, declaration, overlap, capability, and nested-archive inventories are retained beside the ledger. Root/category records are accountability, not evidence that every behavior was adopted.

## Omission ladder

1. **Files and symlinks:** all archive members were listed and validated before extraction; no absolute/traversal members, duplicate members, case collisions, device nodes, or unsafe symlinks were accepted. All 12,285 donor files are in the surface matrix.
2. **Roots/packages/deliverables:** all 19 donor roots and all 2,185 nested directories are inventoried. All 44 detected build/module manifests are separately retained.
3. **Symbols/runtime registrations:** 70,594 normalized declarations were indexed. Mechanism-hotspot evidence was used to revisit small retry, health, DNS, TUN, STUN, update, and process primitives rather than stopping at repository labels.
4. **Independent semantic contracts:** 382 donor-by-semantic buckets cover runtime, proxy protocols, DNS, routing, subscriptions/config, TUN/mobile, NAT/STUN, retries/recovery, scanners, security/auth, persistence, control plane, UI/operator, health, firewall, update/supply-chain, traffic, Tor/circumvention, platform integration, packaging, documentation, and uncategorized leaves. Fine records split the peer primitives that materially changed the target.
5. **State/recovery:** mutation CAS replay, subscription last-known-good refresh, mobile TUN ownership, underlay observation, bounded diagnostic retries, and historical convergence freezing were explicitly checked.
6. **Negative paths/trust boundaries:** explicit config preconditions do not retry; mixed/non-public DNS answers fail closed; cross-origin ETags are stripped; invalid subscription payloads cannot advance freshness; per-app policies fail before tunnel establishment; iperf requires operation-specific authorization; STUN and bridge probes are public-only and bounded.
7. **API/CLI/UI/operator:** new bridge, iperf, and STUN diagnostics are exposed through the existing authenticated daemon/API and Operations UI rather than creating donor-specific operator planes. Android package policy is mobile-local because only `VpnService.Builder` can enforce it.
8. **Scripts/CI/packaging/upgrades:** peer CI/build/update surfaces were reviewed. No peer build or deployment stack displaced LumiNet's release/toolchain contracts. The new wave adds a repository convergence gate and preserves prior convergence gates.
9. **Deep leaves:** byte-overlap groups suppress double-counting of cloned core-family files while branch-specific modifications remain individually visible. Remaining-donor hotspot review revisited peers with no fine adoption for small process, DNS, health, update, and recovery mechanisms.
10. **Historical claims:** old post-141 evidence is not rewritten. The post-141 checker is frozen against the immutable post-160 baseline; final/ultimate convergence checks explicitly recognize the new mutation-helper successors.

## Second-order convergence findings

- OnionHop endpoint-safety evidence was generalized into one shared `foundation/netpolicy` primitive and then reused by both subscription egress and diagnostics instead of duplicated per feature.
- sing-box remote-rule refresh behavior was fused into LumiNet's existing profile mirror/backoff authority rather than adding a second rule-set manager.
- Lantern/NexVPN TUN liveness evidence was not copied blindly: their external-child restart model conflicts with LumiNet's in-process TUN-fd owner. Only the passive underlay/kill-switch-compatible insight was retained.
- The iperf peer exposed that LumiNet's prior raw socket probe was semantically not iperf. It was replaced with the real protocol, then a second security pass pinned the admitted numeric address to close a DNS-rebinding time-of-check/time-of-use gap.
- V2Ray STUN implementations and v2rayN's shallow STUN client were combined as positive and negative evidence: LumiNet implements mapped-address comparison while explicitly refusing unsupported cone/filter labels.
- Xray/V2Ray observatory and DNS families were not imported because LumiNet's existing owners already provide stronger bounded health selection and DNS ownership; this is a supersession decision, not omission.

## Explicit non-adoptions

- LEGION2 exploit/NASL/offensive scanner authority: rejected as an attack-surface and authority expansion.
- v2board commerce/reseller/account plane: rejected as unrelated target authority.
- parallel Xray/V2Ray/sing-box long-lived proxy runtime owners: rejected to preserve one runtime source of truth.
- donor-specific DNS, firewall, observatory, process-supervisor, and subscription managers where LumiNet already owns the same state: superseded.
- source reuse from peers with missing/unclear root code licenses (notably SIMORGH and v2ray_client): reference/inspiration only.

## Remaining uncertainty

No claim is made that static inspection proves runtime equivalence. Go package tests require the repository-pinned Go 1.26.5 toolchain, Rust validation requires the pinned Cargo/Rust toolchain, Android assembly requires the release-provisioned Gradle/AAR path, control-UI type checking requires local npm dependencies, and live iperf interoperability requires an `iperf3` executable and an authorized server. These are recorded as environment/toolchain limitations, not silently converted to passes.
