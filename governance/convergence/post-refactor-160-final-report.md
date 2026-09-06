# LumiNet post-refactor-160 peer-convergence report

## Outcome

This wave converges 19 additional uploaded peer repositories into the existing 141-peer LumiNet baseline, producing a cumulative 160-peer evidence history without introducing donor-specific parallel authorities. The target remains LumiNet-native: peer code was treated as evidence, decomposed to mechanisms/primitives, and either reimplemented, fused into an existing owner, used as a guardrail, superseded, or rejected with reason.

## Implemented target-native value

1. **Automatic configuration mutation retry.** `foundation/config.Manager.Mutate` replays only side-effect-free server-owned intents against a fresh authoritative snapshot after CAS conflict. Default budget is 3, hard cap is 8. Explicit `If-Match` or body revision preconditions are single-attempt. The HTTP layer converges on `commitConfigMutation` and exposes attempt telemetry; runtime side effects remain after durable commit.
2. **Android per-app VPN authority.** `PerAppVpnPolicy` implements mutually exclusive `ALL`, `INCLUDE`, and `EXCLUDE` modes, bounded/deduplicated package sets, package-name validation, empty-include rejection, LumiNet self-recursion prevention, durable mobile-local policy storage, and fail-closed `VpnService.Builder` application.
3. **Passive Android physical-underlay tracking.** `UnderlyingNetworkTracker` passively observes `INTERNET + NOT_VPN` networks, handles hand-off metadata with `setUnderlyingNetworks`, never calls `requestNetwork`, cleans up callbacks, and leaves `VpnService.protect` as the routing-safety authority.
4. **Shared public endpoint admission.** `foundation/netpolicy` is the canonical public/special-use/documentation address classifier reused by subscription ingestion and active diagnostics, preventing duplicated weaker SSRF/DNS-rebinding rules.
5. **Tor bridge reachability diagnostics.** A bounded front-aware planner/prober distinguishes literal bridge endpoints from broker/front/DoH/DoT/URL endpoints, handles documentation placeholders, caps lines/workers/time, validates all DNS answers, dials numeric admitted addresses, and reports explicit refused/unparsed/fronted/reachable states without modifying Tor runtime state.
6. **Real iperf3 diagnostics.** The prior raw zero-byte socket surrogate is replaced with actual `iperf3 -J` execution, TCP retransmit/CPU and UDP jitter/loss parsing, reverse/bidirectional modes, explicit time/output/parallel/bitrate bounds, per-operation authorization attestation, public-only target admission, and numeric DNS pinning to close post-admission rebinding.
7. **Evidence-bounded STUN mapping.** The new RFC 5389 probe uses one UDP socket, cryptographic transaction IDs, bounded attempts/time, source/origin checks, public-only destinations, and same-socket mapped-address comparison. It reports only `endpoint-independent`, `endpoint-dependent-or-port-dependent`, or `unknown`, deliberately avoiding unsupported cone/filter labels.
8. **Subscription validate-before-swap conditional refresh.** sing-box rule-set updater semantics were recomposed into the existing `ProfileService`: source-scoped ETags, cross-origin validator stripping, accepted-validator-only 304s, invalid-2xx failure, last-known-good preservation, and no freshness/validator advancement before payload validation.
9. **Historical convergence preservation.** The post-141 gate now validates its frozen claims against the immutable pre-wave post-160 baseline, while final/ultimate checkers explicitly map retired mutation anchors to the new authoritative successors. Older evidence is not rewritten to pretend the new source did not change.

## Second-order convergence

The second-order pass intentionally looked for interactions and higher-level owners rather than merely accumulating features:

- OnionHop bridge safety and existing subscription SSRF protection became one reusable `netpolicy` primitive.
- sing-box updater semantics were absorbed into the existing subscription authority instead of creating another remote-rule manager.
- NexVPN/Lantern external tun2socks restart logic was not copied because LumiNet's in-process TUN ownership would make blind restart unsafe; only compatible underlay/kill-switch lessons were rederived.
- iperf protocol correction was followed by a separate trust-boundary review that found and closed a DNS time-of-check/time-of-use gap.
- V2Ray positive STUN evidence and v2rayN negative evidence were composed into a smaller, more truthful NAT diagnostic.
- Xray/V2Ray observatory, DNS, and core-management mechanisms were compared branch-by-branch but left superseded where LumiNet already has stronger canonical owners.

## Evidence denominator

- new donors: 19
- peer files: 12,285
- directories: 2,185
- build/module records: 44
- normalized declarations: 70,594
- cross-repository exact-byte overlap groups: 584
- semantic tags: 24
- adoption/accountability ledger: 410 records
- donor-root accountability records: 19
- donor-by-semantic records: 382
- fine peer-derived records: 9
- target-native second-order decision records: 4

The exact file/symbol/module/directory inventories, donor decisions, surface matrix, adoption ledger, omission audit, and validation report are retained under `governance/convergence/post-refactor-160-*`.

## Donor disposition summary

- **LEGION2:** broad exploit/scanner authority rejected; no offensive corpus promoted.
- **OnionHop:** bridge-fronting and endpoint-safety semantics hardened/rederived.
- **SIMORGH:** health/cache/update ideas reviewed; reference only because target owners are stronger and root license is unclear.
- **Xray-core:** observatory/DNS/routing/core mechanisms compared; runtime authority superseded by LumiNet owners.
- **Xray docs:** descriptive/reference evidence only.
- **Xray-tun:** branch-specific TUN/routing mechanisms reviewed; no second TUN/runtime owner introduced.
- **iperf:** real protocol/result semantics adapted through external `iperf3`, not embedded donor C source.
- **Lantern:** passive physical-underlay behavior inspired a target-native tracker; incompatible external-child restart was not copied.
- **MetaCubeXD:** operator/traffic UX used as reference; control UI remains non-authoritative.
- **NexVPN:** per-app routing semantics hardened/rederived; external tun2socks restart not transplanted.
- **Rethink:** per-app allow/deny semantics hardened/rederived; larger DNS/firewall authority remains superseded.
- **sing-box:** conditional remote-rule refresh semantics recomposed into `ProfileService`.
- **v2board:** commerce/reseller/account authority rejected as outside network-client scope.
- **v2ray-core-main:** alternate core mechanisms reviewed and superseded.
- **v2ray-core-master:** STUN mapping evidence hardened into a smaller RFC 5389 diagnostic.
- **v2ray-go:** alternate core/DNS/routing mechanisms reviewed and superseded.
- **v2rayA:** process/DNS/observatory/control-plane mechanisms reviewed and superseded by existing owners.
- **v2rayN:** shallow STUN behavior retained as a negative guardrail against false NAT precision.
- **v2ray_client:** process/subscription examples retained as reference only; root code license unclear.

## Validation

All canonical repository/source/convergence gates executed in this sandbox pass, including the new post-160 gate, repository audit, Go source target/declaration integrity, and historical waves. Runtime package/toolchain tests remain bounded by the environment: Go 1.26.5 is not available, Cargo/Rust is absent, Gradle is absent, npm dependency type packages are absent, and `iperf3` is absent. These are explicitly recorded in `post-refactor-160-validation.md`; they are not represented as passes.

## Release boundary

The delivered source artifact is suitable for the repository's normal pinned CI/release admission. Production release should still run `make verify-release` in the declared toolchain environment so Go/Rust/Android/web runtime tests and packaging are validated with the required dependencies and generated mobile AAR.
