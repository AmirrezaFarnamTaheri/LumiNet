# LumiNet post-refactor-180 peer-convergence release

## Deliverables

This wave converges 20 additional uploaded peers into the post-refactor-160 LumiNet baseline. The release package, source manifest, checksums, evidence bundle, and machine-readable receipt are generated from the exact frozen source after the final gates. This report is the source-resident decision/architecture record for those bytes.

## Scope

### Target baseline

The sole authority-bearing target is the exact post-refactor-160 LumiNet release. Peer repositories are read-only evidence. Existing target state, runtime owners, security boundaries, historical convergence evidence, and the post-refactor-160 automatic mutation-retry contract are preserved unless an explicit post-180 transformation supersedes a narrower mechanism.

### Donors

The wave covers 20 donors:

- IPRadar2ForLinux;
- obfuscated-openssh;
- Yacd-meta;
- subconverter;
- ipscan;
- Throne;
- WarpScanner;
- Shin-TG-V2ray-Collector;
- V2RayDAR;
- SNI-Spoofing-Go;
- libcrafter;
- tailscale-rs;
- gotk4;
- SNI-Spoofing-Pro;
- Vwarp;
- Scrapling;
- mylg;
- tsidp;
- okhttp;
- Sanaei-3xui-v2ray.

### Exhaustive accountability

The strict new-wave inventory contains:

- 6,232 file/symlink surfaces;
- 1,290 real directories;
- 125 build/module manifests;
- 36,779 normalized declaration discoveries;
- 142 nested file payloads;
- 2 confined symlinks;
- 289 evidence/decision records = 20 donor roots + 245 semantic/category records + 24 fine mechanism records.

Every outer surface is SHA-256-accounted and has both donor-root and semantic dispositions. Fine-grained adoptions/rejections point back to exact donor files and hashes. Nested material is accounted separately so JAR/ZIP directory entries do not inflate source-file completeness.

## Decision summary

The strongest convergence in this wave is not a wholesale proxy/runtime transplant. It is six target-native mechanism improvements in existing owners:

1. **Truthful platform traceroute:** replace fake TTL-loop TCP timing with bounded OS traceroute/tracert execution and structured per-hop loss/latency/jitter/load-balancing data.
2. **Finite HTTP follow-up and source recovery:** restore a hard redirect/follow-up budget, reject redirect loops, strip conditional validators across origins, and use bounded `Retry-After` hints without surrendering target backoff ownership.
3. **Immutable provider longest-prefix attribution:** rederive an O(address-width) lookup index from `tailscale-rs` LPM evidence while preserving LumiNet's existing prefix/priority/tie semantics.
4. **WARP temporal stability:** rank repeated successful handshakes by loss, then temporal jitter, then median RTT, preserving LumiNet's real handshake and resource-bound authority.
5. **Protocol-declared IP length hardening:** reject truncated/impossible IPv4/IPv6 packet lengths and expose only declared payload ranges.
6. **Bounded conflict-aware IPv4 defragmentation:** replace append/sort reassembly with offset-aware coverage, finite flows/age/datagram size, deterministic eviction, first-fragment header ownership, duplicate-overlap handling, and fail-closed conflicting overlaps/final-length contradictions.

This wave intentionally does **not** add a parallel proxy runtime, server administration plane, identity provider, raw packet injector, GTK product stack, or untrusted built-in endpoint corpus.

## Architecture and ownership

### Subscription HTTP resilience

Owner: `src/apps/daemon/internal/integrations/sub`.

OkHttp's explicit retry/follow-up state machine revealed a target regression caused by Go API semantics: supplying a custom `CheckRedirect` callback replaces the standard client's built-in 10-redirect protection. LumiNet now owns an explicit finite 10-follow-up budget, canonical redirect-loop identity, per-hop re-admission, and cross-origin validator stripping. The subscription source-health owner also understands bounded `Retry-After` for 429/503 as a lower bound on—not a replacement for—the existing exponential backoff.

The design keeps one subscription mutation/freshness authority. No OkHttp stack or donor scheduler is embedded.

### Path-quality diagnostics

Owner: `src/apps/daemon/internal/analysis/diagnostics`.

`mylg` exposed that real traceroute semantics require TTL-scoped path probing and repeated observations. LumiNet's old routine incremented a TTL variable without applying TTL to the network operation, so it could not truthfully identify hops. The replacement executes bounded platform traceroute tools without a shell, validates targets/options/output size, and parses per-hop addresses, timeouts, loss, min/average/max latency, temporal jitter, load-balanced responders, and destination reachability.

If a backend is unavailable, capability reporting remains truthful rather than synthesizing path data from repeated connects.

### Provider attribution

Owner: `src/apps/daemon/internal/analysis/provider`.

`tailscale-rs/ts_bart` is used as mechanism evidence for indexed longest-prefix matching. LumiNet does not copy the Rust BART structure. Instead, each immutable provider snapshot publishes IPv4 and IPv6 prefix-length maps indexed by masked network address. Lookup walks address widths from most-specific to least-specific, so lookup cost is bounded by 33 IPv4 or 129 IPv6 prefix lengths rather than provider corpus cardinality.

Construction preserves the target's existing priority/tie behavior, and a differential test compares the new index against the old linear reference.

### WARP endpoint qualification

Owner: `src/apps/daemon/internal/runtime/warp`.

WarpScanner's useful separable insight is that one latency sample hides endpoint instability. LumiNet adopts only that primitive. Multiple target-owned real handshake attempts are summarized into loss, temporal jitter (mean absolute adjacent RTT delta), and median RTT. Ranking is lexicographic: successful candidates first, lower loss, lower jitter, then lower median latency. Donor aggregate scoring, GPL implementation code, and unbounded scanning behavior are not imported.

### Native packet parsing

Owner: `src/packages/lumicore/src/transport/ip_packet.rs`.

`libcrafter` provided the discriminator that protocol-declared length is part of validity, not merely a hint. LumiCore now fails closed on truncated IPv4/IPv6 declarations and slices payload according to declared packet length rather than all remaining buffer bytes. This prevents trailing transport/storage bytes from becoming protocol payload and prevents truncated packets from being accepted as complete.

### NAT IPv4 reassembly

Owner: `src/apps/daemon/internal/platform/system/nat`.

The former reassembler bounded age but not concurrent datagrams and appended sorted fragments rather than placing them at protocol offsets. That could misassemble overlap patterns and let arrival order influence conflicting bytes. The new implementation has:

- bounded age and maximum flow count;
- protocol-wide datagram-size bounds;
- offset-addressed byte storage and coverage bitmap;
- complete-range checks before assembly;
- authoritative offset-zero header capture;
- deterministic oldest-flow eviction;
- non-final fragment alignment enforcement;
- acceptance of byte-identical duplicate overlap;
- fail-closed conflicting overlap with flow deletion;
- fail-closed contradictory final length or bytes beyond final length;
- checksum/length/fragment-field repair only after complete assembly.

A second-order review caught a subtle IPv4-options interaction: fragment offset is relative to payload, so a non-zero fragment's longer IHL must not shrink the legal datagram payload range. Admission now uses the protocol-wide payload maximum; the offset-zero header remains authoritative when finalizing the packet.

## Peer synthesis

### Adapted / hardened / extracted

**OkHttp (Apache-2.0):** explicit follow-up state-machine evidence → target-native redirect budget/loop/origin rules and bounded Retry-After parsing.

**mylg (MIT):** TTL-scoped traceroute semantics → target-native platform traceroute backend and structured hop parsing.

**tailscale-rs (BSD-3-Clause):** LPM/trie evidence → independent Go immutable provider prefix index with differential equivalence to the prior LumiNet behavior.

**WarpScanner (GPL-3.0):** repeated-latency stability insight only → independently implemented temporal jitter metric in LumiNet's own WARP scanner. No GPL source is reused.

**libcrafter (MIT):** declared-length and fragment-reassembly invariants → hardened Rust packet parser plus bounded/conflict-aware Go reassembly. The target keeps its own packet representation and ownership.

### Valuable but intentionally held behind prerequisites

**Yacd-meta / Throne / IPRadar2ForLinux:** connection list, process attribution, filters, detail panels, and close controls are useful operator/product evidence. LumiNet does not yet have one cross-runtime flow registry. Runtime-local session maps and global byte counters cannot safely authorize universal close operations. The prerequisite is one canonical flow lifecycle/identity/close authority with recovery and authorization; a partial universal UI would be false product truth.

**tailscale-rs netmon:** interface/address/route/default-route change tracking is mature evidence, but a daemon-wide cross-platform observer is a new supervision/reconciliation plane. It is held rather than being mixed with the existing passive Android-only underlying-network tracker.

**Scrapling:** atomic checkpoint replacement and scheduler snapshot/dedup restore are sound replay primitives. Generic LumiNet job replay remains disabled because current jobs do not uniformly declare idempotency/checkpoint safety. The peer lesson is converted into a guardrail: restart replay requires job-type-specific proof before promotion.

### Superseded/reference-only

**subconverter (GPL-3.0):** broad proxy-link/config conversion is useful as compatibility evidence, but LumiNet already owns one typed proxy parser and observed-format contract tests. A second converter authority would create contradictory normalization.

**V2RayDAR (AGPL-3.0):** running sing-box to validate generated configs is a useful external oracle, but embedding its runtime/subscription authority would conflict with existing target owners and its license posture. LumiNet retains native compatibility validation.

**Vwarp (AGPL-3.0) / ipscan (GPL-2.0):** staged scanner/fetcher/cancellation patterns reinforce existing design; LumiNet's scanner/WARP owners already provide bounded concurrency, cancellation/liveness, typed results and real handshake qualification.

### Rejected with reason

**SNI-Spoofing-Go / SNI-Spoofing-Pro (GPL-3.0):** privileged raw fake-TCP/TLS/SNI injection would create a second packet mutation/evasion authority and materially expand privilege. Rejected as runtime additions.

**obfuscated-openssh:** legacy OpenSSH handshake obfuscation is weak anti-scanning tied to an old SSH codebase and obsolete cryptographic iteration. It does not justify a fork of current SSH/security ownership.

**Sanaei 3x-ui (GPL-3.0):** multi-user Xray server administration/reseller control plane is outside LumiNet's client/network authority model.

**tsidp (BSD-3-Clause):** OIDC/OAuth identity-provider authority is outside scope and would create an unnecessary identity source of truth.

**gotk4 (MPL-2.0 root; subcomponents vary):** GTK/GIR binding generation does not fit LumiNet's React/Wails/Kotlin product stacks and adds a parallel UI/build technology without target semantic value.

**Shin-TG-V2ray-Collector (unclear root license):** scraped public endpoint/config datasets are untrusted and rapidly stale. They are not promoted into built-in target truth; LumiNet keeps explicit remote-source admission, parser validation, freshness and health ownership.

## Second-order convergence pass

The second-order pass deliberately searched for emergent issues caused by combining the selected mechanisms.

1. The redirect adaptation was hardened beyond the donor observation: LumiNet validates every redirect target, detects loops before budget exhaustion, and strips source-scoped ETags on origin changes so a validator cannot leak or be incorrectly reused across sources.
2. Retry-After cannot dictate an arbitrary sleep; it is syntactically validated, restricted to relevant status codes, capped at 24 hours, and only raises existing target backoff.
3. Traceroute target parsing was adversarially tested after an initial URI-shaped input could be misparsed through host/port splitting; URL/path/option-shaped targets are now rejected before process execution.
4. The provider optimization uses the old linear lookup as an explicit differential oracle so performance structure cannot silently alter attribution semantics.
5. WARP stability is not a donor score transplant; loss remains dominant, jitter only breaks equal-loss candidates, and median latency remains the final quality discriminator.
6. Packet reassembly received an additional protocol-level review after its first rewrite. This found the non-zero-fragment IHL/options issue and produced the payload-relative offset fix plus a dedicated regression test.
7. Historical post-refactor-160 convergence evidence is immutable. Its checker is evaluated against the frozen pre-180 baseline; new descendants are validated by the post-180 gate instead of retroactively rewriting old claims.
8. The existing post-refactor-160 automatic mutation retry was explicitly rechecked and remains unchanged: bounded fresh-snapshot intent replay with explicit-precondition single-attempt semantics.

## Omission audit

The durable omission audit covers files/symlinks, directories/deliverables, declarations, semantic contracts, state/recovery, negative/trust paths, operator surfaces, deployment/scripts, deep nested leaves, historical claims, and cross-mechanism contradictions.

The saturation pass did not find another implementation whose target value exceeded the required authority/licensing/migration/validation cost. In particular, flow observability, daemon-wide netmon, and generic job replay are **not missed features**; they are explicitly retained prerequisites because implementing their UI or replay mechanics before establishing authority/idempotency would create false or unsafe behavior.

## Validation

Canonical repository validation is green on the final implementation state:

- source structure/context/tooling/topology: green;
- all daemon/mobile/runtime/subscription authority and liveness gates: green;
- all historical convergence gates through post-refactor-180: green;
- route/platform/native/ABI/FFI/pruning/qualification gates: green;
- repository audit: zero errors, one inherited Gradle-wrapper warning;
- Go declaration checker parsed 1,536 files with zero syntax errors and zero duplicate active declarations on linux, Windows, macOS and Android target selections.

Focused executable validation against exact current target source:

- NAT/IPv4 reassembly and length semantics: 8/8 tests pass;
- provider corpus/index: 9/9 tests pass;
- subscription egress: 10/10 tests pass;
- Retry-After parser/backoff: parent test plus all seven edge cases pass;
- traceroute parser/bounds: 4 tests pass; live Linux loopback backend test passes;
- WARP target ranking/bounds: 11 top-level tests plus 6 resource-limit subcases pass with only the external handshake primitive stubbed.

Rust parser tests are source-present and statically validated but not executed because the Rust toolchain is unavailable. Full LumiNet Go package tests are blocked before compilation because the workspace requires Go 1.26.0/toolchain 1.26.5 while the environment provides Go 1.23.2. Android Gradle, Windows `tracert`, external WARP interoperability and live `iperf3` are likewise outside the executed environment boundary.

See `post-refactor-180-validation.md` for exact claim boundaries.

## Limitations and residual risk

- Full Go 1.26.5 workspace tests were not executable in this environment.
- Rust unit/build validation was unavailable.
- Android Gradle/emulator validation was unavailable.
- Windows traceroute process integration was not executed.
- WARP ranking logic is verified but the isolated suite stubs the external handshake primitive; live service interoperability is not inferred from that suite.
- A canonical cross-runtime flow registry remains prerequisite to a truthful universal connection UI/close plane.
- A daemon-wide network-change observer requires a separate supervision/reconciliation design before adoption.
- Generic restart replay remains forbidden until each job type provides explicit idempotency/checkpoint semantics.

No known critical convergence gap remains inside the requested post-refactor-180 scope; the unimplemented higher-level items above are explicit architectural prerequisites, not unexamined donor surfaces.

## Evidence

Durable evidence under `governance/convergence/` includes:

- `post-refactor-180-archive-safety.csv`;
- `post-refactor-180-new-donors.csv`;
- `post-refactor-180-surface-accountability.csv`;
- `post-refactor-180-directories.csv`;
- `post-refactor-180-modules.csv`;
- `post-refactor-180-symbols.csv`;
- `post-refactor-180-nested-archive-contents.csv`;
- `post-refactor-180-capability-counts.csv`;
- `post-refactor-180-baseline-files.csv`;
- `post-refactor-180-adoption-ledger.csv`;
- `post-refactor-180-license-map.csv`;
- `post-refactor-180-peer-analysis.md`;
- `post-refactor-180-omission-audit.md`;
- `post-refactor-180-validation.md`;
- `post-refactor-180-target-delta.csv`;
- `post-refactor-180-summary.json`;
- this final report.

The release receipt and external evidence bundle freeze hashes of these records together with exact source and validation logs.
