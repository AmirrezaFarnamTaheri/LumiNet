# LumiNet post-refactor-222 peer-convergence release

## Delivered outcome

Post-refactor-222 turns the prior shallow 221 review into a target-native convergence pass with explicit file/symbol accountability, semantic provenance, omission auditing, product promotion and regression gates. It does not create a directory union of donors. Useful behavior is decomposed and recomposed under existing LumiNet owners; weaker or duplicated donor subsystems are superseded; negative/offensive evidence becomes guardrails rather than executable authority.

The requested 40-project baseline (LumiNet plus 39 historical donors) is combined with 23 unique current donor archives. The resulting pass-level accountability universe is **63 projects: LumiNet plus 62 donor projects**, representing **24,770 donor surfaces** across the historical 18,517-surface baseline and the 6,253-surface current corpus.

## Current-corpus accountability

- uploaded artifacts: 28/28 accounted
- donor ZIP uploads: 25 files
- unique current donor archive hashes: 23
- exact duplicate upload aliases: 2 (`Kloak_platform-master.zip`, `stealthspanner-master.zip`)
- current donor file/symlink surfaces: 6,253/6,253
- archive symlinks: 20/20, recorded and never followed
- extracted current donor symbols: 13,006/13,006
- exact historical regular-file matches: 4,960
- reopened/unmatched/link surfaces: 1,293
- post-222 semantic records: 81
- dispositions: adapted 9; extracted 3; guardrail-derived 9; hardened 4; inspired-native 1; recomposed 3; reference-only 30; rejected-with-reason 9; superseded 13

The machine-readable sources of truth are the adoption ledger, surface matrix, symbol matrix, archive/cross-wave/universe accountability files and exact target delta. `post-refactor-222-verify.py` independently re-hashes donor ZIP members and closes bidirectional provenance.

## Promoted target-native planes

### 1. Peer identity/discovery admission and planning

A production read-only planner replaces the dormant/lab-quality concept without importing a donor P2P runtime. It provides BEP42 IPv4 node-ID binding, canonical public-address admission, bounded local CIDR deny policy, self/duplicate/malformed/port-zero rejection, exact 160-bit XOR-distance ordering, bounded results and NAT-safe shared-public-address evidence. Existing runtime trust is descriptive only. The plane performs no DHT/tracker discovery, DNSBL lookup, dialing, persistence, route mutation or automatic trust mutation.

### 2. Endpoint continuity/diversity

EDtunnel and stealthspanner evidence is fused into the existing endpoint owner rather than copied as a proxy runtime. Jitter and packet loss are bounded penalty evidence. Previous success is only a continuity hint inside a five-point quality band. Deterministic scoped diversity only reorders near-equivalent eligible endpoints and cannot manufacture eligibility.

### 3. Operator navigation, appearance and log control

The Control UI now has a canonical navigation registry, accessible Ctrl/Cmd+K command palette, deterministic fuzzy ranking, bounded validated recents, System/Light/Dark local appearance with OS following/cross-tab synchronization, and operator-respecting live-log tail behavior with explicit resume. The command palette was flattened into the canonical UI source root after the repository audit rejected a one-file `components/` namespace wrapper.

### 4. Health and redacted diagnostics

The Health workspace composes existing readiness, capability, passive-network and transport evidence into Healthy/Degraded/Unavailable without creating another backend health authority. Export is allow-listed structural data and excludes raw logs, config bodies, API keys, MAC/interface addresses, credential-bearing URLs and free-form backend/network error text.

### 5. Subscription deep-link admission

Marz's one-tap import affordance is rederived as `luminet://import`, but authority is deliberately reduced. Inputs are bounded, only `url` plus optional `name` are accepted, the embedded source must satisfy the existing managed-profile HTTPS policy, credentials/fragments/extra or duplicate parameters fail closed, and inspection only returns a proposal. It never fetches, saves, refreshes, activates or changes routing/configuration. The Profiles UI explicitly inspects/prefills and requires normal profile creation afterward.

### 6. Signed-update publication durability

The existing verify-before-publication owner is hardened: staged content is synchronized; existing targets are regular-file confined; Unix uses rename-overwrite plus parent-directory synchronization; Windows retains an explicit portable fallback and does not claim Unix directory-fsync semantics.

### 7. Automatic mutation retry convergence

The generic 221 Rust retry helper is deleted rather than retained as a second authority. Configuration mutation remains under `foundation/config.Manager.Mutate`: default 3 attempts, hard maximum 8, fresh snapshot on revision conflict, explicit expected revision means exactly one attempt, and non-conflict/callback errors are not replayed. Remote side effects remain separate under `remoteaction.Executor` with reconciliation/idempotency semantics.

## Major supersessions instead of duplicate product planes

Donor-shaped EDtunnel runtime, Nabzram backend/TinyDB/Xray control plane, Marzban-node RPC/process authority, VpnDad PacketTunnel runtime, stealthspanner downloader/firewall helper, Tao blockchain lease authority, cdin editor/filesystem/plugin shell, Kloak browser-OS/mail/social/media suite, HDS multi-user identity provider, and mission-improbable device-flashing pipeline are not retained as parallel owners. Their separable useful primitives, UX lessons, constraints or negative evidence are either absorbed into a LumiNet owner or explicitly retained as reference/guardrail evidence.

## Negative coverage promoted to the final product boundary

The current corpus includes material that is valuable primarily because it exposes failure/abuse modes. The release therefore makes these boundaries explicit:

- CAPTCHA solving does not become an authentication capability; CAPTCHA is not treated as an authorization boundary.
- Tor/deanonymization research limits anonymity claims against timing/correlation/global-observer models; no deanonymization tooling is imported.
- Torrent active probing/findspies/freerider/content-transfer behavior is excluded; only bounded passive candidate/admission ideas survive.
- DNS-Persist command/control/persistence/shellcode semantics are negative evidence; DNS payloads remain untrusted non-executable data.
- Weak custom browser crypto, plaintext/general JSON secret persistence, warning-only service identity and optional-insecure privileged RPC fail the target security boundary.
- Country-scored trust, broad UFW reset and home-directory credential helpers are rejected.
- Root/ADB/fastboot/signature-spoof/device-image mutation is excluded from update authority.

## Omission/contradiction result

The post-222 omission ladder is closed for the supplied/current corpus at files/symlinks, donor roots, symbols, semantic contracts, state/recovery, negative/trust paths, operator/API/product surfaces, presets/scripts/CI/deployment/update surfaces, deep nested leaves, historical evidence bridges and cross-mechanism contradictions. Exact historical reuse is allowed only for identical content bytes; changed/unmatched/symlink surfaces are reopened.

The pass found and fixed several omissions during verification rather than masking them: invalid peer observations no longer reserve identity/endpoint slots; last-known-good cannot outrank a materially stronger endpoint; historical endpoint test anchors remain stable; new source directories have complete `.context` ownership metadata; the Logs transform is registered in original-topology preservation evidence; five 221 successor artifacts are explicit in the post-220 frozen delta; transient `node_modules` is removed; and the one-file UI `components/` wrapper is flattened.

## Validation summary

Verified in this environment:

- post-222 exact convergence checker: PASS
- independent post-222 evidence graph verifier: PASS
- post-220 historical successor-baseline checker after repair: PASS
- repository topology/source context/Go declaration/ownership and historical convergence chain: PASS for executed gates
- global convergence validator and peer-convergence audit: PASS
- final repository audit: 0 errors, one documented Gradle-wrapper warning
- Control UI characterization: 190/190 checks PASS
- isolated exact-source Go endpoint planner: PASS
- isolated exact-source Go peer planner + canonical public-netpolicy subset: PASS
- isolated exact-source Go signed update admission: PASS
- isolated exact-source Go deep-link parser: PASS
- gofmt on changed Go surfaces: clean
- static ABI/FFI/native coverage gates: PASS

Not executable here and therefore not claimed as passes: full Go 1.26.x workspace tests/build, Cargo/Rust native tests/build, and frontend typecheck/build requiring the missing installed `vite/client`/Node type definitions. See `post-refactor-222-validation.md` for exact boundaries.

## Durable evidence

- `post-refactor-222-adoption-ledger.csv`
- `post-refactor-222-surface-accountability.csv`
- `post-refactor-222-symbols.csv`
- `post-refactor-222-archive-accountability.csv`
- `post-refactor-222-cross-wave-accountability.csv`
- `post-refactor-222-universe-accountability.csv`
- `post-refactor-222-target-delta.csv`
- `post-refactor-222-architecture.md`
- `post-refactor-222-state-and-trust-map.md`
- `post-refactor-222-security-model.md`
- `post-refactor-222-peer-synthesis.md`
- `post-refactor-222-omission-audit.md`
- `post-refactor-222-operator-runbook.md`
- `post-refactor-222-validation.md`
- `post-refactor-222-verify.py`

The release source archive is frozen only after these evidence files and the exact target delta pass their final machine gates. Archive checksum, source-manifest hash and extraction verification are emitted externally after packaging so the frozen source is not modified by self-referential release metadata.
