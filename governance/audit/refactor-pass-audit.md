# LumiNet architecture and codebase refactor audit

## Executive verdict

The supplied `LumiNet-ultimate` source is materially stronger after this pass, but it is not reasonable to call every trust path fully hardened until the remaining SSH and bootstrap decisions are made with an explicit compatibility policy.

The highest-impact delivered changes are:

1. runtime engine replacement is now transactional and restores the last healthy configuration after replacement startup failure;
2. provisioning progress/logging no longer contains a deadlocking/racy subscriber mechanism, and remote execution output is bounded and error-redacted;
3. live relay transports no longer silently trust arbitrary TLS certificates, relay close state is race-safe, and failed-write rollback no longer aliases/corrupts buffered payloads;
4. deterministic Go source blockers in the GSA relay, NAT package, WebTunnel owner, and stale Android lab seam were removed;
5. the configuration interface is narrowed to optimistic-concurrency persistence instead of keeping an unconditional stale-writer escape hatch;
6. 38 zero-consumer Failover DNS resolver methods, including several no-op/constant placeholders, were retired from the internal interface;
7. a dependency-free cross-platform Go syntax/declaration integrity checker was added because the declared Go 1.26 workspace cannot be executed in this offline environment.

The strongest unresolved security issue is SSH server identity: both provisioning and the live SSH tunnel use `ssh.InsecureIgnoreHostKey()`, while neither current request/config interface carries an expected host fingerprint or known-host policy. This requires a product-compatible trust/migration decision rather than another insecure default.

The principal verification blocker is toolchain realism: the repository declares Go 1.26.x, but this environment has Go 1.23.2 and cannot fetch the newer toolchain/dependencies; Rust/Cargo are unavailable. Exact-source dependency-isolated Go harnesses and repository governance gates therefore provide the strongest executed evidence for changed paths, while the Rust FFI remediation remains design-first.

## Scope, baseline, and coverage

- Baseline: frozen `LumiNet-ultimate-converged-working-tree` supplied in this conversation.
- Baseline source entries: 2,588 files/symlinks.
- Git state: archive has no `.git`; commit/branch status cannot be reconstructed from the artifact itself.
- Remote repository metadata: `maybeknott/LumiNet`, default branch `main`, read/pull access available through the connected GitHub account.
- Audit mode: incremental exhaustive/transform. The prior 63-donor convergence evidence is reused only where its source identity remains unchanged; recent/hot-path and dependency-affected surfaces were re-inspected and re-exercised.
- Material coverage rows: see `refactor-pass-coverage.csv`. Every material architecture band has a disposition; Rust execution is explicitly Blocked rather than inferred.

### Baseline checks

Before current refactor governance layering, the ultimate convergence checker passed with 63 donors, 8,223 donor surfaces, 18,098 symbols, 662 adoption records, and `errors=0`.

The canonical `make verify-repo` baseline invocation was environment-time-limited, but all commands printed before the limit passed. Final validation is rerun after the refactor and reported separately; timeout is never counted as success.

## System model

The daemon uses explicit dependency bands documented in source context:

`foundation/native -> protocols/platform -> networking -> analysis/integrations -> runtime -> workflows -> adapters`

The refactor deliberately preserves that direction.

Critical state/authority owners inspected in this pass:

- **Configuration authority:** durable revision/CAS plus secret-reference storage.
- **Remote mutation authority:** operation safety classes, provider-scoped retry/cooldown, reconciliation, bounded coordinator state.
- **Runtime engine authority:** long-lived Tor/Psiphon ownership and replacement lifecycle.
- **Host-network authority:** transactional snapshot/apply/verify/rollback owner; duplicate root mutation modules are not allowed.
- **Provisioning authority:** typed provisioning intent, SSH execution, cloud mutations, progress evidence.
- **Relay transport authority:** HTTP/WebSocket/GSA adapters used by live evasion runtime.
- **Native ABI authority:** Rust/C FFI plus private Go ABI declaration header.

## Prioritized findings

The canonical finding ledger is `refactor-pass-findings.csv`. Findings below are ordered by remediation dependency and risk, not discovery order.

### F-015 — Live SSH sessions do not authenticate server host keys

- **Severity / priority:** High / Design first
- **Confidence:** Statically validated
- **Locations:** provisioning SSH runner; live SSH tunnel client
- **Evidence:** both live constructors use `ssh.InsecureIgnoreHostKey()`. Provisioning request/config and runtime SSH fields carry credentials and host but no expected host key/fingerprint/known-host policy.
- **Consequence:** an attacker able to redirect/intercept the SSH path can impersonate the server and obtain session/credential access.
- **Root cause:** server identity was never modeled as domain data, so there is no safe value for either adapter to consume.
- **Recommendation:** introduce one SSH host-identity seam with two real adapters/use cases (provisioning and runtime tunnel). Make the trust policy explicit rather than hiding an insecure fallback.
- **Acceptance:** zero live `InsecureIgnoreHostKey()` uses; key mismatch/rotation/unknown-host behavior is explicitly tested and operator-visible.

### F-016 — Provisioning pipes an unpinned remote installer into a privileged shell

- **Severity / priority:** High / Design first
- **Confidence:** Statically validated
- **Evidence:** the live “Docker missing” branch executes `curl -fsSL https://get.docker.com | sh` remotely.
- **Consequence:** upstream compromise, content drift, DNS/TLS trust failure, or changed installer semantics can execute unreviewed root code.
- **Recommendation:** pick a supported-host/bootstrap policy first, then use a pinned package/repository or digest-verified artifact with explicit version evidence.

### F-017 — Rust FFI string input and error envelope are unnecessarily unsafe and shallow

- **Severity / priority:** High / Design first
- **Confidence:** Statically validated; runtime verification blocked
- **Evidence:** `c_str_to_str` returns a caller-chosen lifetime from a raw pointer and maps null/invalid UTF-8 to an empty string. The FFI tree contains dozens of `unsafe extern` exports and repeated JSON/panic/string envelope code; `exports.rs` suppresses missing-safety-doc linting.
- **Consequence:** ambiguous error semantics and a larger-than-needed unsafe reasoning surface. Future changes can accidentally let a fabricated lifetime escape the immediate call.
- **Recommendation:** preserve every exported C symbol and wire shape; internally copy C input immediately into owned validated data and centralize panic/deserialize/serialize/output handling. Do not ship the refactor until Cargo, Miri where applicable, ABI, and Go/CGO checks all pass.

### F-018 — HTTP/GSA relay adapters claim `net.Conn` deadlines but implement them as no-ops

- **Severity / priority:** Medium / Design first
- **Confidence:** Reviewed
- **Consequence:** callers can reasonably expect deadline cancellation while a slow polling relay can wait indefinitely; queued transmit data has no explicit protocol-level backpressure contract.
- **Recommendation:** design deadline/cancellation/backpressure semantics together at the relay seam; avoid one-off timers that create another state owner.

### Delivered findings

- **F-001:** fixed provisioning log replay deadlock/channel-close race by deleting the unused subscriber lifecycle.
- **F-002:** bounded remote SSH output and removed command/stderr from returned errors.
- **F-003:** runtime replacement now restores the previous configuration after failed replacement startup.
- **F-004:** removed unconditional configuration `Save` and duplicate `GetCopy`; revision CAS is the mutation interface.
- **F-005 / F-013:** retired unconsumed privileged/shallow modules (admin SSH, Linux tproxy, generic job runners, obsolete Android lab socket adapter).
- **F-006:** removed 38 zero-consumer Failover DNS resolver methods from the internal interface.
- **F-007:** removed GSA relay self-alias/redeclaration compile blocker.
- **F-008:** resolved NAT `TCP`/`UDP` constant/type namespace collision without renaming the live listener types.
- **F-009:** live serverless relay now verifies TLS certificates.
- **F-010:** relay close state is atomic/idempotent under concurrent I/O.
- **F-011:** shared failed-write rollback snapshots pending bytes before resetting the buffer.
- **F-012:** WebTunnel now uses the canonical relay WebSocket adapter; unpinned connections use normal PKI, explicit SHA-256 pinning remains available for private/self-signed endpoints.
- **F-014:** added cross-platform stdlib-only Go syntax/declaration integrity verification.

## Deep-module assessment

### Provisioning execution module — deepened

The former log subscription interface forced callers to understand replay buffers, channel lifetime, draining, and unsubscribe behavior even though production callers discarded the stream. The deletion test showed the subscription module was shallow: deleting it removed complexity instead of moving it. Provisioning now exposes log history and execution outcome; internal concurrency stays local.

### Runtime engine lifecycle module — deepened

The external `Start` interface remains small. Replacement preflight, stop/start ordering, restore, and combined rollback errors are now implementation details behind the same seam. This increases leverage: every engine replacement caller gets transactional recovery without learning new lifecycle steps.

### Configuration authority module — deepened

The interface no longer advertises two mutation semantics. Callers use revisioned snapshots and CAS. Removing the unconditional path improves locality because stale-writer policy exists in exactly one place.

### DNS resolver module — interface narrowed

This pass intentionally did not split the package by line count. The deletion test identified 38 exported internal methods whose removal does not move complexity to callers because there are no callers. Removing them is depth-positive; a package split without a second real adapter would be architecture theater.

### Relay transport module — partially deepened

Close ownership and failed-write rollback are centralized. The next depth step is not another adapter: it is to make deadline/cancellation/backpressure a real implementation behind the existing `net.Conn` seam.

### Rust FFI module — design first

The C ABI is the real seam and must not change casually. The right refactor deepens *inside* that seam: fewer unsafe input/string/error concepts for each export to know, while exported symbols and memory-ownership contracts stay fixed.

## Remediation portfolio

See `refactor-pass-remediation.csv` for the machine-readable dependency-ordered portfolio.

Priority order after this delivered pass:

1. **Design SSH host identity** before changing either live SSH adapter.
2. **Choose a pinned bootstrap policy** for unmanaged VPS hosts.
3. **Design relay deadline/backpressure semantics** behind the existing relay interface.
4. **Refactor Rust FFI internally** only in an environment with Rust/Cargo and ABI/CGO validation.

## Verification matrix

| Check | Scope | Result | Evidence / limitation |
|---|---|---|---|
| Provision logger race stress | current source | Pass | 100 repetitions under `-race` |
| Provision SSH bounded output | current source | Pass | 100 repetitions under `-race`; vet |
| Runtime engine replacement | current source | Pass | 100 repetitions under `-race`; replacement and rollback-failure cases |
| NAT package | current source | Pass | full exact-source package 100 repetitions under `-race`; vet |
| HTTP relay | current source | Pass | 100 repetitions under `-race`; TLS/close/rollback evidence |
| GSA relay | current source | Pass | 100 repetitions under `-race`; compile blocker and rollback evidence |
| WebTunnel trust/adapter | current source | Pass | 100 repetitions under `-race`; untrusted-cert rejection and explicit-pin acceptance |
| Go syntax/declarations | repository source/labs | Pass | Linux, Windows, macOS, Android active selections; zero duplicate top-level declarations |
| Rust build / Miri | native core | Blocked | Rust/Cargo unavailable |
| Full Go 1.26 workspace | daemon | Blocked | local Go 1.23.2; offline toolchain/dependency fetch unavailable |
| Canonical repository gates | whole repository | Pass | one-shot command passed through platform capability before external timeout; exact remaining Makefile tail then passed with bytecode disabled |
| Clean-extracted release | final artifact | See external release receipt | source is frozen before packaging; final archive hash/manifest/clean-extraction evidence is recorded externally to avoid self-referential source edits |

## Residual risks and next actions

The current risk frontier contains only the explicit Design-first/Blocked items F-015 through F-018 plus the unavailable full Go/Rust toolchains. None is hidden behind a “complete” label.

A suspicious evasion startup log was challenged and rejected as a finding because the actual value is already passed through the existing secret-redaction policy. An early DNS-statistics hypothesis was also rejected after exact receiver/call-site analysis showed the similarly named live callers belonged to other scanner types; the removed DNS stats methods were dead interface, not active false telemetry.

## Completion boundary

The **authorized refactor/remediation slice is implemented**, and every canonical repository verification command has executed successfully on the current source state. The in-tree source audit is complete. Immutable package integrity and clean-extracted verification are recorded in the external release receipt generated after this source state is frozen. Rust behavioral equivalence and full Go 1.26 workspace compilation remain explicitly blocked by toolchain availability and must not be represented as verified.
