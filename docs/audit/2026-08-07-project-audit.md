# Project audit — 2026-08-07

> **Historical recovery baseline.** This document records the first cleanup wave. Current Graphify/refactor state, pinned CI inputs, and later verification are tracked in [`2026-08-07-graphify-hardening-audit.md`](./2026-08-07-graphify-hardening-audit.md). Do not use the "watch" rows below as the current release verdict.

Scope: complete uploaded archive, all 8,319 ZIP entries and all 7,772 files after extraction.  
Repair status: first recovery wave applied in this clean copy.  
Original rollback source: `LumiNet.zip` remains unchanged outside this project directory.

## Evidence inspected

- Full ZIP central-directory inventory and extraction reconciliation.
- Every top-level module, language manifest, workflow, build script, source subtree, hidden directory, binary, dependency tree, and historical document.
- Go, Rust, Kotlin/Java, Swift, TypeScript/React, shell/PowerShell, deployment, and enterprise code.
- Focused static inspection of the desktop embed seam, Makefile, Go workspace, Android fragments, CI, Rust crate surface, and the 690-file Go proxy package.

Detailed machine evidence is under `docs/audit/inventory/`; excluded payloads are recorded in `docs/audit/removed-artifacts.csv`.

## Checklist status

| Area | Status | Evidence |
|---|---|---|
| Repository contents | repaired | 339 MiB working tree reduced to a source-focused tree; every exclusion is hashed and recorded. |
| Build orchestration | repaired | duplicate `build-go` target removed; frontend path now points to `desktop/frontend`. |
| Desktop packaging | repaired | Wails embeds `frontend/dist`, not source and dependencies. |
| Toolchain contract | improved | `.go-version`, `go.work` toolchain, `.nvmrc`, Rust toolchain, EditorConfig added. |
| Android | partial | canonical Gradle module, manifest, resources, and incubator boundary added; build not executed. |
| Documentation | repaired | porting research moved out of root and marked historical. |
| Dependency health | watch | lockfiles retained; online audits could not run in the restricted environment. |
| Test health | watch | frontend type-check passed before cleanup; native/Go/Android full suites require unavailable toolchains. |
| CI supply chain | watch | floating GitHub Action tags remain and are reported by `scripts/repo_audit.py`. |
| Architecture | watch | `server/internal/proxy` remains a 690-file, roughly 108k-line god package. |

## Findings

1. **Critical — uploaded archive mixed source with reproducible and native outputs.**
   - Evidence: checked-in `node_modules`, three Windows test executables, four duplicated `lumicore.dll` files, caches, and nested VCS state.
   - Impact: non-portable installs, misleading source size, accidental distribution of stale binaries, slower review and security scanning.
   - Action: removed from the clean copy; exact hashes and reasons are preserved in `removed-artifacts.csv`.
   - Confidence: high.

2. **Critical — root build target did not build the real frontend.**
   - Evidence: Makefile searched `server/web` and `desktop/package.json`; the actual package is `desktop/frontend/package.json`; `build-go` was defined twice.
   - Impact: false-success builds and divergent release behavior.
   - Action: replaced with one explicit build graph.
   - Confidence: high.

3. **Critical — desktop host embedded the whole frontend tree.**
   - Evidence: `//go:embed all:frontend` included source and could include dependencies.
   - Impact: oversized binaries and accidental source/dependency packaging.
   - Action: production assets now cross a small `fs.FS` seam rooted at `frontend/dist`.
   - Confidence: high.

4. **Watch — Android source had no project boundary.**
   - Evidence: Kotlin/Java code existed, but no Gradle files, wrapper, manifest, or resources existed in the archive.
   - Impact: Android capabilities could not be built or validated despite being presented as project code.
   - Action: canonical `mobile/android` module added; incomplete/deprecated ports quarantined in `incubator/`.
   - Confidence: high.

5. **Watch — proxy ownership is too broad.**
   - Evidence: `server/internal/proxy` contains 690 Go files and roughly 108k source lines, including adapters, runtime lifecycle, transports, policy, metrics, and port shells.
   - Impact: weak locality, slow navigation, broad change blast radius, and shallow tests around internal seams.
   - Action: staged deep-module plan in `docs/architecture/deep-module-opportunities.md`; no unsafe bulk move was attempted.
   - Confidence: high.

6. **Watch — compiled Rust surface and porting surface are intermixed.**
   - Evidence: many small/log-only Rust port files coexist with the crate modules exported by `core/src/lib.rs`.
   - Impact: unclear ownership and capability truth; accidental promotion of stubs.
   - Action: recorded as a follow-up module-boundary task, requiring Cargo-based proof before relocation.
   - Confidence: medium-high.

7. **Watch — CI actions use floating tags.**
   - Evidence: workflow `uses:` entries include `@v4`, `@v5`, `@stable`, and third-party floating tags.
   - Impact: supply-chain inputs can change without a repository diff.
   - Action: audit tool emits warnings; pinning is a separate, reviewable workflow-only change.
   - Confidence: high.

## Checks not run

- Go tests/build: local Go is 1.23.2; the project selects Go 1.26.5 and outbound toolchain download is unavailable.
- Rust format/check/test: Rust/Cargo are absent.
- Android build/test: Gradle, Android SDK, and wrapper are absent.
- Full npm install/build/audit: the archive contained Windows-native dependencies and outbound package access is blocked. Direct TypeScript compilation succeeded before cleanup.
- Graphify extraction: CLI absent; installation/source download blocked.

## Overall assessment

**At risk before recovery; watch after recovery.** The clean copy has a defensible source boundary and coherent entry points, but release readiness still depends on native toolchain verification, Android compilation, CI action pinning, and staged decomposition of the proxy and Rust porting surfaces.
