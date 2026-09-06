# Repository recovery and architecture plan

## Goal

Turn the uploaded mixed artifact into a source-focused, buildable, reviewable multi-platform project without losing provenance or silently promoting porting shells to supported capabilities.

## Completed first wave

- [x] Reconcile every ZIP entry with extracted files.
- [x] Generate complete inventory, duplicate analysis, hashes, and tree listing.
- [x] Create a clean copy and record every excluded file.
- [x] Repair the Makefile and desktop frontend embed seam.
- [x] Centralize toolchain declarations.
- [x] Move historical porting documents under an explicit archive.
- [x] Establish canonical Android project and incubator boundary.
- [x] Add repository audit/inventory tooling and Graphify integration.

## Next implementation waves

### Wave 2 — verification and CI

- Pin every GitHub Action to a full commit SHA with a readable version comment.
- Run Go 1.26.5 tests, vet, race tests, and cross-platform compile checks.
- Run Rust format, check, Clippy, tests, and FFI ABI fixtures.
- Reinstall frontend dependencies on each target platform; run lint, build, audit, and UI smoke tests.
- Generate Gradle wrapper in a networked Android environment and compile `:app`.
- Install Graphify and commit no generated graph; publish graph-derived architecture findings as dated audit evidence.

### Wave 3 — proxy deepening

- Add characterization tests for startup, configuration transitions, rollback, snapshot, and shutdown.
- Extract a proxy runtime module behind a small lifecycle interface.
- Consolidate transport registration around validated specifications.
- Quarantine or delete log-only port shells only after reference and capability scans prove no live owner.

### Wave 4 — Rust surface truth

- Map `core/src/lib.rs` exports against all Rust files.
- Classify compiled, feature-gated, test-only, and dormant porting code.
- Move dormant code under an explicit incubator or remove it with provenance evidence.
- Split the FFI implementation behind one versioned interface and strengthen allocation/panic tests.

### Wave 5 — product enrichment

Only after baseline verification:

- typed Go/TypeScript control contracts;
- accessible frontend empty/error/degraded states;
- Android state holder and lifecycle-safe Flow model;
- structured logs and RED metrics at runtime seams;
- reproducible multi-platform release manifests and SBOMs.

## Pre-mortem gates

Assume the recovery failed and the next release regressed behavior.

| Failure path | Prevention requirement | Gate |
|---|---|---|
| Generated artifacts returned | `scripts/repo_audit.py` must report zero compiled/dependency artifacts | required in CI before build |
| Android project only looked complete | Gradle wrapper plus `:app:assembleDebug` and manifest test evidence | Android remains `unverified` until green |
| Proxy move broke hidden contracts | characterization tests before each extraction; one cluster per PR | no bulk package move |
| Dormant ports were mistaken for capability | every promoted module needs owner, tests, and capability reporting | release capability audit |
| Toolchain upgrade caused silent drift | pinned toolchain files and lockfile-preserving builds | clean CI on all target OSes |
| Graph output was treated as truth | graph findings must link back to source and tests | no graph-only approval |
