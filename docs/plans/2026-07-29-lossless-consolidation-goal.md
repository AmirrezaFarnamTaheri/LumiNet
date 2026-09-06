# Goal

> **Status:** Historical session goal from the July 2026 consolidation/recovery effort. Current repository authority lives in `CONTEXT.md`, current architecture/ADRs, and the verified source tree; this file is retained as planning history.

Deliver the implementation-ready LumiNet Lossless Consolidation and Production Recovery Roadmap at `docs/plans/2026-07-29-001-refactor-luminet-consolidation-roadmap-plan.md`. The product outcome is a truthful, production-safe system with explicit canonical ownership for overlapping implementations, preserved peer-only behavior, reproducible historical evidence, and release claims backed by real verification.

# Scope

- Work through the roadmap's dependency-ordered units and Definition of Done, beginning with the preservation ledger (U1) and the already-planned foundation work.
- Treat existing uncommitted recovery work as valuable candidate progress: inspect and verify it before extending it; preserve unrelated user changes.
- Establish lossless consolidation evidence, TPM/native-secret lifecycle safety, truthful capability and redaction contracts, ABI/package authority, canonical domain boundaries, platform/client conformance, provenance generation, and release enforcement.
- Fix in-scope defects uncovered by verification rather than stopping at the first plausible patch.

# Boundaries

- The roadmap and its `session-settled:` decisions are authoritative. Do not alter the roadmap body to record progress.
- Do not delete a generated family, wrapper, porting shell, historical artifact, or pre-existing file merely because it appears redundant, unused, incomplete, or low quality. Retirement requires the roadmap's separate evidence gate and ADR.
- Preserve accepted peer details through explicit dispositions, adapters, specializations, or quarantine. Stop and surface an actual blocker when a security boundary, ABI/platform contract, or accepted behavior cannot be proven.
- Keep the Windows native bridge limited to `x86_64-pc-windows-gnu`; keep remote subscription/Telegram aggregation opt-in; never simulate successful runtime capability.

# Proof

- Use characterization or test-first evidence for behavior changes where practical, then run each active unit's specified verification and the applicable Verification Contract gates.
- Exercise affected real local surfaces where available; use deterministic fixtures as supporting evidence, not the sole product proof.
- Verify preservation/provenance coverage, consumer reachability, capability truthfulness, rollback behavior, platform support claims, clean generated artifacts, and package/runtime smoke paths as each becomes applicable.
- Review non-mechanical changes, address eligible findings, and report changed files, completed units, test evidence, residual risks, deliberate deferrals, and genuine blockers.
