# Conductor Workflow & Operational Rules

## 1. Evidence-first changes
For behavior changes and bug fixes, use RED -> GREEN -> refactor whenever the failure can be reproduced locally. If the required toolchain/runtime is unavailable, add the strongest truthful static/contract gate and keep the unexecuted proof boundary explicit.

## 2. Repository authority rules
- Preserve every original-baseline object through byte-identical relocation, an explicit reviewed transform, or a separately justified retirement.
- Supported source roots contain only reachable shipped code. Dormant/alternate value belongs in hash-accounted `labs/` or `governance/reference/`.
- Do not create a second owner for session discovery, UI source/embed assets, API routes, public errors, build identity, FFI declarations/linking, Android VPN lifecycle, or release orchestration. The decisions are indexed by `governance/convergence/split-brain-synthesis.csv`.
- Compatibility surfaces delegate to canonical owners; they do not maintain parallel business/runtime state.

## 3. Verification
- Run `make verify-repo` after structural or governance changes.
- Run focused behavior tests for every changed domain, then repository-wide lanes supported by the current environment.
- Do not substitute a weaker local toolchain for the repository-required Go/Rust/Android build and call it release proof.
- Keep workflow actions SHA-pinned and validate workflow/shell syntax after delivery changes.
- Refresh `docs/audit/current-inventory/` only after the tree stops moving.

## 4. Delivery hygiene
- Keep changes scoped and reviewable.
- Do not commit, push, publish, or release without explicit authorization.
- Do not weaken a failing guard to obtain green; fix the implementation or the demonstrably incorrect guard.
