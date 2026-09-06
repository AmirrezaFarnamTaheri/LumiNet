# Flatten repository taxonomy while preserving semantic depth

Status: Accepted

## Context and Problem Statement

After live source converged under `src/`, both support trees and one live app namespace still reflected historical/category layouts: copied `internal/` and Android source-set chains in labs, preservation-wave folders, one-file governance wrappers, provider templates behind an extra category, internal repository checks mixed with direct scripts, and a doubly nested third-party module snapshot.

Those paths made the repository look more structurally complex than its current interfaces. At the same time, some deep paths are real contracts: Go package/module layout, Android package namespaces, provider-required deployment paths, vendored dependency structure, daemon dependency bands, and immutable provenance locators.

## Considered Options

- Preserve all historical directory structure and rely on documentation.
- Flatten every non-source path aggressively.
- Flatten taxonomy/copying artifacts while retaining depth that encodes a real interface, package, deployment, or immutable evidence contract.

## Decision Outcome

Use the third option.

- `src/apps/` contains direct runnable app peers; namespace-only app wrappers are not kept when they own no source/build contract. The current Android host therefore lives at `src/apps/android/`, beside `daemon/` and `desktop/`.
- within a module, one-file category folders are flattened when the parent already owns the same interface; the control UI keeps `AppLayout.tsx` beside `App.tsx` rather than preserving hypothetical `components/layout` namespaces.
- `scripts/` keeps only the documented direct human-facing adapters at its root; internal checks live one level under `scripts/checks/`, generators under `scripts/generate/`, and Go tooling keeps its language-required `cmd/internal/vendor` structure.
- `labs/` groups preserved code by stable package/domain role. Historical wave/source-tree scaffolding is removed; governance records carry provenance and retirement reason.
- deployment templates sit directly under their provider owner; canonical relay adapters sit directly under `deploy/relays/` unless a provider/runtime requires a subdirectory.
- documentation uses existing semantic groups (`architecture`, `guides`, `runbooks`, `plans`, `audit`, `porting`) instead of tool-specific or one-file wrapper directories.
- one-file governance wrappers are flattened when no independent interface exists.
- third-party modules are rooted at their actual module directory rather than an archive-name wrapper.

Do **not** flatten paths whose depth carries semantics: live daemon dependency bands; Go/Rust/Android package or module layout; `testdata`; provider-required paths such as Vercel `api/`; Go vendoring; `governance/conductor/`; and immutable provenance ledger locators.

## Consequences

Current navigation is shallower and describes ownership rather than migration history or taxonomy. Path-sensitive current manifests, checks, docs, and build configuration must move together, while immutable baseline/provenance identities remain unchanged. Future reviews must justify a new directory by the seam or contract it creates; category-only nesting is not sufficient. `repo_audit.py` rejects pure one-child/no-owned-file wrappers unless a documented semantic exception applies.
