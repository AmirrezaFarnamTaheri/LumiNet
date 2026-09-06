# Organize live source under src and dependency bands

Status: Accepted

## Context and Problem Statement

Live product source was split between top-level `apps/` and `packages/`, while the daemon placed more than fifty internal packages in one flat namespace. The flat layout hid dependency direction: foundational state, protocols, platform mutation, networking, runtime orchestration, workflows, and transport adapters appeared as peers even when callers formed a clear layered graph.

Repository tooling, historical labs, deployment assets, and governance evidence also sat beside live source. That made repository navigation and automated ownership checks harder because path shape did not communicate whether a file was product source, preserved evidence, or tooling.

## Considered Options

- Keep the existing roots and rely on package names/documentation.
- Move `apps/` and `packages/` under `src/` but keep the daemon internal namespace flat.
- Make `src/` the live source root and group daemon internals into dependency bands derived from the actual import graph.

## Decision Outcome

Use `src/apps/` and `src/packages/` as the only live application/shared-package roots. Keep `docs/`, `governance/`, `labs/`, `scripts/`, `deploy/`, `tests/`, and `third_party/` outside `src/` because they are not live product source.

Group daemon internals into these ordered bands, deepest first: `foundation`/`native`, `protocols`/`platform`, `networking`, `analysis`/`integrations`, `runtime`, `workflows`, and `adapters`. Cross-band imports may point only to a lower rank; same-band imports are allowed. The `cmd` composition root sits outside `internal/` and may depend inward.

Every meaningful source folder carries a `.context` file describing purpose, contents, interface/dependencies, invariants, and child ownership. Generated/copied packaging trees (`control-ui/dist`, `control-ui/public`, Android `res`) are documented by their parent context instead of receiving files that could alter shipped artifacts.

Rust module internals remain structurally unchanged inside `src/packages/lumicore/src/`; their root moves under `src/`, but deeper re-bucketing remains Cargo-gated under ADR-0010.

## Consequences

Folder placement now communicates source authority and dependency direction, improving locality and repository navigation. Go internal import paths change to include the dependency band, so all callers and source-aware verification tooling must migrate together. Module declarations and public module roots remain unchanged, preserving external module identities.

Path-sensitive governance records must distinguish immutable historical provenance from current target paths. Source-layout checks and `.context` coverage become repository invariants. Future new daemon packages must choose the deepest band that can own their behavior without importing upward.
