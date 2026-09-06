# Repository topology reconstruction

## Goal

Reconstruct the previously verified LumiNet repository topology from the preserved 2,442-file baseline after the transient execution workspace was reset. The target remains a coherent `apps/`, `packages/`, `deploy/`, and `governance/` ownership model with behavior-preserving deep-module extractions.

## Invariants

1. Every one of the 2,442 baseline files remains accounted for during topology waves.
2. A baseline file may be byte-identically relocated or explicitly transformed with a reviewed reason; no retirement is allowed until the post-wave convergence phase.
3. Public or compatibility-facing Go symbols are retained unless an explicit convergence decision proves a stronger owner and no unique behavior.
4. Distinct peer mechanisms are not collapsed merely because names overlap.
5. Each risky owner extraction gets characterization or differential proof before acceptance.
6. The existing frontend 7/7 and relay 14/14 regression lanes remain green where runnable.
7. Full Go 1.26.5, Rust, and Android equivalence remains unclaimed while those toolchains are unavailable.

## Reconstruction slices

1. Canonical repository roots and build/audit path contracts.
2. Serverless relay client and live relay server ownership.
3. Tarpit and focused proxy owners.
4. Apps Script relay client and proxy configuration/parser ownership.
5. Disconnected and connected dormant experiment preservation.
6. General presets and API support ownership.
7. TLS fragmentation and censorship-doctor ownership.
8. Recompute the remaining live proxy graph and finish only evidence-backed ownership seams.
9. Post-wave convergence: promote/revive unique historical value and retire only objects proven to add no distinct value.

## Proof and rollback

Each slice is committed independently after focused tests, repository audit, topology accounting, and `git diff --check`. The Git history is the rollback boundary. The reconstruction does not claim to reproduce lost local commit hashes; it reproduces the verified state and evidence contracts.

## Review focus

- accidental public API loss;
- relative-path/build-workspace regressions;
- duplicated authority after extraction;
- false dead-code classification caused by build tags, cgo, embeds, external-package consumers, or mixed tests;
- inappropriate consolidation of distinct peer mechanisms;
- final retirements without bidirectional provenance and a no-additional-value proof.
