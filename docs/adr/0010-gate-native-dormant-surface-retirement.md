# Gate native dormant-surface retirement on Cargo proof

Status: Accepted

## Context and Problem Statement

The Rust tree retains a stub streaming scan ABI and zero-consumer crypto surfaces. Removing compiled modules or C ABI exports without a Rust toolchain could create link, symbol, or compatibility failures that static grep cannot prove away.

## Considered Options

- Delete zero-reference Rust/ABI surfaces from static evidence alone.
- Freeze zero-consumer status and require native verification before retirement.

## Decision Outcome

No dormant native surface may gain a production consumer. Module/export retirement or implementation requires pinned Cargo fmt, Clippy, tests, ABI/header validation, and CGO bridge verification. The current reachability classification lives in `governance/topology/wave17-native-reachability.json`.

## Consequences

Capability truth improves without making unverifiable native edits. The active Rust graph remains larger until hosted native CI supplies the required proof.
