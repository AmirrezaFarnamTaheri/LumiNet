# Keep the repository tooling surface explicit

Status: Accepted

## Context and Problem Statement

The top-level `scripts/` directory accumulated a mix of supported build/development entry points, repository checks, compatibility launchers, one-off experiments, and abandoned installer/fetch helpers. File existence therefore implied an interface even when a script had no caller, no current documentation, or duplicated a deeper canonical command. CI compounded this by hand-running a subset of repository guards instead of consuming the root verification interface.

## Considered Options

- Keep every historical script as an implicit direct interface.
- Move all tooling behind a new monolithic command framework.
- Declare a small direct tooling interface, keep implementation helpers caller-reachable, and make CI consume the canonical repository verification interface.

## Decision Outcome

`scripts/README.md` declares the supported direct human-facing tooling interface. Top-level implementation helpers must either be a declared direct tool or have a live caller in Make, CI, or another script. Zero-consumer experiments and shallow compatibility launchers are retired instead of preserved as accidental interfaces.

`make verify-repo` remains the canonical repository architecture/truth verification interface. The repository architecture/truth interface remains `make verify-repo`. ADR-0022 composes it into `make verify-release`, which CI and tag publication consume instead of maintaining handwritten subsets of architecture guards.

## Consequences

Adding a new top-level executable under `scripts/` requires an explicit interface decision. Internal checks stay free to evolve behind Make/CI. Repository guards added to `make verify-repo` automatically reach CI and tag admission through `make verify-release`. Historical evidence may still mention retired scripts without making them current interfaces.
