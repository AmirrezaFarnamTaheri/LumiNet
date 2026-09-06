# Own governance authority discovery in validator modules

Status: Accepted

## Context and Problem Statement

After the live source and governance trees moved, repository-tool commands still embedded old `conductor/` and `core/` paths. CI supplied explicit corrected paths, which let those stale defaults survive while local/default command interfaces were wrong. The same class of split authority appeared in frontend development tooling: the control UI declares npm and ships `package-lock.json`, while dev launchers required pnpm.

## Considered Options

- Keep canonical repository paths duplicated in every command, workflow, and compatibility launcher.
- Make each validator module discover its own canonical authority from repository root while retaining explicit path overrides.
- Introduce a separate path-registry module shared by unrelated tooling.

## Decision Outcome

The ABI manifest, preservation ledger, and provenance ledger modules own canonical authority discovery from repository root. Their command path flags are override-only. CI and compatibility launchers pass repository root plus policy inputs and rely on the same default discovery exercised by module tests.

The control UI has one package-manager interface: npm. Build and development tooling use that interface and the checked `package-lock.json`; no second package manager is required for normal development.

## Consequences

Repository relocations require updates in the owning validator module instead of synchronized edits across every caller. CI exercises the same default interface used locally, improving locality and making stale paths fail at the owner. Explicit overrides remain available for fixtures, migrations, or alternate evidence roots.

Frontend development no longer adds an unnecessary package-manager seam. Package-manager choice is owned beside the UI manifest/lockfile and enforced by host-product verification.
