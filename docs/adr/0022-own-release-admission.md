# Own release admission behind one verification seam

Status: Accepted

## Context and Problem Statement

The repository already had strong verification, but tag publication did not consume it. `ci.yml` ran only for branch pushes and pull requests, while `release.yml` ran for `v*` tags and built/published artifacts without repository truth gates or the Rust, Go, desktop, and control-UI tests used to define a verified change. The release workflow also rebuilt the control UI in a separate job, so the bundle packaged into host artifacts was not necessarily the exact bundle exercised by the verification path.

This duplicated release knowledge across workflow YAML and made successful compilation act as an implicit substitute for admission.

## Considered Options

- Keep branch CI and tag release independent, relying on maintainers to tag only commits whose earlier branch CI was green.
- Duplicate the full CI test sequence inside `release.yml`.
- Define one release-admission interface in repository tooling and require both CI and tag publication to consume it.

## Decision Outcome

Release admission has one interface: `make verify-release`. It composes the vendored repository-tool tests, ABI and preservation-ledger validation, repository truth gates, pinned-database dependency audits (`govulncheck` and `cargo audit`), Rust format/Clippy/tests, Go vet plus CGO/non-CGO tests, desktop tests, and control-UI tests/lint/build.

The Make interface owns what must pass. Workflow adapters own only prerequisites that Make cannot provision reproducibly itself: the pinned audit-tool installation and the deterministic history base used by preservation validation.

Linux CI consumes that interface before its full linked host build. The former standalone preservation/security jobs are folded into admission so they cannot drift from tag policy. Pull-request/branch CI supplies the event base SHA; tag admission supplies the previous release tag (or the empty tree for the first release) as the preservation base. The tag release workflow consumes the same interface before any platform build. The control-UI bundle produced by the admitted release job is uploaded once and is the bundle downloaded by Linux, Windows, and macOS packaging jobs.

Platform-specific release jobs remain responsible for target compilation and packaging; admission remains responsible for proving the source state is eligible to enter those jobs.

## Consequences

A tag cannot reach platform packaging or publication merely because compilation succeeds, nor can it bypass the dependency-security or preservation checks required by branch CI. Adding or removing a release-critical test belongs in the admission interface rather than requiring synchronized edits to CI and release YAML. The packaged desktop/control UI is tied to the admitted verification run rather than a second unverified frontend build.

Release workflows may still contain target-specific build, SBOM, signing/attestation, and packaging logic because those are adapters after the admission seam rather than duplicated admission policy.
