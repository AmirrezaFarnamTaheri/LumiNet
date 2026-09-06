# Prefer deep modules over package-count optimization

Status: Accepted

## Context and Problem Statement

After organizing daemon source into dependency bands, several folders still looked suspicious when judged only by file count, LOC, or number of packages. Those measures conflict: `runtime/proxy` is large but callers now use only a small evasion/qualification interface, while some tiny one-caller packages hide protocol state, process lifetime, platform variation, or external integrations behind a useful seam.

Repeated cleanup also showed the opposite failure mode: historical/test-only implementations can remain inside an otherwise live package and make its apparent interface much wider than the product interface.

## Considered Options

- Minimize package count by merging every one-caller module.
- Split large packages until each folder is small.
- Judge modules by interface depth, locality, dependency direction, and proven liveness.

## Decision Outcome

Optimize for **deep modules**, not package count or LOC. Apply the deletion test before merging: merge a module only when deleting its interface removes indirection rather than spreading state/protocol complexity into callers. Apply the locality test before splitting: split only when callers currently learn unrelated knowledge that can move behind a coherent owner.

Large implementations may remain intact when their caller-visible interface is small and coherent. One-caller modules remain valid when they own substantial state, protocol semantics, process lifetime, platform variation, curated data, or a true external adapter. Test-only, self-contained, and zero-consumer implementations are retired instead of being kept to make a module look more capable.

Dependency bands from ADR-0015 remain the placement rule. Package changes must preserve downward imports, regenerate local `.context` metadata, and pass topology/reachability plus ownership/capability truth gates.

## Consequences

Repository shape can no longer be evaluated from folder count alone. Architecture reviews require caller/interface evidence and explicit deletion/locality reasoning. This reduces cosmetic churn while increasing locality: large deep modules are allowed to stay large, and shallow compatibility or dormant implementations do not survive merely because they have tests.
