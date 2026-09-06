# Own operational capability truth at the runtime owner

Status: Accepted

## Context and Problem Statement

Several advanced HTTP routes constructed private mutable objects inside the transport package and returned success even though no production runtime consumed that state. Simulation, analysis, and operational control therefore shared one shallow interface and capability status could overstate what the daemon actually changed.

## Considered Options

- Keep handler-owned subsystem objects and document which routes are best-effort.
- Require operational mutations to cross a real runtime owner and classify disconnected behavior as analysis-only, compatibility-only, unavailable, or retired.

## Decision Outcome

HTTP transport does not own operational runtime state. Each advanced route has explicit capability truth; a mutation may report operational success only when a production owner consumes and exposes the resulting state. Disconnected or simulator-only controls fail closed.

## Consequences

Capability reporting is more local and testable, and removing a transport handler cannot silently remove runtime state. Some historical advanced controls are intentionally unavailable or retired until a real owner and executable verification exist.
