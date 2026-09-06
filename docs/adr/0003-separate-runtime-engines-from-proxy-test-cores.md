# Separate runtime engines from proxy test cores

Status: Accepted

## Context and Problem Statement

Long-lived Tor/Psiphon state and temporary Xray/sing-box proxy-test processes have different lifetime and status semantics. Treating both as one runtime owner previously created split state and false capability reports.

## Considered Options

- Put every network core behind one global manager.
- Keep long-lived runtime engines separate from ephemeral qualification cores.

## Decision Outcome

`internal/runtimecore` owns long-lived Tor and Psiphon runtime engines. Proxy qualification owns temporary Xray/sing-box cores only for bounded test sessions.

## Consequences

Runtime status has one authority and qualification cannot leak temporary process state into daemon runtime state. Some shared process-launch mechanics may remain internal implementation details rather than a shared external seam.
