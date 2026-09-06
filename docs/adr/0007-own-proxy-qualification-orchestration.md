# Own proxy qualification orchestration

Status: Accepted

## Context and Problem Statement

CLI and async jobs independently selected Xray/sing-box, constructed `CoreManager` and `ProxyTester`, managed progress, and normalized results. Two real core adapters justify a seam, but callers owned its protocol.

## Considered Options

- Keep duplicated caller orchestration.
- Introduce one qualification module around the existing concrete core adapters.

## Decision Outcome

One proxy-qualification module owns ephemeral core selection, binary/config/process lifetime, tester construction, cancellation, progress, and normalized results. CLI and jobs submit qualification intent.

## Consequences

Temporary processes and files have one lifetime owner. Callers lose concrete-core knowledge. Long-lived runtime engines remain separate under ADR-0003.
