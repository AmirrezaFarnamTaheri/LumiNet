# Own daemon background lifetime from one caller

Status: Accepted

## Context and Problem Statement

Scheduler work, WebSocket subscriptions, cron tasks, middleware tickers, and HTTP shutdown previously had independent lifetime owners. That made quiescent shutdown and deterministic tests impossible to prove.

## Considered Options

- Let each constructor start background work with its own context.
- Make process lifetime caller-owned and pass cancellation downward.

## Decision Outcome

Use one daemon-lifetime owner. Background work participates in the caller-owned cancellation/shutdown path; constructors do not create process lifetime implicitly.

## Consequences

Shutdown and tests cross one interface and can prove ownership. Local adapters may still own shorter-lived contexts when they also expose explicit `Close`/`Stop` semantics.
