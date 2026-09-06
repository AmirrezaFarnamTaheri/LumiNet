# Keep mobilebind adapter-only

Status: Accepted

## Context and Problem Statement

The gobind package manually mirrored evasion configuration and reported different safety-policy behavior than HTTP. That made a platform adapter behave like a second semantic owner and exposed raw evasion status fields.

## Considered Options

- Let mobile maintain independent defaults/status/capability behavior.
- Keep gobind translation shallow and route semantics to canonical owners.

## Decision Outcome

`internal/mobilebind` is an adapter only. Mobile status consumes the evasion module's redacted snapshot, startup maps through the proxy-owned mobile/evasion conversion, and safety validation uses the shared `SafetyGovernor` and default settings owner.

## Consequences

Mobile keeps gobind-compatible JSON and lifecycle concerns while capability truth stays shared. The mobile wire shape includes every canonical evasion field plus mobile-only sensor/outbound fields.
