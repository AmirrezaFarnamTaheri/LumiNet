# Post-refactor-224 operator runbook

## Convergence policy lab

Use Operations for read-only endpoint, KCP, resolver, L7, traffic-profile and routing-corpus planning. These planners describe evidence and recommended policy; they do not install DNS, inspect packets, execute Marionette actions or mutate system proxy state.

## Endpoint selection

`quality-first` remains the baseline. `least-loaded`, `weighted-quality`, and `sticky` may reorder only candidates inside the existing near-equivalence band. Treat `unhealthy`, circuit-open and full-capacity endpoints as ineligible. Degraded evidence is negative only.

## KCP

Legacy behavior remains the default when no 224 profile/overrides are supplied. Explicit zero/false overrides are preserved through share-link round trips. AES-GCM is opt-in via `crypt=aes-gcm` (or explicit key-size variants); do not assume older peers support it.

## DNS pool

Resolver plans accept HTTPS candidates only. Credential-bearing URLs and malformed bootstrap IPs are invalid. `active`, `reserve`, `invalid`, and fallback order are evidence outputs only; apply DNS changes through the existing host/DNS owners, not the planner.

## WebSocket and mutation reliability

System status exposes local configuration CAS counters separately from remote-mutation counters and WebSocket fan-out counters. Broadcast drops mean transient clients may need to re-read authoritative state. Slow-client disconnects are not evidence of durable job loss.

## Routing/signature/profile evidence

Do not promote donor mutable routing lists into durable authority. L7 signatures are offline validation assets only. Traffic profiles are declarative analyses; unsupported executable actions are rejected rather than sandboxed or run.
