# Post-refactor-226 operator runbook

## General rule

Every new 226 planner is advisory. Inspect its output, then use the existing authenticated runtime/configuration owner for any actual change. Never treat a planner response as an implicit write, installation, network probe, browser registration, process restart, or credential operation.

## Rules: local rule normalization

Paste bounded local AdGuard/hosts/Clash/Surge/LumiNet rule text into the Rules planner. Review detected syntax, normalized domains/CIDRs/actions, duplicates and rejected lines. The planner fetches no URL and installs no classifier/ruleset. Apply accepted policy only through the normal rule/config owner.

## Settings: Tailnet transaction evidence

Select the intended transaction shape and provide explicit ETag/revision evidence for revision-bearing operations. Distinguish DNS patch from DNS replacement. Device-route changes remain target-device-scoped. Key creation and webhook-secret rotation are sensitive one-shot operations; the planner itself never receives a Tailnet credential or makes the API call.

## Settings: browser handoff

Use browser handoff evidence to verify profile identity, native-host install/online state, required permissions, message-size bound and a loopback-only proxy target. `install-required`, `offline`, `permission-incomplete` and `ready` are intentionally distinct. Registration and browser proxy mutation remain external to the planner.

## Health: worker affinity/recovery

Supply observed worker health/load/capacity evidence. The planner returns deterministic affinity or bounded spillover. No eligible worker yields fail-open evidence rather than an infinite wait. Review the capped restart-backoff schedule; no process is started or restarted.

## Connections: WebSocket readiness

Do not treat an open TCP port as a healthy WebSocket backend. Ready requires observed TCP reachability plus HTTP 101, `Upgrade: websocket`, `Connection: upgrade`, the exact `Sec-WebSocket-Accept`, and verified TLS when TLS is expected. Failure reasons identify the missing protocol evidence.

## Operations: gateway composition

Describe service IDs, roles, dependencies and observed health. The planner rejects unknown roles/dependencies and dependency cycles, then returns topological start order, reverse rollback order, unhealthy evidence and bounded restart backoff. It does not download binaries or write systemd, cron, runit, Caddy or other service configuration.

## WireGuard/MWGP evidence

Treat translated receiver-index mappings as short-lived state: unique nonzero index, bounded source identity, explicit future expiry, maximum 24-hour lifetime. Obfuscation is only a traffic-shape property and must never be used to justify authentication/confidentiality/replay claims.

## Protocol failures

- Unsupported proxy protocol: correct the configuration; do not coerce it to SOCKS.
- Invalid SS2022 PSK: supply method-correct base64 key components; do not pad/truncate.
- No valid SSH auth: provide a valid key or explicit password fallback before retrying.
- Invalid SOCKS host/port/ATYP: fix the endpoint or peer; do not narrow/truncate the value.

## Configuration conflicts

Default mutation retry is bounded to three attempts, eight maximum. Each revision-conflict retry rereads authoritative state. An explicit expected revision receives exactly one attempt. Non-conflict failures are not replayed automatically.
