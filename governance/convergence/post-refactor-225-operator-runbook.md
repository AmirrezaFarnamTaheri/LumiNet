# Post-refactor-225 operator runbook

## Principle

Planner surfaces are evidence tools. They do not become runtime authority merely because they appear in the UI. Use them to review a prospective configuration, then apply changes through the existing authenticated owner where an actual write is intended.

## DNS

Use the DNS page to load a resolver preset into the unsaved resolver draft, inspect DoH pool evidence, and review transport/fallback policy. Loading a preset does not apply it. The normal DNS apply action remains the write boundary. A secure policy must not silently downgrade to plaintext fallback.

## Connections

Use endpoint dispatch evidence to compare quality-first, least-loaded, weighted-quality and sticky strategies. Health/circuit/capacity make candidates ineligible before secondary strategy ordering. Secondary strategies may only reorder candidates inside the existing quality band. Use multiplex policy to review protocol/version, connection/stream limits and bounded padding; it does not open sessions.

## Rules

Use routing-artifact provenance to verify source URL, format, source version, size and SHA evidence before any external process imports a rule artifact. The planner never downloads or installs the artifact. Use offline L7 admission for bounded `name::RE2-expression` evidence; it hashes/adjudicates expressions and never captures traffic or installs a classifier.

## WARP / WireGuard

Use Settings/WARP scan evidence to compare observed endpoints and export/copy evidence. Copy/export does not activate the endpoint. Use the WireGuard readiness planner for peer identity, AllowedIPs ownership/overlap, replay/rate/cookie and lifecycle timing evidence. Key material must be explicit in actual proxy configuration.

## Health

Use incident planning to distinguish first failure, incident opening, reason changes, maintenance suppression, notification grace and recovery. It does not send notifications or persist state; the output is a reviewable transition recommendation.

## Logs

Search and severity filters are local views over already loaded log data. Export is an operator-side export action. WebSocket broadcast drops and slow-client disconnects are monotonic backpressure observations and should be investigated when nonzero; they are not reconstructed from current queue depth.

## Profiles

Profile/node search is bounded local search across already materialized metadata. It does not fetch subscriptions. Node activation/import/export continue through existing profile/subscription authority.

## Operations convergence lab

The lab intentionally retains advanced read-only planners for KCP, SNI, TLS fingerprint, DNS, multiplex, routing, artifacts, incident, queues, workflows and WireGuard. Every surface is planning-only; none installs policy or opens sockets. Use natural pages for routine workflows and Operations for cross-plane analysis.

## Failure handling

- If an artifact is quarantined, do not bypass the result by manually copying private keys or mutable remote data into general state.
- If a candidate is ineligible because TLS is unverified, treat it as measurement evidence only.
- If a workflow planner reports a cycle/unknown dependency/executable action, fix the declarative input rather than executing it outside the target owner.
- If a config mutation exhausts retry attempts, reread current state and present the conflict; do not increase retry loops blindly.
- If an explicit expected revision conflicts, the operation is intentionally not replayed automatically.
