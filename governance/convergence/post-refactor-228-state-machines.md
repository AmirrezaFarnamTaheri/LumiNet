# Post-refactor-228 state machines and recovery

## Configuration mutation
`fresh snapshot -> mutate callback -> revision CAS -> committed` with revision conflicts only returning to `fresh snapshot`. Explicit expected revision has no retry edge. Exhaustion is bounded.

## Browser handoff
`install-required | identity-incomplete | offline | permission-incomplete -> ready`. Planning cannot transition the real browser/native host. Reconnect guidance is finite `1000,2000,4000,8000 ms`.

## Worker planning
`observed -> preferred -> selected | spillover | fail-open`; protocol readiness requires `{"ready":true}` before correlated NDJSON requests. Desynchronization/hard-cap failure implies recycle in the owning runtime; this planner starts no process.

## WireGuard translation evidence
`observed -> admitted -> live-valid`; persisted records after restart become `needs-revalidation` and cannot be restored directly. Expired/duplicate/zero/unbound mappings are rejected.

## Subscription node activation
`materialized -> compatibility-evaluated -> activatable | planning/import-only`; hidden or incompatible nodes cannot transition through the UI activation action. Runtime process ownership remains one active exact profile/node pair.
