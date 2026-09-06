# Own typed and secret-safe async job intents

Status: Accepted

## Context and Problem Statement

Handlers and runners previously shared a stringly JSON convention. Fields could be accepted and ignored, and provisioning credentials were copied into SQLite-backed `Job.Config` and history/export surfaces.

## Considered Options

- Keep raw JSON and add per-handler redaction/validation.
- Make typed job intent the jobs-module interface and keep serialization internal.

## Decision Outcome

Every job kind submits a sealed typed intent. The jobs module owns normalization, execution intent, secret-safe history encoding, persistence, event publication, and result/evidence serialization. Execution credentials remain in memory only.

## Consequences

Schema drift becomes visible in code and secrets no longer need persistence. Legacy persisted rows are scrubbed on hydration. Public transport request structs remain adapters where wire shapes differ.
