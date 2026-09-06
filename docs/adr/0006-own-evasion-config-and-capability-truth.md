# Own evasion configuration and capability truth

Status: Accepted

## Context and Problem Statement

HTTP, CLI, and mobile reconstructed a wide evasion configuration independently, imported dozens of defaults, and could advertise simulated or incomplete covert modes as running. Secret-bearing status/log paths also diverged.

## Considered Options

- Keep transport-specific configuration assembly with parity tests.
- Put defaults, validation, redaction, and lifecycle semantics behind the evasion module.

## Decision Outcome

The evasion runtime owns canonical defaults, normalization, fail-closed covert-mode validation, redacted snapshots, listener lifecycle, and internal dial policy. Transport adapters translate their wire inputs and consume the same capability truth.

## Consequences

Defaults and secret handling gain locality. Some public wire structs remain wide for compatibility, but they may not define independent semantics or silently enable simulator-only transports.
