# Let the terminal stream event own FFI callback lifetime

Status: Accepted

## Context and Problem Statement

Cancellation can race with late Rust callbacks. Freeing Go callback context at cancellation can cause use-after-free; retaining it without one terminal owner leaks memory.

## Considered Options

- Free callback state when cancellation is requested.
- Keep ownership until Rust publishes exactly one terminal callback.

## Decision Outcome

Cancellation is only a signal. Rust retains stream ownership until completion and emits one terminal `STREAM_EVT_SCAN_DONE`; only that callback lets Go close the channel, remove the sink, and free callback memory.

## Consequences

The callback lifetime is race-safe and testable. The retained stream ABI is currently dormant/stubbed and is not a production scan capability; ABI retirement remains Cargo-gated.
