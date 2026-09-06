# Use durable transactional host-network mutations

Status: Accepted

## Context and Problem Statement

Machine-wide DNS, proxy, firewall, certificate, and TUN changes can strand the host when apply, verification, or process lifetime fails. Multiple reset algorithms also create conflicting authority.

## Considered Options

- Let each platform adapter mutate and best-effort reset its own state.
- Route mutations through one durable transaction with crash recovery.

## Decision Outcome

Use one host-network transaction: snapshot, persist recovery state, apply, verify, commit on success, and rollback/recover on failure. The watchdog consumes the same recovery contract rather than a second reset implementation.

## Consequences

Mutation and recovery logic gain locality and serialization. Platform adapters must supply exact snapshot/apply/verify behavior and cannot bypass the transaction owner.
