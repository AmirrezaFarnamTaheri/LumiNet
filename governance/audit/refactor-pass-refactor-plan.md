# Refactor plan: harden the remaining SSH, relay, and Rust seams

## Problem Statement

LumiNet's recent convergence work has concentrated authority into stronger modules, but three remaining seams still make callers understand or tolerate behavior that should live behind a deeper interface.

First, both live SSH use cases authenticate users but do not authenticate the server because expected host identity is not represented in the domain model. Second, the polling relay adapters satisfy a connection interface while leaving deadline and backpressure semantics undefined. Third, the native Rust bridge preserves a useful stable C ABI but repeats raw-pointer, JSON, panic, and string-allocation mechanics across many exports, including a raw-string conversion with overly broad lifetime semantics.

A fourth adjacent risk is provisioning bootstrap provenance: unmanaged hosts can run a mutable remote installer as root. This needs a product policy decision before implementation because narrowing supported hosts or requiring a preinstalled runtime is an observable behavior change.

## Solution

Deepen the existing seams rather than add parallel abstractions.

SSH server identity should become an explicit validated value consumed by both real SSH use cases. The trust behavior must be visible to operators and must fail closed on mismatch. Relay deadline, cancellation, and transmit-queue bounds should be implemented once behind the existing connection seam. The Rust bridge should keep its exported C contract unchanged while copying raw input into owned validated Rust data immediately and centralizing common panic, JSON, error, and output-allocation behavior.

Provisioning bootstrap should use an explicitly supported and integrity-verifiable installation strategy selected before code changes begin.

## Commits

1. Add characterization tests for current provisioning SSH success/failure behavior without changing trust semantics.
2. Add characterization tests for current runtime SSH tunnel success/failure behavior.
3. Define a validated SSH server-identity value and unit-test parsing/normalization only.
4. Add host-key mismatch tests against an in-process SSH server fixture.
5. Add host-key rotation/changed-key tests and define the operator-visible failure result.
6. Thread optional server-identity data through provisioning intent without changing the existing default yet.
7. Thread optional server-identity data through runtime tunnel configuration without changing the existing default yet.
8. Make both SSH adapters consume the same host-identity matcher.
9. Add configuration/request round-trip tests for trusted host identity.
10. Add redaction tests proving host trust metadata is non-secret while SSH credentials remain secret.
11. Choose and document the migration rule for configurations that lack host identity.
12. Apply that migration rule and remove insecure host-key callbacks from provisioning.
13. Apply the same migration rule and remove insecure host-key callbacks from the runtime tunnel.
14. Add end-to-end negative tests proving a mismatched host cannot be used even with valid user credentials.
15. Add operator diagnostics for unknown, matched, and mismatched SSH host identity without exposing credentials.
16. Characterize relay read/write behavior under slow polling, cancellation, and stalled remote delivery.
17. Define the maximum transmit queue and deadline semantics at the existing relay connection interface.
18. Add failing tests for write deadline expiry before changing implementation.
19. Add failing tests for read deadline expiry before changing implementation.
20. Add failing tests for bounded transmit queue exhaustion and recovery.
21. Implement one internal relay deadline state owner shared by the HTTP and GSA adapters.
22. Implement bounded transmit queue behavior and explicit temporary/permanent error classification.
23. Verify failed-write prepend ordering still holds when queue limits and deadlines interact.
24. Verify concurrent close, deadline change, read, and write behavior under the race detector.
25. Freeze and compare the exported Rust C symbol set before any native refactor.
26. Add Rust tests characterizing null, invalid UTF-8, valid JSON, invalid JSON, panic, and allocation/free behavior at the existing C seam.
27. Replace borrowed raw-string conversion internally with immediate owned input conversion while preserving every exported C function.
28. Introduce a typed internal FFI input error and preserve the externally documented error envelope.
29. Centralize panic capture and output allocation for JSON-style exports behind one internal function.
30. Move JSON deserialization/serialization mechanics into that internal function without moving domain behavior.
31. Convert a small representative export set to the new internal path and run ABI plus Go/CGO verification.
32. Convert remaining JSON-style exports in small batches, verifying the ABI and representative host calls after each batch.
33. Add operation-specific safety documentation to every unsafe export touched by the migration.
34. Remove the blanket missing-safety-documentation suppression only after the crate passes lint without it.
35. Run Miri on the raw-input/allocation helper tests and resolve every finding without weakening assertions.
36. Run the complete Rust, ABI, Go/CGO, and packaged-artifact verification suite.
37. Characterize current Docker bootstrap behavior on each supported provisioning host family.
38. Decide the supported bootstrap source: pinned packages, pinned repository metadata, or digest-verified installer artifact.
39. Add integrity/version tests for the chosen bootstrap source.
40. Replace mutable remote script-to-shell execution with the chosen verified strategy.
41. Add failure/rollback diagnostics for unavailable or integrity-mismatched bootstrap material.
42. Run provisioning integration tests on every supported host family before declaring the bootstrap migration complete.

## Decision Document

- Keep one SSH trust concept shared by provisioning and runtime tunnel use; do not create unrelated trust implementations.
- Do not keep an insecure host-key fallback hidden inside adapters.
- Treat host identity as trust metadata, not as a credential secret.
- Keep the existing relay connection seam; deepen its implementation rather than create another transport interface.
- Deadline, cancellation, transmit bounds, and failed-write recovery belong to one relay lifecycle model.
- Keep the Rust C ABI unchanged during the native refactor.
- Prefer owned raw-input conversion over any borrowed helper that fabricates a lifetime from a C pointer.
- Prefer internal functions/generics over macros for common FFI mechanics unless a concrete syntax requirement proves a macro necessary.
- Do not modify Rust source until the Rust toolchain, ABI checks, and Go/CGO host verification are available.
- Do not choose a provisioning bootstrap migration implicitly; supported-host policy and artifact provenance are part of the decision.

## Testing Decisions

Good tests exercise behavior through the same interface used by real callers. Tests should avoid inspecting private helper structure unless the helper itself owns a safety invariant that cannot be observed through the public seam.

- SSH tests exercise connection acceptance/rejection through provisioning/runtime adapter behavior with in-process SSH fixtures.
- Relay tests exercise the connection interface: read, write, close, deadlines, cancellation, queue exhaustion, and retry ordering.
- Rust tests exercise the stable C seam and memory ownership, supplemented by focused internal tests for unsafe conversion/allocation invariants.
- Provisioning bootstrap tests exercise the supported host workflow and integrity failure path rather than matching command strings.
- Existing transaction, convergence, topology, ABI, and race tests remain mandatory regression evidence.

Prior art in this repository includes transactional runtime replacement tests, revision-CAS configuration tests, exact-source relay race/TLS tests, and host-network snapshot/apply/verify/rollback tests.

## Out of Scope

- Replacing SSH with a different remote-management protocol.
- Rewriting the Tor/Psiphon runtime architecture.
- Changing the exported LumiCore C ABI or renaming FFI exports.
- Adding another relay protocol or another host-network mutation authority.
- General package-count reduction or file splitting without a demonstrated deep-module payoff.
- Performance optimization without profiling evidence.

## Further Notes

This plan was produced from the supplied frozen source archive and the connected repository metadata. The archive itself contains no Git metadata, so branch-relative source drift must be checked before executing the remaining commits against the remote default branch.
