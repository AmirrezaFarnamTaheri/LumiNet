# Rust FFI deepening RFC — ABI-preserving internal refactor

## Decision

Do not modify LumiCore FFI source in this environment. Rust/Cargo are unavailable, and the FFI seam is a compatibility authority. A source-only edit without compilation, ABI verification, and Go/CGO checks would be lower quality than leaving the known debt explicit.

## Current friction

The C ABI itself is the correct seam, but the implementation behind it is shallow in two ways:

1. raw C-string input conversion returns a reference with a caller-selected lifetime, even though the pointer provenance cannot justify that lifetime;
2. many JSON exports repeat the same unsafe pointer conversion, panic guard, JSON parse, error serialization, and owned-C-string return pattern.

Null input and invalid UTF-8 are currently collapsed to the empty string. That makes input provenance/error classification less explicit than the rest of LumiNet's fail-closed contracts.

## Target shape

Keep every exported symbol, calling convention, argument layout, result layout, allocator/free function, and Go private ABI header unchanged.

Deepen only the Rust implementation behind that seam:

- raw input is copied immediately into an owned Rust value inside the unsafe entry scope;
- null input and invalid UTF-8 become explicit typed input errors;
- the unsafe pointer lifetime cannot escape the conversion helper;
- panic capture, JSON input decoding, domain invocation, JSON output encoding, and output allocation are centralized in one internal call path;
- async/runtime-specific work remains supplied as behavior to that internal path instead of being hidden in macros;
- exported functions retain operation-specific `# Safety` documentation;
- remove the blanket missing-safety-doc suppression only when all exports satisfy the contract.

## Alternatives considered

### One macro per JSON export

Rejected as the default. It reduces line count but moves complexity into macro expansion and makes diagnostics/test locality worse. Rust guidance prefers functions/generics unless a macro is required by syntax.

### Convert raw pointer to borrowed `&str`

Rejected. A helper returning an unconstrained borrow from a raw C pointer keeps the lifetime problem alive even if the signature looks cleaner.

### Owned input plus internal generic function

Recommended. It removes the fabricated lifetime and concentrates common FFI mechanics without changing external ABI.

## Required evidence before merge

1. `cargo fmt --check`.
2. `cargo clippy` with correctness/suspicious/unsafe documentation checks.
3. full Rust unit/integration/ABI tests.
4. Miri for FFI helper tests that can execute under Miri.
5. existing LumiCore ABI checker and Go private-header compatibility checker.
6. Go/CGO smoke tests for representative JSON, binary, streaming, allocation/free, null input, invalid UTF-8, panic, and error cases.
7. symbol-table comparison proving no exported C symbol drift.
8. clean release build using the repository-pinned Rust toolchain.

## Acceptance criteria

- no raw C-string helper can fabricate an arbitrary Rust lifetime;
- null and invalid UTF-8 input have distinct, stable failure envelopes;
- common JSON FFI mechanics exist in one internal module;
- C ABI and Go host declarations are byte/semantic compatible;
- no blanket unsafe-documentation suppression remains;
- all required Rust and host verification is executed, not inferred.
