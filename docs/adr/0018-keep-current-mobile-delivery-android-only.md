# Keep current mobile delivery Android-only

Status: Accepted

## Context and Problem Statement

The repository has one current mobile product host: the Android `VpnService` app. CI and release build the generated Android AAR and linked APK. Historical and target-specific iOS code remains in Go/Rust source, and `docs/future-extensions.md` tracks an iOS binding as future work, but there is no current iOS application host, CI product lane, or release artifact. A legacy helper script still generated an iOS XCFramework on macOS, which made build behavior contradict supported-host documentation.

## Considered Options

- Keep opportunistic iOS framework generation in the current mobile helper despite having no shipped iOS host.
- Treat Android as the only current mobile delivery path and require a complete product path before iOS becomes supported.

## Decision Outcome

Current mobile delivery is Android-only. `scripts/mobile_bind.sh` builds and links the Android AAR only. Target-specific iOS source may remain guarded for compatibility, validation, or future implementation, but it is not a supported host merely because it compiles under an iOS build tag.

An iOS delivery path may return only when all of the following exist together:

1. a current iOS host/application owner;
2. a CI lane that builds and verifies that host against the intended binding/native path;
3. a release artifact with packaging/provenance ownership; and
4. current architecture/capability documentation naming iOS as supported.

## Consequences

Current build helpers, platform matrices, and supported-host documentation cannot imply an iOS product that the repository does not deliver. Existing iOS-specific Rust/Go code is not deleted by this decision; native visibility or ABI retirement remains governed by ADR-0010 and its Cargo-backed proof gate.
