# Prove scanner liveness before retirement

Status: Accepted

## Context and Problem Statement

The scanner package contains active behavior and historical capability corpus in one Go package. Package-level reachability cannot prove symbol/file liveness because one imported symbol makes every file appear reachable.

## Considered Options

- Prune files from grep-only or package-level zero-reference evidence.
- Require symbol/build-tag/registration/platform proof before moving a whole file.

## Decision Outcome

Retire scanner code only after proving no active symbol, method receiver, build-tag, registration, reflection, native, platform, or test consumer. Proven files are byte-preserved under governed labs; mixed files stay active.

## Consequences

Dormant corpus can leave the product without speculative deletion. The proof burden is higher, but platform/JNI/implicit entry points are protected from accidental removal.
