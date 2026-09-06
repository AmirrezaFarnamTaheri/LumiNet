# Retire proven-unconsumed internal source

Status: Accepted

## Context and Problem Statement

Repeated convergence waves left internal implementations that had no production consumer but remained active because they were self-contained, test-only, or historically ported. Keeping them in active packages inflated capability surface and made future liveness reviews ambiguous.

## Considered Options

- Keep dormant internal implementations as tested future capability.
- Retire internal source once product, test/non-Go, registration, reflection, platform, and native liveness have been explicitly dispositioned.

## Decision Outcome

Internal source with no product consumer is removed from the active graph once liveness proof excludes dynamic/native/platform entry paths. Characterization tests alone do not make a capability product-live. External cgo/JNI/build-tag seams remain until their target toolchains can prove retirement. Historical migrations and governed lab provenance are retained when deletion would erase compatibility or audit evidence.

## Consequences

Active code better reflects shipped capability and future audits have fewer false surfaces. Retirement requires explicit evidence and topology accounting; uncertain dynamic or platform consumers stop deletion rather than being guessed away.
