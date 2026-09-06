# Android Labs

This directory is the intentional, non-compiled home for valuable Android porting fragments that are not ready for the canonical application source set.

## Contract

- `labs/` is project-owned capability evidence, not production source and not a deletion queue.
- Nothing here is included in `app/src/main` or any Gradle source set.
- Promotion requires a real owner/interface, lifecycle and coroutine review, tests or runnable integration evidence, and removal of placeholder/log-only behavior.
- `DefaultNetworkListener.kt` remains quarantined because it uses `GlobalScope`, `Dispatchers.Unconfined`, the obsolete `actor` API, and blocking synchronization. It must be redesigned around scoped lifecycle state before promotion.
- Other fragments are retained byte-for-byte from the original baseline and catalogued in `CAPABILITIES.csv`.

The supported Android application remains `src/apps/android/app/`.
