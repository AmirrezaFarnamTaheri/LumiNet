# Own subscription ingestion and refresh in one module

Status: Accepted

## Context and Problem Statement

Subscription profiles, safe remote fetch, refresh lifetime, format detection, and node parsing were split across `internal/sub`, API callbacks, `internal/proxy`, `internal/subparser`, and `internal/linkparser`. This duplicated formats and let HTTP create background refresh lifetime.

## Considered Options

- Keep multiple parsers and enforce parity at each caller.
- Make `internal/sub` own ingestion and refresh while reusing `internal/proxyconfig` for canonical per-node semantics.

## Decision Outcome

`internal/sub` owns profile state, caller-owned refresh lifetime, safe remote fetch, format detection, and normalization. Canonical node parsing flows through `internal/proxyconfig`. Transport and proxy callers consume the subscription interface instead of injecting parser callbacks or defining alternate models.

## Consequences

Refresh cancellation, SSRF policy, and format knowledge gain locality. Historical duplicate aggregators/parsers are retired. CAPTCHA retry remains an explicit ingestion option; the Apps Script coalescer path was retired after whole-repo proof showed no production subscription consumer. No separate HTML-extraction contract existed in the live subscription parser being consolidated. Adding a new subscription format now requires changing one ingestion owner and its fixtures.
