# Post-refactor-222 state machines and trust boundaries

## Configuration mutation

States: snapshot -> candidate callback -> compare-and-swap -> committed, or conflict -> fresh snapshot retry. Explicit-revision requests do not retry. Callback/non-conflict failures terminate without commit. Attempts are bounded to 3 by default and 8 maximum.

## Signed update staging

States: discover/expected metadata -> bounded HTTPS fetch -> redirect admission -> size/hash/signature verification -> temporary regular file -> file sync -> publication -> parent directory sync (Unix) -> receipt. Invalid metadata, non-HTTPS/public-target violations, oversize, digest/signature mismatch, redirect excess, non-regular target or sync/rename failure terminate without a successful stage result.

## Peer planning

States per candidate: unparsed -> parsed identity -> address policy -> local deny policy -> port/duplicate endpoint -> BEP42 identity -> admitted evidence -> globally sorted/truncated. Rejected candidates never reserve identity/endpoint state; a later valid observation remains eligible. No peer lifecycle persists beyond the request.

## Endpoint planning

States: validate observations -> score evidence -> determine eligibility -> deterministic near-equal diversity -> optionally promote prior success inside quality band -> bounded dispatch order. Prior success and diversity never create eligibility.

## Health projection

States: loading -> source snapshots -> healthy/degraded/unavailable. Source failures remain visible as source-level status; missing evidence cannot collapse to healthy. Export is an allow-listed snapshot, not backend state.

## Trust boundaries

- Operator/browser -> authenticated local API.
- API -> typed analysis planners (read-only) or explicit mutation owners.
- Donor evidence -> governance/implementation decisions only; never direct authority.
- Runtime trust store -> peer planner descriptive snapshot only.
- LocalStorage -> appearance and command-palette recents only; never backend authority.
- Update network -> public/secure admission and bounded verification before filesystem publication.
- General config/log/UI state -> secret redaction/reference boundaries.
