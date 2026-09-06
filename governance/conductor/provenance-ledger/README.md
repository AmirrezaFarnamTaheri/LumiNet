# LumiNet Provenance Ledger

This directory is the immutable source-evidence side of the consolidation
program. It is intentionally separate from
`conductor/preservation-ledger`, which owns mutable peer dispositions.
The two ledgers associate records through `source_ref`; neither copies the
other ledger's authority.

## Storage contract

- `sources.v1.jsonl` contains one Draft 2020-12 `schema-v1.json` source record
  per line.
- A `source_ref` is permanent and unique. Existing JSONL lines may not be
  edited, removed, or reordered. New records are appended.
- `immutable_locator` is relative to this directory and must resolve to a
  regular file below it. Symlink escape, missing files, size mismatch, and
  SHA-256 mismatch fail validation.
- Upstream absence, an unresolved commit, a suspected force-push, and
  contradictory evidence are recorded explicitly with qualification evidence.
  They are never silently treated as qualified.
- Every source and peer `source_ref` declared by the preservation ledger must
  resolve to a validated provenance record before validation or generation
  succeeds.
- Raw files under `raw/snapshots` are immutable evidence. A corrected or newer
  source is a new snapshot and a new source record, not an overwrite.

Duplicate display names are permitted because identity is `source_ref`.
Windows and POSIX locator separators normalize to the same generation input.

## Offline verification

From `scripts`:

```text
GOWORK=off GOPROXY=off go run -mod=vendor ./cmd/validate-provenance-ledger
GOWORK=off GOPROXY=off go run -mod=vendor ./cmd/generate-provenance-inputs
```

On PowerShell, set the variables with `$env:GOWORK='off'` and
`$env:GOPROXY='off'`.

Outside CI, the normal commands derive their trusted append-only baseline from
the repository `HEAD`. CI must set `PROVENANCE_BASE_REF` (or `-base-ref`) to its
approved merge base; when `CI` is set, the commands deliberately have no
implicit git baseline and fail closed. An explicitly materialized trusted prior ledger may be
passed with `-base-ledger <path>` or `PROVENANCE_BASE_LEDGER`; it takes
precedence over the git ref. Validation refuses to run when neither baseline is
provided. The validator performs no network requests and compares every prior
line byte-for-byte before validating newly appended records, all raw snapshots,
and preservation-ledger references.

During the initial uncommitted bootstrap, `HEAD` has no provenance ledger yet;
use `-base-ledger` with an explicitly reviewed empty baseline. After bootstrap
is committed, the supported default command derives the approved ledger from
`HEAD`, so editing, deleting, or reordering an existing line fails without
extra flags.

The generation-input command emits a stable, `source_ref`-sorted JSON document
containing only immutable locators, digests, sizes, retrieval timestamps,
upstream commits, and qualification states. U20 generators consume this
verified boundary rather than reading mutable trackers or compendia directly.
