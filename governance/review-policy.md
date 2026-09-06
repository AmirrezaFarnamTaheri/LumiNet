# Review Evidence Policy

Review evidence is current only when each claim has a dated, reproducible source link. Generated summaries, scores, and “ready” markers are
not release authority by themselves.

## Required evidence

- exact source paths and commit/worktree state;
- commands, tool versions, and raw output locations;
- scope, owner, and review round;
- failed, skipped, and unavailable checks;
- explicit disposition for every unresolved risk.

A review may be called `ready` only when every referenced artifact exists, all
required gates have dated evidence, and no planned round remains open without
an explicit waiver. Missing historical review files are recorded as missing;
they are never reconstructed as completed evidence.

The current consolidation scope and status are maintained in
`docs/current-system.md`, the active roadmap, and the conductor ledgers.
