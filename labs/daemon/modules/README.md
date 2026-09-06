# Daemon module islands

This tree preserves complete Go package islands that were present under `apps/daemon/internal/` but are unreachable from every declared supported daemon product/library root. They are non-authoritative experiments or compatibility peers, not live runtime packages.

`MODULE_ISLANDS.csv` records each preserved file, its baseline provenance, byte hash, and original canonical-path location. Promotion requires a live owner, explicit imports, focused tests, and topology/convergence evidence.
