# Audit evidence

This directory separates current generated inventory from historical audit artifacts.

- `current-inventory/` is regenerated from the present repository with `make inventory`.
- `inventory/` is the immutable inventory of the original recovered archive; its old paths are evidence, not navigation.
- dated `*.md` reports are point-in-time audits.
- `change-manifest.csv`, `change-summary.json`, and removed-artifact reports describe historical transformations.

Do not hand-edit `current-inventory/`; regenerate it after the repository reaches a clean final state.
