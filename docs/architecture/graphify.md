# Graphify knowledge graph

LumiNet uses Graphify as an optional repository-analysis layer. The checked-in integration is version-pinned and excludes dependencies, generated output, vendored code, historical porting material, and audit snapshots through `.graphifyignore`.

```bash
uv tool install graphifyy==0.9.26
make graph
```

Expected output is written to `graphify-out/` and is intentionally untracked.

## Audit status

The historical audit recorded a Graphify 0.9.34 run in a network-enabled Floot VM. That exact version is not a reproducible public package pin in the sources rechecked on 2026-08-09, so the measured counts below are preserved as historical evidence rather than a current toolchain claim. The current CI/local version pin is `graphifyy==0.9.26`, which is published on PyPI and tagged by the upstream project. CI additionally verifies the published wheel SHA-256 before installation. Graphify's transitive Python dependencies are still resolved at install time and are not lockfile-pinned in this repository.

The historical full public-main pass recorded 5,359 nodes, 10,028 edges, and 402 communities across 505 code files. The historical production-oriented pass using this repository's `.graphifyignore` policy recorded 3,839 nodes, 7,031 edges, and 309 communities across 355 code files. CI now rebuilds a fresh code-only graph from the current tree and validates that `graphify-out/graph.json` is a non-empty NetworkX node-link graph.

Use `docs/audit/graphify-first-party-analysis.md` for the measured findings, interpretation guardrails, and prioritized refactor seams. The checked-in `.graphifyignore` intentionally excludes vendored, scratch, generated, archived, and test-only material so future runs emphasize first-party production architecture.
