# LumiNet documentation

Start with [`current-system.md`](current-system.md). It is the current product/ownership manual and tells you which capabilities are live, degraded, unavailable, or historical.

## Current navigation

- [`current-system.md`](current-system.md) — current product and ownership truth.
- [`api/current-routes.md`](api/current-routes.md) — served route inventory and workflow surface.
- [`architecture/`](architecture/) — current architecture, dependency, security, and protocol material.
- [`guides/`](guides/) — quickstart, CLI, development, build, and validation guidance.
- [`runbooks/`](runbooks/) — operator procedures such as TPM migration and general operations.
- [`adr/`](adr/) — append-only accepted architecture decisions.
- [`future-extensions.md`](future-extensions.md) — explicitly future/non-current work.
- [`product-strategy.md`](product-strategy.md) — productization and market source material.

## Evidence and history

- [`audit/`](audit/) — current generated inventory plus dated/historical audit evidence.
- [`plans/`](plans/) — implementation plans retained for decision history, not current authority.
- [`porting/`](porting/) — porting history; archived material lives under `porting/archive/`.
- [`excluded/`](excluded/) — explicitly rejected or non-adopted source material.

## Authority rule

Current behavior comes from live source, tests, generated/current contracts, `CONTEXT.md`, accepted ADRs, and machine-readable governance. Historical plans, audits, porting reports, screenshots, and donor paths remain evidence only.

The canonical domain glossary is [`../CONTEXT.md`](../CONTEXT.md). Structural changes should update the nearest current guide/architecture document and append an ADR only when the decision is durable and non-obvious.
