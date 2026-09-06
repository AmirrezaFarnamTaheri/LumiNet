# LumiCore Labs

`source-alternates/` preserves source and data that existed under the Rust crate source root but was not part of Cargo's reachable module graph at the convergence baseline.

These files are retained as project evidence, not compiled source. Promotion requires an explicit target owner, dependency and platform review, focused tests, and removal of any competing authority. The relative path under `source-alternates/` mirrors the prior crate-module grouping; the current compiled crate is `src/packages/lumicore/`.
