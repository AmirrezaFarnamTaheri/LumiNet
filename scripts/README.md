# Repository tooling

`scripts/` is a small public tooling interface backed by internal verification and generation code.

## Direct tools

| Tool | Purpose |
|---|---|
| `build-all.sh` | Build LumiCore, control UI, daemon, watchdog, and desktop host on Linux/macOS. |
| `build-all.ps1` | Windows counterpart to the full host build. |
| `dev.sh` | Run Linux/macOS development watchers and dev servers. |
| `dev.ps1` | Windows counterpart to development mode. |
| `graphify.sh` | Generate and validate Graphify output transactionally. |
| `mobile_bind.sh` | Build the supported Android gomobile AAR and place it in the Android app dependency tree. |

The root `Makefile` owns canonical build, test, verification, inventory, and release-admission workflows.

## Internal layout

- `checks/` contains the flat repository verification implementation, including native-link resolution. These files are not independent product interfaces and must have a live Make/CI/script caller.
- `generate/` contains deterministic repository/source metadata generators.
- `cmd/`, `internal/`, and `vendor/` are the language-imposed layout of the offline Go tooling module.

Do not add new executable helpers at the `scripts/` root unless they are intentionally promoted to the documented direct interface.

## Windows packet dependency

WinDivert-backed raw packet injection is an external runtime dependency, not a repository fetch/install interface. LumiNet does not bundle WinDivert in source or current Windows release artifacts. Operators who enable those Windows modes must supply a trusted WinDivert distribution themselves; runtime startup fails closed when the DLL/driver is unavailable.
