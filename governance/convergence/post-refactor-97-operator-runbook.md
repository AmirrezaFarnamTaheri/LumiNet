# LumiNet post-refactor 97-donor operator runbook

## Tor startup

A successful Tor engine start now means the child process is alive **and** authenticated control bootstrap reports progress 100. Startup probes begin immediately and retry temporary cookie/control availability errors every 250 ms inside a 60 s bounded window. Early process exit or startup timeout is a hard failure and the child is torn down. Operators should therefore interpret slower startup as Tor bootstrap latency rather than a daemon hang.

## Tor control failures

Raw control commands containing CR, LF, or NUL are rejected before any socket write. Commands have a bounded size and deadline; replies have a 1 MiB aggregate bound. A timeout, malformed framed reply, status-code mutation, or connection failure invalidates the current control connection. Reconnect through the normal TorController path rather than reusing a failed socket.

## Authorization

ControlFilter patterns match the complete command line. A command that starts with an allowed verb/shape but carries unapproved trailing arguments is denied. Do not loosen this with prefix-only regular expressions.

## Network authority

Do not install donor iptables scripts, LD_PRELOAD torsocks interception, tun2tor's userspace stack, or a second Tor service/controller beside LumiNet's owners. The peer evidence is retained as guardrail/reference material; target mutation must continue through the existing host-network/runtime authority boundaries.

## Validation boundary

On this host, changed Tor Go seams are validated through dependency-isolated exact-source harnesses under the race detector (100 repetitions) plus go vet. Full workspace Go 1.26, Rust/Miri, and Android validation require the declared toolchains in an environment that can provide them.
