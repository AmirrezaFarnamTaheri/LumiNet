# LumiNet ultimate operator runbook

## Tor client pluggable transports

Use the existing capability-guarded `POST /api/system/engines` endpoint with `engine: "tor"`, `action: "start"`, bridge lines, and registered `transport_plugins`. The live API accepts client transport names `obfs4`, `snowflake`, and `webtunnel`. Executable fields, when supplied, must reduce to the registered executable basename; arbitrary paths are rejected. Only Snowflake may currently receive the narrowly approved `-keep-local-addresses` client argument. Missing/unexecutable binaries fail preflight before a currently healthy Tor engine is stopped.

Example request shape (illustrative; bridge parameters must come from a trusted bridge source):
```json
{
  "engine": "tor",
  "action": "start",
  "socks_port": 19050,
  "bridges": ["obfs4 <bridge-address-and-parameters>"],
  "transport_plugins": [
    {"name": "obfs4", "executable": "lyrebird"}
  ]
}
```

Do not pass shell fragments, paths, or general process flags. Transport configuration is data admission, not process-launch authority.

## Tor exit evidence
`POST /api/system/tor/exit-check` accepts an IP and optional `via_tor`. With `via_tor: true`, the active Tor engine must already be running; encrypted DNS is sent through its loopback SOCKS port. Responses are tri-state: `exit`, `not_exit`, or `unknown`. Treat `unknown` as lack of evidence, not as non-exit.

## Filesystem observation
The canonical file watcher is an internal notification primitive. It survives atomic replacement by watching parent directories and filtering exact paths. It is **not** authorization to add another automatic config reconciler. Runtime configuration authority remains with the existing durable config/CAS owners.

## Endpoint/TLS evidence
Endpoint quality and enriched TLS peer data are diagnostics/evidence. They are not currently connected to automatic route-selection authority. Promotion requires production comparative measurement, explicit ownership, rollback/fallback behavior, and operator visibility.

## Failure handling
- Invalid Tor transport requests fail before replacement.
- Missing transport binaries fail preflight before replacement.
- Invalid encrypted-DNS proxy configuration fails closed; it does not fall back direct.
- DNS resolver/provider failure yields `unknown` for DNSEL rather than a false negative.
- Existing remote mutations continue to use the provider-scoped bounded retry/reconciliation plane; do not add bespoke retry loops around side effects.
