# Post-refactor-228 operator runbook

- **Rules:** use local rule-set and policy-group planning as previews; they perform no remote probe, fetch, or installation.
- **Profiles:** imported nodes now display maintained-core activation truth. Planning/import-only nodes remain visible/manageable but cannot be activated.
- **Settings:** browser handoff shows browser identity/native-host contract and readiness only; it does not register a host or change browser settings.
- **Health:** worker affinity view includes protocol framing/readiness/backpressure/recycle bounds; no worker process is started by the planner.
- **Operations:** gateway presets and WireGuard index-translation recovery are read-only plans; SNI gateway literal self-loop conflicts block readiness.
- **SSH tunnels:** encrypted private keys may use a passphrase; the passphrase is secret-bearing and is never part of redacted operator payloads.
- **Retries:** configuration mutation retries are automatic only for revision conflicts. Explicit CAS revisions are not retried. External side effects belong outside the mutation callback; remote actions use their own safety classes/reconciliation.
- **Known gap:** Linux process-owner attribution remains unavailable in the target native core until compiled/native evidence supports a deliberate promotion.
