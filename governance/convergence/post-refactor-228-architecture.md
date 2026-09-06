# Post-refactor-228 architecture

## Scope
228 is a second-order successor audit over the frozen 227 source and all 15 raw donor archives already represented by waves 226/227. It re-audits 1,349 donor files, 268 directory/root Merkle records, 16,310 definitions, and all 949 predecessor semantic records without increasing the historical donor count.

## Promoted target-native planes
- **Routing policy plane:** extended local rules plus manual-select, latency-auto, fallback, and deterministic weighted load-balance planning; no remote probe/install authority.
- **Browser companion contract:** Chrome/Firefox identity, native-host manifest allowlists, bounded native-message framing, explicit commands, loopback-only proxy targets, and finite reconnect backoff; no host registration or browser mutation.
- **Gateway composition presets:** reverse TLS relay, websocket edge, and managed edge tunnel expand into the existing bounded DAG/start/rollback model.
- **WireGuard recovery evidence:** receiver-index translation becomes a read-only identity/expiry/revalidation contract, never a second packet mutator.
- **Worker process contract:** ready handshake, correlated NDJSON, depth-one affinity queue, unbuffered spillover, frame/readiness caps, recycle-on-desync, fail-open cancellation, and cold-first-call telemetry.
- **Subscription runtime truth:** parsed/imported protocols are distinguished from maintained-core executable protocols before activation.

## Single owners retained
Configuration mutation retry remains `foundation/config.Manager.Mutate`; external proxy runtime remains CoreManager; SNI raw-packet injection remains the existing platform runtime owner; subscription parsing/materialization remains ProfileService/NodeCatalogue; UI remains non-authoritative.

## Explicit platform gap
TinyTun demonstrates Linux socket-to-process attribution via inet_diag + `/proc`, but LumiCore still returns an empty process-owner view off Windows. Cargo/rustc are unavailable here, so 228 records this as a real residual capability gap rather than shipping an uncompiled Rust native-path claim.
