# Post-refactor-232 peer synthesis

SplitPT contributes per-packet round-robin/random scheduling, 8-byte session identity, uint16 framing limits and queue behavior; its silent-drop/fatal-recovery behavior becomes negative evidence rather than runtime code. DNS-Tunnel-Deploy contributes delegation, MTU, listener/redirect, service-user, key-lifecycle, systemd/firewall sequencing and rollback knowledge without root authority. Outline contributes static invite unwrapping, static/dynamic access-key classification, connection/repository/product semantics while LumiNet retains runtime/persistence owners. PYDNS contributes bounded lifecycle, batching, drain limits, cache busting, Slipstream/SlipNet mode vocabulary and negative evidence against binary/MTU authority.

Mechanically: 750 files, 611 definitions, 218 modules, 433 high-signal surfaces, 57 UI/product surfaces, and 47 focused behavior records.
