# Post-refactor-224 security and trust model

## Trust boundaries

1. **Configuration CAS:** only server-owned side-effect-free intents may retry revision conflicts automatically. Default budget is 3 attempts, hard ceiling 8. A client-supplied expected revision is single-attempt and never replayed.
2. **Remote mutations:** provider/host actions keep their existing idempotent, reconcile-before-retry, or single-attempt safety classes. Local CAS retry does not widen remote authority.
3. **WebSocket fan-out:** bounded queue pressure may drop transient broadcast delivery or disconnect a slow client; monotonic counters expose this without creating a second persistent log.
4. **KCP runtime:** explicit configuration overrides win over policy advice; total FEC shards are bounded to 64; upstream dependency internals remain upstream-owned.
5. **DNS planning:** only HTTPS URLs are admitted; userinfo/credential-like query parameters and invalid bootstrap IPs are rejected. Resolver planning is side-effect free.
6. **L7 planning:** patterns are compiled/hashed offline only. There is no DPI, pcap capture, packet classifier installation or malware-inspection authority.
7. **Traffic profiles:** only bounded declarative delay/padding/burst/overhead/idle actions are admitted. Arbitrary executable actions fail closed.
8. **Routing corpus:** source material may be hashed/audited but mutable external donor lists never become live target routing authority.

## Volatile account rejection

`Iran-configs` live account/subscription endpoints are not copied. Their durable value is converted into credential-free synthetic parser fixtures for VMess, VLESS+Reality, Trojan, Shadowsocks, Hysteria2, TUIC and Juicity.

## Mutable routing data

`Iran-v2ray-rules` generated IP/domain bodies are time-sensitive external data and are not imported as durable target policy. Only provenance/generation/category mechanics and stable target-native intents survive.

## TLS

The JJ donor's certificate-disabled scanner/fronting behavior is rejected. No new insecure TLS fallback is introduced by this wave.

## KCP crypto

The exact pinned `kcp-go/v5@v5.6.72` source exposes AES-GCM. LumiNet adds it only as an explicit opt-in KCP cipher; existing `aes`, `aes-128`, `aes-192`, `aes-256` and other legacy methods retain existing behavior. This prevents a silent wire-compatibility migration. Runtime compilation of the new call remains statically validated rather than executed in this environment because the required Go 1.26 toolchain/dependency build is unavailable.

## Privileged fast path

L7MP's eBPF/UDP-offload machinery is rejected as a donor runtime authority. The only `*ebpf*` paths permitted under `src` are the two pre-existing LumiCore transport files already present in the frozen 223 baseline.

## DNS authority

OpenWrt/LuCI installation, UCI and RPCD mutation semantics are not imported. Resolver canary/fallback planning never mutates host DNS configuration.

## Marionette

Executable format actions, arbitrary plugins, updater execution and record/multiplexer runtime ownership are rejected or superseded. Only bounded non-executing graph/profile semantics survive.

## Lacuna

LACUNA call-stack spoofing, VEH, shellcode and EDR-bypass mechanics are not operationalized. The stale LumiNet `StackSpoofing` source/export is removed; shellcode/build mechanics remain negative evidence only.
