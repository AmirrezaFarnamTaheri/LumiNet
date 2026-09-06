# Post-refactor-228 security and authority model

- SSH encrypted-key passphrases are admitted only with a key, participate in the existing pre-network auth gate, and are redacted/restored as secrets.
- Shadowsocks SIP003 plugin/prefix intent is never silently dropped: compatible sing-box plugins are retained; incompatible sing-box/Xray intent fails closed.
- Browser planning accepts only explicit loopback `http://` or `socks5://` endpoints without credentials/query/fragment and never registers a host or changes proxy settings.
- SNI gateway self-loop admission uses literal endpoints only and performs no DNS/network I/O.
- WireGuard index-translation mappings are nonzero, unique, peer-bound, future-expiring (<=24h), and persisted entries require post-restart revalidation; the planner rewrites no packets.
- Automatic config retry is single-owned, conflict-only, fresh-snapshot, default 3/max 8; explicit CAS is one attempt. Remote mutations remain separately classified by idempotency/reconciliation safety.
- Mutable peer provider/rule/SNI corpora remain reference evidence, not routing authority.
- TinyTun eBPF, peer browser host registration, SNI UI installer/downloader, and reverse-tunnel root/system service mutation remain outside target authority.
