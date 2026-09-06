# LumiNet CLI Navigation Reference

> **Authority:** the Cobra definitions under `src/apps/daemon/cmd/` define the live CLI. For flag names, defaults, and command-specific help, use `luminet <command> --help` (or `luminet <group> <command> --help`). This guide intentionally does not duplicate every flag.

## Root command

Running `luminet` with no subcommand starts the same daemon path as `luminet serve`.

Global configuration flags are:

- `--config`
- `--log-level`
- `--data-dir`
- Cobra's standard `--help` and `--version` surfaces

## Current command tree

```text
luminet
├── serve
├── scan
│   ├── icmp [targets...]
│   ├── ports [targets...]
│   ├── dns [domains...]
│   ├── tls [hosts...]
│   ├── sni [domains...]
│   └── wg [endpoints...]
├── diagnose
├── proxy
│   ├── test [proxy-uris...]
│   ├── parse [uris...]
│   ├── subscribe [url]
│   ├── export
│   └── generate [base-uri]
├── system
│   ├── dns
│   │   ├── apply [servers...]
│   │   ├── clear
│   │   └── status
│   ├── proxy-settings
│   │   ├── apply [server]
│   │   ├── clear
│   │   └── status
│   ├── ddns
│   │   └── force
│   ├── profiles
│   │   ├── list
│   │   └── apply [name]
│   ├── startup
│   │   ├── status
│   │   ├── enable
│   │   └── disable
│   └── evasion-tunnel
│       └── start
├── doctor
└── tpm
    ├── migrate
    ├── verify
    ├── inventory
    ├── rollback
    └── cutoff
```

## Verified usage examples

### Serve the daemon

```bash
luminet serve
luminet serve --host 127.0.0.1 --port 8470
luminet serve --stdio
```

`--web` is a legacy browser-hosted console path. The current desktop product is the Wails host under `src/apps/desktop/`.

### Scan targets

```bash
luminet scan icmp 192.168.1.0/24 --concurrency 100 --timeout 1500
luminet scan ports 10.0.0.15 --ports 22,80,443 --output json
luminet scan dns example.com --server 9.9.9.9 --record-type A
luminet scan tls example.com --port 443
luminet scan sni example.com
luminet scan sni example.com --ip 203.0.113.10
luminet scan wg 203.0.113.10:51820
```

Common scan flags live on `luminet scan`; inspect them with:

```bash
luminet scan --help
luminet scan ports --help
```

### Run diagnostics

```bash
luminet diagnose
luminet diagnose --phases 1,2,3 --json --output diagnostics.json
```

The phase set is defined in `src/apps/daemon/cmd/diagnose.go`.

### Work with proxies

```bash
luminet proxy parse 'vless://...'
luminet proxy test -f proxies.txt --concurrency 16 --speed-test
luminet proxy subscribe 'https://example.net/subscription'
luminet proxy export -f proxies.txt --format clash --output config.yaml
luminet proxy generate 'vless://...' --range 203.0.113.0/24 --sample 4
```

`proxy subscribe` fetches the URL supplied as its single argument. It has no `add` or `fetch` child command.

### Manage host network settings

```bash
luminet system dns status
luminet system dns apply 9.9.9.9 149.112.112.112
luminet system dns clear

luminet system proxy-settings status
luminet system proxy-settings apply 127.0.0.1:1080
luminet system proxy-settings clear

luminet system profiles list
luminet system startup status
```

Host-network mutations use the daemon's durable recovery/watchdog ownership. `dns clear` returns the active adapter to its platform default/DHCP configuration.

### Start the evasion tunnel

```bash
luminet system evasion-tunnel start --port 1080 --split 3 --delay 10 --auto-sni
luminet system evasion-tunnel start --dns https://cloudflare-dns.com/dns-query
```

The evasion command has many advanced flags. Do not copy flag lists into documentation; inspect the live interface instead:

```bash
luminet system evasion-tunnel start --help
```

### Readiness and TPM operations

```bash
luminet doctor --url http://127.0.0.1:8470
luminet doctor --url http://127.0.0.1:8470 --json

luminet tpm inventory
luminet tpm verify
```

Use `luminet tpm <command> --help` before migration, rollback, or cutoff operations because those commands require explicit envelope paths/policy inputs.
