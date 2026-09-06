# Product Definition: LumiNet

## Vision & Overview
LumiNet is a local, sovereignty-grade network diagnostics console, active circumvention engine, and system management workstation. The platform provides transparent, raw network instrumentation for power users, developers, and censorship researchers working in hostile, restricted, or actively monitored network spaces.

Unlike typical diagnostic suites that rely on cloud-dependent servers or commercial SaaS, LumiNet is built on zero-budget local execution, honest diagnostic feedback, and user-space network manipulation. It bridges a high-performance Rust core (`lumicore`) with an orchestration server (`go-server`) and a native desktop UI to enable comprehensive system control and secure routing.

## Target User Personas
- **The Censorship Researcher:** Auditing network pathways under state-level DPI firewalls, probing SNI blocks, identifying cert hijacking, and analyzing raw TCP segment splitting.
- **The Remote Developer & Admin:** Managing DNS/DDNS, egress tunnels, concurrent port scanning, and automated proxy routing rulesets across restricted infrastructure.
- **The Privacy-Conscious Power User:** Securing personal telemetry, bypassing local captive portals, and routing system traffic over multi-hop chains.

## Core Pillars & Architectural Modules
- **LumiScan:** Parallel stateful/stateless sweeps (ICMP, TCP connect/banner grabbing, TLS certificate parsing, SNI reachability probing).
- **LumiGuard:** DNS poisoning detection (UDP vs DoH cross-check), MITM SSL decryption warnings, NCSI registry overrides, CAPTCHA solver integration, SOCKS5 UDP NAT mapper.
- **Active Evasion:** TCP segment splitting & delay, TLS SNI auto-split, raw socket handshake injection (paqet mode), HTTP header mutation, range-based fragmentation.
- **LumiDiag:** Automated eight-phase diagnostic runbook with evidence and report generation.
- **LumiSystem:** System DNS switcher with crash rollback protection, global proxy registry adaptor, DDNS updater.
