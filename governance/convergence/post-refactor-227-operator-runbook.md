# Post-refactor-227 operator runbook

## Operations: SNI decoy handshake evidence

Use the SNI decoy handshake planner to inspect supplied observations. Provide coherent SYN/SYN-ACK/third-ACK/fake/server-ACK/RST evidence. The result explains expected sequence values, whether fake injection evidence is coherent, and whether the supplied server ACK would support relay readiness.

The planner **captures no packets, injects no traffic, opens no socket, changes no route, and grants no raw-packet privilege**. It is evidence interpretation only.

## Live runtime

Out-of-window injection requires a fresh captured SYN sequence for the exact TCP four-tuple. Missing evidence is an error. Evidence expires and is consumed once. Operators should not interpret a successful diagnostic plan as proof that the live path observes the donor’s complete server-confirmation lifecycle.

## TLS decoy

Go diagnostics and live runtime share the same bounded 517-byte TLS decoy builder. SNI must be a valid bounded ASCII DNS hostname up to 219 bytes.

## Platform boundary

Linux and Windows retain target-native raw-packet owners. The donor macOS BPF implementation is not a supported LumiNet raw SNI-injection path in this release.

## Update/runtime boundary

Do not install donor bundled binaries or mutable “latest” Xray/WinTun downloads through this convergence surface. Canonical update admission, profile, and core-manager paths remain authoritative.
