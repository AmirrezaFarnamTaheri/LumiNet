# 🛡️ LumiCircumvent: Active Evasion and Transport Circumvention Specification

This document details the active evasion protocols, packet-level manipulation, and obfuscated transport mechanisms built into LumiNet. These circumvention techniques run in user-space without administrative driver requirements (unless running in raw packet injection mode).

On Windows, raw packet injection is conditional on an **operator-supplied WinDivert 2.2.2+ runtime**. WinDivert is not bundled in the source tree or current LumiNet Windows release artifact; the requested packet-injection mode fails closed when the DLL/driver cannot be loaded.

---

## 1. SOCKS5 Smart Evasion Tunnel

The smart evasion tunnel intercepts SOCKS5 connections locally and applies packet-level mutation to bypass deep packet inspection (DPI) censorship engines.

### 1.1 TCP Segment Splitting
Rather than sending TCP streams as unified buffers, the evasion tunnel slices the payload into segment fragments at a configured byte offset:
* **Byte Offset (n)**: The exact position in the outbound TCP stream where the slice occurs. Typically set to a small value (e.g. `2` or `3` bytes).
* **Inter-Packet Delay (ms)**: A timing pause (e.g., `10ms` to `50ms`) introduced before writing the second TCP segment. This timing gap forces DPI middleboxes to process the packet out-of-order or buffers them, disrupting signature extraction algorithms.

### 1.2 Auto-Split TLS SNI (Server Name Indication)
For TLS traffic (port 443), firewalls scan the Server Name Indication (SNI) extension in the plaintext TLS `ClientHello` handshake:
* **DPI SNI Extraction**: The firewall reconstructs the first TCP packet to match hostname blocklists.
* **Auto-Split Mechanism**: 
  1. The evasion tunnel locates the SNI extension inside the ClientHello payload.
  2. It automatically calculates the offset of the SNI hostname string.
  3. It splits the TCP packet exactly in the middle of the SNI hostname (e.g., if the host is `google.com`, it sends `goog` in the first packet, pauses, and sends `le.com` in the second packet).
  4. The remote server reassembles the segments correctly, but signature-based DPI firewalls fail to reconstruct the blocked hostname.

```
       [ Client App ]
             │ (Dial target.com)
             ▼
   [ SOCKS5 Evasion Tunnel ]
             │
             ├─► Segment 1: [ TLS ClientHello Header + "targ" ]
             ├─► [ 15ms Sleep Delay ]
             └─► Segment 2: [ "et.com" + Rest of Payload ]
```

### 1.3 Userspace Raw Handshake Injection (`paqet` mode)
For environments with active DPI trackers that track TCP 3-way handshakes, the raw mode bypasses the standard OS TCP stack:
* **Raw Injections**: Injects fake SYN packets and payload buffers with altered TTL parameters (`FakePacketTtl`) to confuse intermediate firewall routers while keeping the destination socket connection active.
* **Kernel RST Protection**: Dropping local kernel-level `RST` frames utilizing `WinDivert` filters (on Windows) or `AF_PACKET` raw socket filters (on Linux) to prevent the OS from closing connections initialized outside standard Winsock wrappers.

---

## 2. Netrix KCP/UDP Transport Obfuscation

The Netrix transport protocol layer scrambles traffic fingerprints by running KCP multiplexing over UDP sockets, avoiding plain TCP handshake signatures.

### 2.1 Performance Configuration Profiles
Netrix supports multiple latency and throughput profiles matching network conditions:
* **`balanced`**: `nodelay=0, interval=20ms, resend=2, nc=0, sndwnd=512, rcvwnd=512, mtu=1350`
* **`aggressive`**: `nodelay=0, interval=10ms, resend=2, nc=1, sndwnd=2048, rcvwnd=2048, mtu=1400`
* **`latency`**: `nodelay=1, interval=5ms, resend=1, nc=1, sndwnd=256, rcvwnd=256, mtu=1200`
* **`cpu-efficient`**: `nodelay=0, interval=50ms, resend=3, nc=0, sndwnd=128, rcvwnd=128, mtu=1400`

### 2.2 Fingerprint Scrambling & Compression
* **Entropy Optimization**: Compression using Zstandard (`zstd`) or LZ4 framing is applied to payloads larger than 1024 bytes to maximize Shannon entropy, preventing statistical payload analysis.
* **Jitter Addition**: Adds random timing delays (jitter between 5ms and 20ms) to packet transmissions to mask packet interval timings.

---

## 3. Zephyr Google Drive Mailbox Transport

The Zephyr transport bridges SOCKS5 stream frames over third-party APIs (such as Google Drive) to completely bypass standard network egress controls.

### 3.1 Mailbox File Ingestion
* **Client Uploads**: The local client encapsulates connection packets inside a custom envelope and uploads them as temporary files (e.g. `client_<session_id>_<sequence>.bin`) to a shared Google Drive directory.
* **Relay Downloads**: The remote upstream relay host polls the GDrive folder, downloads the client files, unwraps the payload, dials the target server, collects responses, and uploads them back as `relay_<session_id>_<sequence>.bin`.
* **Framing Envelopes**: Prepend MagicBytes (`0x1F`), SessionID, and payload length descriptors to ensure reliable reassembly of multiplexed streams.
