# LumiNet Future Extension Specifications

> **Scope:** Advanced architectural extensions expanding LumiNet's release pipeline, P2P mesh overlay network, and UI widget ecosystem.

---

## Extension 1: GoReleaser Multi-Platform CI/CD Packaging Matrix

### 1. Build Target Matrix
- **Windows:** `windows/amd64`, `windows/arm64` (`.exe`, `.msi` via WiX Toolset).
- **Linux:** `linux/amd64`, `linux/arm64`, `linux/riscv64` (`.tar.gz`, `.deb`, `.rpm`).
- **macOS:** `darwin/amd64`, `darwin/arm64` (Universal Binary `.dmg`, notarized `.pkg`).
- **Mobile Bindings:** `android/arm64` (`.aar`), `ios/arm64` (`.xcframework`).

### 2. Zero-CGO Build Configuration (`.goreleaser.yaml`)
```yaml
builds:
  - id: luminet-server
    main: ./cmd/server
    binary: luminetd
    env:
      - CGO_ENABLED=0
    goos:
      - windows
      - linux
      - darwin
    goarch:
      - amd64
      - arm64
    flags:
      - -trimpath
    ldflags:
      - -s -w -X github.com/maybeknott/luminet/internal/platform/system.Version={{.Version}}
```

---

## Extension 2: P2P Mesh Node Discovery & Relay Routing Protocol

### 1. Architecture
- **DHT Discovery:** Kademlia-based peer discovery over UDP port hopping (`libp2p` integration).
- **NAT Hole Punching:** Dual STUN/TURN/ICE hole punching to connect peers behind symmetric NATs.
- **Multi-Hop Chaining:** Encrypted onion-style relay routing across 2 to 4 intermediate mesh nodes.

### 2. Protocol Interface (future daemon runtime module under `src/apps/daemon/internal/runtime/`)
- Peer ID generation using Ed25519 public keys.
- Passive RTT probing and link quality score calculations.

---

## Extension 3: Sovereign Glass Desktop UI Theme Customization & Widget Library

### 1. Glassmorphism Design System Tokens
- **Backdrop Blur:** `backdrop-filter: blur(20px) saturate(180%)`.
- **Surface Alpha:** `rgba(15, 23, 42, 0.75)` dark mode base.
- **Accent Glow:** HSL dynamic color shift based on active node latency (Green < 100ms, Amber 100-250ms, Red > 250ms).

### 2. UI Component Library
- **Live Latency Sparkline Widget:** Real-time canvas rendering of ping jitter.
- **Atomic Mode Switcher:** Glass toggle for Wintun TUN / System Proxy / Direct.
- **Interactive Globe / Map:** Visual node geographical distribution view.
