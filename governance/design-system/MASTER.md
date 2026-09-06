# 🌐 LumiNet Cockpit Design System — Master Specification (v1.0)

This document is the authoritative visual token and component specification for
the **LumiNet** desktop and mobile platforms. `DESIGN.md` owns product and
interaction intent; `governance/design-system/legacy.md` is retained historical
source material and must not override these tokens.

---

## 1. Visual Strategy & Creative Direction
*   **Creative Direction**: **Sovereign Glass Command Cockpit**
*   **Philosophy**: Rich information density designed for power users, censorship auditors, and security researchers. Leverages subtle depth via glassmorphic overlays and high-contrast OLED dark modes.
*   **Color Strategy**: **Restrained Neo-Neon**. Tinted near-black neutrals with high-contrast functional neon accents (blue, cyan, purple, emerald) indicating active connection states and diagnostic ratings. Emojis are strictly banned; all iconography uses vector SVGs.

---

## 2. Design Tokens

### 2.1 Color Palette (OKLCH & Hex Mappings)
We define our theme using a deep space void navy base with high-chroma indicator accents:

| Token Name | OKLCH Value | Hex Value | Purpose / Usage |
| :--- | :--- | :--- | :--- |
| `--bg-void` | `oklch(12.5% 0.015 245)` | `#020617` | OLED background canvas |
| `--bg-surface` | `oklch(18.2% 0.024 245)` | `#0f172a` | Glassmorphic card overlays |
| `--bg-element` | `oklch(24.3% 0.032 245)` | `#1e293b` | Secondary layout segments, panels |
| `--border-glow` | `rgba(255,255,255,0.06)` | `--` | Subtle container borders |
| `--neon-blue` | `oklch(62.3% 0.22 250)` | `#3b82f6` | Primary action states, evaluate proxies tab |
| `--neon-cyan` | `oklch(76.2% 0.16 200)` | `#06b6d4` | Network scan sweeps, throughput data |
| `--neon-purple` | `oklch(58.4% 0.21 290)` | `#8b5cf6` | Diagnostic runbooks, system indicators |
| `--neon-emerald` | `oklch(72.1% 0.22 150)` | `#10b981` | Positive connection, active status, success |
| `--neon-warning` | `oklch(78.5% 0.18 80)` | `#f59e0b` | Warn boundaries, degraded proxy states |
| `--neon-error` | `oklch(60.2% 0.23 25)` | `#ef4444` | Interface offline state, validation errors |

### 2.2 Typography Scale
*   **Fonts**:
    *   `font-display` & `font-sans`: **Outfit** (Sans-serif) ── for layouts, headers, and UI elements.
    *   `font-mono`: **Fira Code** or **JetBrains Mono** ── for IP tables, logs, port maps, and shell traces.
*   **Scale Limits**:
    *   `Display H1`: `2.25rem` (36px), Line Height `1.2`, Letter Spacing `-0.02em` (Never below `-0.04em`).
    *   `Header H2`: `1.5rem` (24px), Line Height `1.3`, Letter Spacing `-0.015em`.
    *   `Title H3`: `1.125rem` (18px), Line Height `1.4`, Weight `500`.
    *   `UI Labels`: `0.8125rem` (13px), Mono spacing, Weight `400`.

### 2.3 Spacing & Borders
*   **Base Spacing Unit**: `4px` (0.25rem)
    *   `xs`: `4px` | `sm`: `8px` | `md`: `16px` | `lg`: `24px` | `xl`: `32px`
*   **Rounding Ceiling**:
    *   `rounded-sm`: `6px` | `rounded-md`: `8px` | `rounded-lg`: `12px`
    *   *Constraint*: Over-rounding (24px+) is restricted to buttons and full-pill tags.

---

## 3. Structural Layout Concept

### 3.1 Desktop Layout Blueprint
*   **Navigation**: Left-hand sidebar layout with collapsible text tags.
*   **Content Surface**: Multi-column bento grids organizing diagnostics, scanning logs, and active dials.
*   **Interactions**: Floating actions and bottom console feeds. No heavy orchestrated entry page-load animations.

### 3.2 Mobile Layout Blueprint
*   **Navigation**: Bottom navigation tab bar anchored within easy thumb reach.
*   **Content Surface**: Collapsible rows and bottom-anchored modal sheets. Swipe-to-action indicators trigger sweeps and test diagnostics.

---

## 4. Design Guidelines & Anti-Patterns to Avoid
*   **Anti-Pattern Check (Slop Test)**:
    *   No emojis are used as indicators. All icons are scalable vector SVGs.
    *   No side-stripe borders are used on card elements.
    *   No gradient text decorations are used.
    *   All buttons and clickable cards feature explicit pointer feedback (`cursor-pointer`) and smooth transitions (`transition-all`, 200ms easing).
