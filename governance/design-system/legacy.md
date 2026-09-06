# Design System Master File (Historical Source Material)

> **Lifecycle:** Retained to preserve design rationale and component detail. For
> new UI work, follow `../../MASTER.md` for tokens and component rules and
> `../../DESIGN.md` for product intent. This document must not override either.

---

**Project:** LumiNet (Native Network Operations Console)
**Last Updated:** 2026-06-22
**Category:** Sovereignty-Grade Network Diagnostics & Proxy Operations Dashboard

---

## 1. Design Philosophy: "Sovereign Glass Command Cockpit"

LumiNet uses a technical, high-precision visual design that balances functional density with immersive aesthetic polish. The environment is dark-first, reflecting the typical physical context of researchers and power users auditing hostile networks in low-light environments. Information density is kept high, avoiding excessive whitespace that slows down log auditing, but remains structured using crisp glassmorphic panels and thin high-contrast borders.

Visual anchors are driven by neon-accented telemetry indicators and responsive status updates, ensuring that every design detail serves an active information-carrying purpose.

---

## 2. Global Rules

### 2.1 CSS Custom Properties (Theme Tokens)

Copy this token system directly into your global stylesheets to maintain system-wide design integrity:

```css
:root {
  /* Fonts */
  --font-display: 'Outfit', sans-serif;
  --font-body: 'Outfit', sans-serif;
  --font-mono: 'JetBrains Mono', monospace;

  /* Space Void Navy (Default Theme) Base Colors */
  --bg-primary: #0a0e1a;
  --bg-secondary: #0f1425;
  --bg-tertiary: #151b2e;
  --border-color: rgba(255, 255, 255, 0.08);
  --border-hover: rgba(255, 255, 255, 0.15);
  
  /* Text Color Tokens */
  --text-primary: #f1f5f9;
  --text-secondary: #94a3b8;
  --text-muted: #64748b;
  
  /* Neon Status Accents */
  --color-accent: #3b82f6;       /* Electric Blue */
  --color-accent-glow: rgba(59, 130, 246, 0.15);
  --color-cyan: #06b6d4;         /* Neon Cyan (CPU/Networking) */
  --color-purple: #8b5cf6;       /* Neon Purple (Memory/Diag) */
  --color-success: #10b981;      /* Terminal Green (Passed audits) */
  --color-warning: #f59e0b;      /* Warning Amber (Degraded status) */
  --color-error: #ef4444;        /* Critical Red (Failed status) */
  
  /* Border Radius */
  --rounded-sm: 0.375rem;        /* 6px */
  --rounded-md: 0.5rem;          /* 8px */
  --rounded-lg: 0.75rem;         /* 12px */
  --rounded-xl: 1rem;            /* 16px */

  /* Spacing Tokens */
  --space-xs: 0.25rem;           /* 4px */
  --space-sm: 0.5rem;            /* 8px */
  --space-md: 1rem;              /* 16px */
  --space-lg: 1.5rem;            /* 24px */
  --space-xl: 2rem;              /* 32px */
  --space-2xl: 3rem;             /* 48px */

  /* Transitions */
  --transition-fast: 100ms ease;
  --transition-base: 200ms cubic-bezier(0.4, 0, 0.2, 1);
  --transition-slow: 300ms ease;
}
```

### 2.2 Typography & Type Scale

Typography must prioritize structural scannability. Match the typography scale below:

| Token Name | Font Family | Size | Weight | Line Height | Usage |
|:---|:---|:---|:---|:---|:---|
| `h1` | Outfit | `2.25rem` (36px) | 600 | 1.2 | Page title headers |
| `h2` | Outfit | `1.5rem` (24px) | 600 | 1.3 | Card headers, main layout components |
| `h3` | Outfit | `1.125rem` (18px) | 500 | 1.4 | Group labels, diagnostic workbench titles |
| `body` | Outfit | `0.875rem` (14px) | 400 | 1.6 | Narrative explanations, help cards |
| `mono` | JetBrains Mono | `0.8125rem` (13px) | 400 | 1.4 | IP addresses, ports, telemetry values, console logs |

---

## 3. UI Component Specifications

### 3.1 Interactive Buttons
Buttons must feature hover translations and focus indicators. Emojis are forbidden in buttons; use SVG icons.

```css
/* Base Button Layout */
.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-family: var(--font-display);
  font-size: 0.875rem;
  font-weight: 600;
  padding: 0.625rem 1.25rem;
  border-radius: var(--rounded-md);
  border: 1px solid transparent;
  cursor: pointer;
  transition: all var(--transition-base);
  gap: var(--space-sm);
  outline: none;
}

/* Primary Accent Action */
.btn-primary {
  background: linear-gradient(135deg, var(--color-accent), #4f46e5);
  color: #ffffff;
  box-shadow: 0 4px 12px rgba(59, 130, 246, 0.2);
}

.btn-primary:hover {
  transform: translateY(-1px);
  box-shadow: 0 6px 16px rgba(59, 130, 246, 0.35);
  opacity: 0.95;
}

/* Secondary Ghost Action */
.btn-secondary {
  background: rgba(255, 255, 255, 0.03);
  color: var(--text-primary);
  border-color: var(--border-color);
}

.btn-secondary:hover {
  background: rgba(255, 255, 255, 0.08);
  border-color: var(--border-hover);
  transform: translateY(-1px);
}
```

### 3.2 Glassmorphic Cards & Containers
Depth is generated via white-opacity borders and backdrop filters rather than heavy static drop shadows.

```css
.card {
  background: rgba(15, 20, 37, 0.65);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  border: 1px solid var(--border-color);
  border-radius: var(--rounded-lg);
  padding: var(--space-lg);
  transition: border-color var(--transition-base), transform var(--transition-base);
}

.card:hover {
  border-color: var(--border-hover);
  transform: translateY(-2px);
}
```

### 3.3 Technical Inputs & Form Controls

```css
.input-text {
  background: rgba(10, 14, 26, 0.8);
  color: var(--text-primary);
  border: 1px solid var(--border-color);
  border-radius: var(--rounded-md);
  padding: 0.625rem 0.875rem;
  font-family: var(--font-mono);
  font-size: var(--mono);
  transition: all var(--transition-base);
  width: 100%;
}

.input-text:focus {
  border-color: var(--color-accent);
  box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2);
  outline: none;
}
```

---

## 4. Visual Themes Specification

LumiNet supports six core visual identity variations, map details below:

1. **Space Void Navy (Default)**: deep dark blue views (`#0a0e1a`), slate blue containers (`#0f1425`), electric blue actions (`#3b82f6`).
2. **Matrix Cyberpunk**: deep forest black background (`#020502`), container blocks (`#0a0f0a`), neon toxic green borders/actions (`#00ff66`), fonts forced to JetBrains Mono.
3. **Nord Frost**: arctic background (`#2e3440`), secondary slate grey (`#3b4252`), frosted blue accent (`#88c0d0`).
4. **Dracula**: deep midnight violet background (`#282a36`), secondary dark violet (`#44475a`), neon pink/cyan status accents (`#ff79c6`).
5. **Sunset Sahara**: warm dark clay background (`#1a1515`), dark copper containers (`#261d1d`), fiery warning amber actions (`#f97316`).
6. **Light Slate Override**: light slate background (`#f8fafc`), clean white panels (`#ffffff`), dark blue text (`#0f172a`), border opacity shifted to 15% dark opacity (`rgba(0,0,0,0.1)`).

---

## 5. Anti-Patterns (Forbidden Details)

*   ❌ **No Emojis as Icons:** All status nodes or button decorators must use crisp, scalable inline SVGs (e.g. Lucide / Heroicons).
*   ❌ **No Warm Marketing Palettes:** Avoid beige or warm-cream background gradients that conflict with network-diagnostic tool contexts.
*   ❌ **No Layout Shifting:** Animations and hovers must not modify physical grid positions or dimensions. Use absolute/transform coordinates for hover micro-motions.
*   ❌ **No Unstyled Scrollbars:** Default browser scrollbars are forbidden. Override scrollbar colors to blend seamlessly with the active theme background.
*   ❌ **No Blind Contrast:** Text colors against backgrounds must maintain at least a **4.5:1** contrast ratio (verified under AAA/AA accessibility audits).

---

## 6. Pre-Delivery Checklist

Before merging or rendering any frontend user interface change, verify the following checklist:

- [x] Custom variables are used instead of ad-hoc HEX values.
- [x] Typography fits the Outfit / JetBrains Mono hierarchy correctly.
- [x] Accessibility: Focus rings are visible on keyboard Tab traversal.
- [x] Responsiveness verified at standard widths: `375px`, `768px`, `1024px`, and `1440px`.
- [x] Clickable components have `cursor: pointer` styles attached.

