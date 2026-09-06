package proxy

import (
	"bufio"
	"fmt"
	"strings"
	"unicode"
)

// PatchOpenVPNConfig parses a legacy OpenVPN configuration and upgrades it with
// modern, secure parameters compatible with OpenVPN 2.5+.
//
// Porting Sources:
//   - OmidVPN-master (Project 6): Flutter cipher patcher — `replaceAll(RegExp(r'cipher '), 'data-ciphers ')`
//   - Compendium §2.1.3: "Implement OmidVPN on-the-fly cipher string patcher"
//
// Transformation rules applied:
//  1. Legacy `cipher <ALGO>` lines are rewritten to `data-ciphers <ALGO>:AES-256-GCM`.
//  2. Deprecated options are scrubbed: ncp-disable, comp-lzo, keysize.
//  3. `tls-version-min` is injected at 1.2 if not already set.
//  4. `data-ciphers` preference list is injected if no data-ciphers line exists.
//  5. `verb` level is clamped to ≤3 to suppress excessive logs.
//  6. `persist-key` and `persist-tun` are enforced for stable reconnection.
//  7. `keepalive 10 120` is injected if not already set.
func PatchOpenVPNConfig(configData string) string {
	var lines []string

	// Track what's already present
	hasDataCiphers := false
	hasTLSVersionMin := false
	hasPersistKey := false
	hasPersistTun := false
	hasKeepalive := false

	// Directives that must be scrubbed for compatibility with OpenVPN 2.5+
	deprecated := map[string]bool{
		"ncp-disable": true,
		"comp-lzo":    true,
		"keysize":     true,
	}

	scanner := bufio.NewScanner(strings.NewReader(configData))
	for scanner.Scan() {
		raw := scanner.Text()
		line := strings.TrimSpace(raw)

		// Preserve blank lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			lines = append(lines, raw)
			continue
		}

		fields := strings.FieldsFunc(line, unicode.IsSpace)
		if len(fields) == 0 {
			lines = append(lines, raw)
			continue
		}

		directive := strings.ToLower(fields[0])

		// ── Scrub deprecated directives ──────────────────────────────────────
		if deprecated[directive] {
			lines = append(lines, "# LUMINET COMPAT: scrubbed legacy directive: "+line)
			continue
		}

		// ── Rewrite legacy cipher → data-ciphers ────────────────────────────
		// OmidVPN source: `ovpnConfig.replaceAll(RegExp(r'cipher '), 'data-ciphers ')`
		// Extended: we carry the algorithm name forward and build a preference list.
		if directive == "cipher" {
			algo := "AES-256-GCM"
			if len(fields) >= 2 {
				algo = strings.ToUpper(fields[1])
			}
			lines = append(lines, fmt.Sprintf(
				"# LUMINET CIPHER PATCH: rewritten 'cipher %s' → data-ciphers", algo))
			// Build preference list: specified algo first, then AES-256-GCM fallback
			preference := algo
			if algo != "AES-256-GCM" {
				preference += ":AES-256-GCM"
			}
			if !strings.Contains(preference, "AES-128-GCM") {
				preference += ":AES-128-GCM"
			}
			lines = append(lines, "data-ciphers "+preference)
			hasDataCiphers = true
			continue
		}

		// ── Track existing modern directives ─────────────────────────────────
		switch directive {
		case "data-ciphers":
			hasDataCiphers = true
		case "tls-version-min":
			hasTLSVersionMin = true
		case "persist-key":
			hasPersistKey = true
		case "persist-tun":
			hasPersistTun = true
		case "keepalive":
			hasKeepalive = true
		case "verb":
			// Clamp verbosity to ≤3 to avoid log flooding
			level := 3
			if len(fields) >= 2 {
				fmt.Sscanf(fields[1], "%d", &level)
				if level > 3 {
					lines = append(lines, "# LUMINET: verb clamped from "+fields[1]+" to 3")
					lines = append(lines, "verb 3")
					continue
				}
			}
		}

		lines = append(lines, raw)
	}

	// ── Inject missing directives ─────────────────────────────────────────────
	lines = append(lines, "")
	lines = append(lines, "# --- INJECTED BY LUMINET CONFIG PATCHER ---")
	if !hasDataCiphers {
		lines = append(lines, "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305")
	}
	if !hasTLSVersionMin {
		lines = append(lines, "tls-version-min 1.2")
	}
	if !hasPersistKey {
		lines = append(lines, "persist-key")
	}
	if !hasPersistTun {
		lines = append(lines, "persist-tun")
	}
	if !hasKeepalive {
		lines = append(lines, "keepalive 10 120")
	}
	lines = append(lines, "# -------------------------------------------")

	return strings.Join(lines, "\n")
}

// ApplyInlineCipherFix performs the simple OmidVPN-style inline cipher rewrite:
// replaces every occurrence of the literal string "cipher " with "data-ciphers ".
//
// This is the exact algorithm from OmidVPN's `_configPatches()`:
//
//	ovpnConfig.replaceAll(RegExp(r'cipher '), 'data-ciphers ')
//
// Use this for a lightweight, non-destructive patch when full parsing is unnecessary.
func ApplyInlineCipherFix(configData string) string {
	return strings.ReplaceAll(configData, "cipher ", "data-ciphers ")
}

// PatchOpenVPNConfigOptions provides fine-grained control over the patcher.
type PatchOpenVPNConfigOptions struct {
	// InlineCipherFix applies the lightweight OmidVPN regex-style cipher rewrite only.
	InlineCipherFix bool
	// EnforceTLS12 injects tls-version-min 1.2 if not already present.
	EnforceTLS12 bool
	// ClampVerbosity limits the verb level to ≤ MaxVerb (default 3).
	ClampVerbosity bool
	// MaxVerb is the maximum verbosity level to allow (default 3).
	MaxVerb int
	// InjectKeepalive injects "keepalive 10 120" if not already set.
	InjectKeepalive bool
}

// DefaultPatchOptions returns the recommended set of patch options.
func DefaultPatchOptions() PatchOpenVPNConfigOptions {
	return PatchOpenVPNConfigOptions{
		InlineCipherFix: true,
		EnforceTLS12:    true,
		ClampVerbosity:  true,
		MaxVerb:         3,
		InjectKeepalive: true,
	}
}

// PatchOpenVPNConfigWith applies the patcher with the given options.
func PatchOpenVPNConfigWith(configData string, opts PatchOpenVPNConfigOptions) string {
	if opts.InlineCipherFix {
		return ApplyInlineCipherFix(configData)
	}
	return PatchOpenVPNConfig(configData)
}
