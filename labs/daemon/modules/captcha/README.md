# CAPTCHA Bypass Blueprints

This document outlines the architecture, design, and integration blueprints for automated CAPTCHA solving services within LumiNet.

## Overview

The LumiNet client may encounter target sites (e.g., subscription portals, proxy providers, and telemetry endpoints) protected by CAPTCHAs (like hCaptcha and reCAPTCHA v2). To maintain a fully autonomous operation, LumiNet integrates with third-party automated solving services (e.g., 2Captcha) securely.

## 1. Architectural Isolation (Feature Gating)

To ensure zero bloat and absolute security in standard builds, the CAPTCHA module (`server/internal/captcha`) utilizes Go build tags:

- **Standard Build (`!captcha`)**: Uses `stub.go`. All CAPTCHA solving methods return `ErrPluginDisabled`.
- **Enabled Build (`captcha`)**: Uses `plugin.go`. This compiles the real `http.Client` implementation.

**Command to build with CAPTCHA support:**
```bash
go build -tags captcha -o luminet.exe ./cmd/luminet
```

## 2. Secrets Management

- **No Hardcoded Keys**: API keys for 2Captcha MUST NEVER be hardcoded or stored in standard configuration files (e.g., `config.json`).
- **Secure Injection**: Keys should be injected securely via environment variables (`LUMINET_2CAPTCHA_KEY`) or fetched securely from an encrypted vault during runtime.
- **Redaction**: The API key is strictly redacted at the logger level to prevent accidental leakage in debug outputs.

## 3. Integration Blueprint

### Interface Design

The CAPTCHA module exposes a minimal and clean interface:

```go
type Solver interface {
	SolveHCaptcha(ctx context.Context, siteKey, pageURL string) (string, error)
	SolveRecaptchaV2(ctx context.Context, siteKey, pageURL string) (string, error)
}
```

### Usage Pattern

When integrating the solver into autonomous tasks (e.g., background subscription scrapers):

1. **Initialization**: Initialize the solver during application startup if the API key is present.
2. **Context Deadlines**: Always wrap `Solve*` calls with strict `context.WithTimeout` to prevent indefinite stalling (e.g., 3-5 minutes maximum).
3. **Graceful Degradation**: If the solver returns an error (or if the plugin is disabled), the system MUST gracefully fall back to alternative data sources or notify the user rather than crashing.

### Example Integration

```go
import "github.com/maybeknott/luminet/internal/captcha"

// ...

solver := captcha.NewPlugin(os.Getenv("LUMINET_2CAPTCHA_KEY"))

// ... during a scraping task ...
ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
defer cancel()

token, err := solver.SolveHCaptcha(ctx, "site-key-here", "https://example.com/login")
if err != nil {
	if errors.Is(err, captcha.ErrPluginDisabled) {
		log.Println("CAPTCHA encountered, but auto-solver is disabled. Skipping target.")
	} else {
		log.Printf("Failed to solve CAPTCHA: %v", err)
	}
	return
}

// Proceed with token ...
```

## 4. Threat Model & Security Considerations

- **Outbound Network Calls**: The plugin uses its own isolated `http.Client`. It does not proxy its own requests to avoid recursive proxy loops.
- **Data Minimization**: The solver only transmits the `siteKey` and `pageURL` to the 2Captcha API. No user data, cookies, or headers are ever sent.
- **Timeouts & Polling**: The plugin utilizes a smart polling mechanism with a 5-second interval and a strict hard deadline (3 minutes). This prevents goroutine leaks in the event of an unresponsive API endpoint.
