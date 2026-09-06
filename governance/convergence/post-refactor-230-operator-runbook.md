# Post-refactor-230 operator runbook

Use Operations → Convergence policy lab for Tor bridge selection, Tor bootstrap evidence, censorship measurement evidence, DTLS session policy, phantom pool selection, and flow filtering. These endpoints are planning/evidence only and do not fetch bridges, control Tor, run probes, perform DTLS handshakes, register phantoms, or intercept/replay flows. CDN scan jobs reject private/non-routable candidates before probes. Multiplex settings are validated against explicit bounds and KCP uses target-pinned smux v1 behavior.
