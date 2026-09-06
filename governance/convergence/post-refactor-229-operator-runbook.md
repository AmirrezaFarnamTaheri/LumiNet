# Post-refactor-229 operator runbook

- **Health / Tunnel safety:** require only guards relevant to the intended posture; a missing required DNS/QUIC/STUN/DoH/IPv6 guard degrades safety. Planner is read-only.
- **Health / TLS interception evidence:** enter caller-observed component compatibility, grade/PFS and weak-cipher evidence. Treat `suspicious` as an anomaly signal, never product attribution.
- **Operations / Artifact admission:** provide claimed filename/format plus bytes when available. A format mismatch is quarantine, even when the extension looks valid.
- **Operations / Endpoint pool:** quota safety buffer is reserved; only usable headroom participates in dispatch eligibility. Reset timestamps are evidence, not mutation authority.
- **Rules / Split tunnel:** validate include/exclude intent and manifest identity; `runtime_enforced=false` means no OS mechanism is installed.
- **Profiles / Relay constraints:** filter caller metadata, then hand eligible candidates to the existing endpoint scorer.
- **Settings / Updates:** schema-v2 monotonic replay protection is only true after daemon-owned persistent high-water acceptance.
- **Relay runtime:** legacy responses may omit sequence; supplied sequence must correlate. Non-JSON/HTML control errors intentionally preserve multiple plausible causes.
