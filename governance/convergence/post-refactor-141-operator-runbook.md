# LumiNet post-refactor 141 operator runbook

## API proxy trust

The API now treats the direct TCP peer as the default client identity. Forwarded client-IP headers are not trusted by default. Deployments that genuinely terminate behind a reverse proxy must introduce an explicit reviewed trusted-proxy policy rather than relying on Gin defaults.

## Android / browser identity

Android per-app routing remains reported unavailable because the current runtime does not enforce package policy. Network/VPN egress state must not be presented as browser geolocation/timezone/WebRTC authority.

## Donor binaries and nested archives

Bundled donor AAR/JAR/native binaries are evidence only. Do not copy them into release inputs.
