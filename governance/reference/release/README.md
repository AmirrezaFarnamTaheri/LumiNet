# Retired release configuration evidence

`.goreleaser.yaml` is preserved byte-for-byte as historical packaging evidence.
It is intentionally not an active repository-root release configuration.

GitHub Actions (`.github/workflows/release.yml`) is the release authority for the
supported product matrix, including host daemon/watchdog/desktop artifacts and
the Android AAR + linked APK.
